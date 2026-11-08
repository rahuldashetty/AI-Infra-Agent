#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "mcp[cli]>=1.25,<2",
#     "asyncssh>=2.14.0",
#     "python-dotenv>=1.0.0",
# ]
# ///
"""
InfraAgent — AI-powered server troubleshooting MCP server.
Auto-detects runtime platforms (Docker, Kubernetes, systemd, PM2, Supervisor)
and performs read-only diagnostics over SSH. Includes database query tools and service management capabilities.
"""

import asyncio
import os
import re
import shlex
import asyncssh
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize MCP server
mcp = FastMCP("infra-agent")

# SSH connection timeout (seconds)
SSH_TIMEOUT = 30

# Read-only SQL commands that are allowed (first keyword)
ALLOWED_SQL_COMMANDS = {"SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN"}

# Destructive SQL keywords that must NEVER appear anywhere in a query
BLOCKED_SQL_KEYWORDS = {
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE",
    "CREATE", "REPLACE", "RENAME", "GRANT", "REVOKE",
    "LOAD", "CALL", "SET", "LOCK", "UNLOCK", "FLUSH",
}

# Regex for validating user-provided identifiers (organization names, server names, domain names)
SAFE_IDENTIFIER_RE = re.compile(r'^[a-zA-Z0-9._ -]+$')

# Allowed platforms for application diagnostic tools
ALLOWED_PLATFORMS = {"auto", "docker", "systemd", "kubernetes", "pm2"}

# Allowed service state filters for systemd detection
ALLOWED_SERVICE_STATES = {"active", "failed", "inactive", "all"}

# Safe error patterns for log searching (prevents shell injection)
ALLOWED_ERROR_PATTERNS = {
    "error", "exception", "fatal", "panic", "critical",
    "warning", "oom", "timeout", "refused", "denied",
    "traceback", "segfault", "killed", "fail"
}

# URL validation regexes for connectivity checks
SAFE_URL_RE = re.compile(r'^https?://[a-zA-Z0-9._:-]+(:[0-9]{1,5})?(/[a-zA-Z0-9._/~%-]*)?$')
SAFE_HOSTPORT_RE = re.compile(r'^[a-zA-Z0-9._-]+:[0-9]{1,5}$')

# Allowed resource types for diagnostic workflows
ALLOWED_RESOURCES = {"auto", "cpu", "memory", "disk", "all"}

# Allowed protocols for connectivity diagnostics
ALLOWED_PROTOCOLS = {"tcp", "http", "https"}

# Service name validation
ALLOWED_SERVICE_NAME_RE = re.compile(r'^[a-zA-Z0-9._@:-]+$')


def _validate_sql_readonly(query: str) -> None:
    """
    Validate that a SQL query is strictly read-only.

    Checks:
    1. First keyword must be in ALLOWED_SQL_COMMANDS
    2. No semicolons (prevents multi-statement attacks like SELECT 1; DROP TABLE x)
    3. No destructive keywords anywhere in the query body

    Raises:
        ValueError: If the query fails any safety check
    """
    stripped = query.strip()
    if not stripped:
        raise ValueError("Query cannot be empty")

    # Block semicolons — prevents multi-statement injection
    if ";" in stripped:
        raise ValueError(
            "Semicolons are not allowed in queries. "
            "Submit one statement at a time."
        )

    # Check first keyword is allowed
    query_upper = stripped.upper()
    first_word = query_upper.split()[0]
    if first_word not in ALLOWED_SQL_COMMANDS:
        raise ValueError(
            f"Only read-only queries are allowed. "
            f"Permitted commands: {', '.join(sorted(ALLOWED_SQL_COMMANDS))}. "
            f"Your query starts with: {first_word}"
        )

    # Tokenize and check for destructive keywords anywhere in the query
    # Split on non-alphanumeric to isolate SQL keywords (avoids false positives
    # on column names like "updated_at" matching "UPDATE")
    tokens = set(re.split(r'[^A-Za-z]+', query_upper))
    found_blocked = tokens & BLOCKED_SQL_KEYWORDS
    if found_blocked:
        raise ValueError(
            f"Query contains blocked keyword(s): {', '.join(sorted(found_blocked))}. "
            f"Only read-only queries are allowed."
        )


def _sanitize_identifier(value: str, param_name: str) -> str:
    """
    Validate and sanitize user-provided identifiers (org names, server names, domain names).

    Args:
        value: The identifier string to validate
        param_name: Name of the parameter (for error messages)

    Returns:
        str: The validated identifier

    Raises:
        ValueError: If the identifier contains invalid characters or is too long
    """
    if not value:
        raise ValueError(f"{param_name} cannot be empty")

    if len(value) > 255:
        raise ValueError(f"{param_name} exceeds maximum length of 255 characters")

    if not SAFE_IDENTIFIER_RE.match(value):
        raise ValueError(
            f"{param_name} contains invalid characters. "
            f"Only alphanumeric characters, dots, underscores, hyphens, and spaces are allowed."
        )

    return value


async def _check_command_exists(command_name: str) -> bool:
    _sanitize_identifier(command_name, "command_name")
    try:
        output = await run_ssh_command(f"command -v {shlex.quote(command_name)} 2>/dev/null && echo EXISTS || echo MISSING")
        return "EXISTS" in output
    except Exception:
        return False


async def run_database_query(query: str, db_name: str = None) -> str:
    """
    Execute a read-only SQL query against the remote MariaDB database.

    Args:
        query: SQL query to execute (must be a read-only query)
        db_name: Optional database name (defaults to env DB_NAME)

    Returns:
        str: Query results as tab-delimited rows (no column headers)

    Raises:
        ValueError: If query is not read-only
        Exception: If SSH connection or query execution fails
    """
    _validate_sql_readonly(query)

    db_host = os.environ.get("DB_HOST")
    db_port = os.environ.get("DB_PORT", "3306")
    db_user = os.environ.get("DB_USER", "app")
    db_pass = os.environ.get("DB_PASS")
    target_db = db_name or os.environ.get("DB_NAME", "app")

    if not db_host:
        raise ValueError("DB_HOST environment variable is required")
    if not db_pass:
        raise ValueError("DB_PASS environment variable is required")
    quoted_query = shlex.quote(query)

    command = (
        f"mysql "
        f"-h {shlex.quote(db_host)} "
        f"-P {shlex.quote(db_port)} "
        f"-u {shlex.quote(db_user)} "
        f"-p{shlex.quote(db_pass)} "
        f"--safe-updates "
        f"-N "
        f"{shlex.quote(target_db)} "
        f"-e {quoted_query}"
    )

    return await run_ssh_command(command)


async def ssh_connect():
    """
    Create an SSH connection to the remote server using SSH keys.

    Uses SSH_KEY_PATH from environment if set, otherwise defaults to ~/.ssh/id_ed25519.

    Returns:
        asyncssh.SSHClientConnection: Active SSH connection

    Raises:
        KeyError: If required environment variables are not set
        asyncssh.Error: If SSH connection fails
    """
    ssh_host = os.environ.get("SSH_HOST")
    if not ssh_host:
        raise KeyError("SSH_HOST environment variable is required")

    ssh_user = os.environ.get("SSH_USER", "root")
    ssh_key = os.path.expanduser(os.environ.get("SSH_KEY_PATH", "~/.ssh/id_ed25519"))

    return await asyncssh.connect(
        ssh_host,
        username=ssh_user,
        client_keys=[ssh_key],
        known_hosts=None  # Accept any host key (use with caution in production)
    )


async def run_ssh_command(command: str) -> str:
    """
    Execute a command on the remote server via SSH.

    Args:
        command: Shell command to execute

    Returns:
        str: Command output (stdout + stderr)

    Raises:
        Exception: If SSH connection or command execution fails
    """
    async with await ssh_connect() as conn:
        result = await asyncio.wait_for(
            conn.run(command),
            timeout=SSH_TIMEOUT
        )

        # Combine stdout and stderr
        output = result.stdout
        if result.stderr:
            output += f"\n[stderr]\n{result.stderr}"

        return output.strip()


