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


@mcp.tool()
async def check_disk_usage() -> str:
    """
    Check disk usage on the remote server.

    Returns filesystem usage information including size, used space,
    available space, and mount points for all mounted filesystems.
    """
    try:
        output = await run_ssh_command("df -h")
        return f"Disk usage on remote server:\n\n{output}"
    except Exception as e:
        return f"Error checking disk usage: {str(e)}"


@mcp.tool()
async def check_docker_containers() -> str:
    """
    List all Docker containers on the remote server.

    Shows container ID, name, status, and port mappings for both
    running and stopped containers.
    """
    try:
        command = 'docker ps -a --format "table {{.ID}}\\t{{.Names}}\\t{{.Status}}\\t{{.Ports}}"'
        output = await run_ssh_command(command)
        return f"Docker containers on remote server:\n\n{output}"
    except Exception as e:
        return f"Error listing Docker containers: {str(e)}"


@mcp.tool()
async def run_sql_query(query: str) -> str:
    """
    Run a read-only SQL query against the remote database.

    SECURITY: Only SELECT, SHOW, DESCRIBE, DESC, and EXPLAIN queries are allowed.
    Queries that modify data (INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE) are rejected.

    Args:
        query: SQL query to execute (must be a read-only query)

    Returns:
        Query results as a formatted string
    """
    try:
        _validate_sql_readonly(query)

        db_host = os.environ.get("DB_HOST")
        db_port = os.environ.get("DB_PORT", "3306")
        db_user = os.environ.get("DB_USER", "app")
        db_pass = os.environ.get("DB_PASS")
        db_name = os.environ.get("DB_NAME", "app")

        if not db_host:
            return "Error: DB_HOST environment variable is required"
        if not db_pass:
            return "Error: DB_PASS environment variable is required"

        quoted_query = shlex.quote(query)

        command = (
            f"mysql "
            f"-h {shlex.quote(db_host)} "
            f"-P {shlex.quote(db_port)} "
            f"-u {shlex.quote(db_user)} "
            f"-p{shlex.quote(db_pass)} "
            f"--safe-updates "
            f"{shlex.quote(db_name)} "
            f"-e {quoted_query}"
        )

        output = await run_ssh_command(command)
        return f"Query results:\n\n{output}"

    except ValueError as e:
        return f"Query blocked: {str(e)}"
    except Exception as e:
        return f"Error executing query: {str(e)}"


@mcp.tool()
async def check_service_status(service_name: str) -> str:
    """
    Check the status of a systemd service.

    Returns the current service status from systemctl and the last 50 log lines
    from journalctl. This is a read-only operation that doesn't modify the service.

    Args:
        service_name: Name of the systemd service (e.g., "nginx", "my-app")
    """
    try:
        if not re.match(r'^[a-zA-Z0-9._@:-]+$', service_name):
            return "Error: Invalid service name. Only alphanumeric, dots, underscores, @, colons, and hyphens allowed."

        safe_name = shlex.quote(service_name)
        status_output = await run_ssh_command(f"systemctl status {safe_name}")
        logs_output = await run_ssh_command(f"journalctl -u {safe_name} --no-pager -n 50")

        return f"Service Status ({service_name}):\n\n{status_output}\n\n--- Recent Logs (last 50 lines) ---\n\n{logs_output}"
    except Exception as e:
        return f"Error checking service status: {str(e)}"


@mcp.tool()
async def restart_service(service_name: str) -> str:
    """
    Restart a systemd service and verify it's running. MUTATING TOOL.

    Executes the following steps:
    1. Runs 'sudo systemctl restart <service>' (requires passwordless sudo)
    2. Waits 2 seconds for service to stabilize
    3. Checks if service is active with 'systemctl is-active'
    4. Retrieves recent logs from the last 2 minutes

    Args:
        service_name: Name of the systemd service to restart (e.g., "nginx", "my-app")
    """
    try:
        if not re.match(r'^[a-zA-Z0-9._@:-]+$', service_name):
            return "Error: Invalid service name. Only alphanumeric, dots, underscores, @, colons, and hyphens allowed."

        safe_name = shlex.quote(service_name)
        restart_output = await run_ssh_command(f"sudo systemctl restart {safe_name}")

        await asyncio.sleep(2)

        is_active_output = await run_ssh_command(f"systemctl is-active {safe_name}")
        logs_output = await run_ssh_command(f'journalctl -u {safe_name} --no-pager -n 50 --since "2 minutes ago"')

        service_status = "✓ ACTIVE" if is_active_output.strip() == "active" else f"✗ NOT ACTIVE (status: {is_active_output.strip()})"

        return (
            f"Service Restart Results ({service_name}):\n\n"
            f"Restart Command: Executed\n"
            f"Service Status: {service_status}\n\n"
            f"--- Recent Logs (last 2 minutes) ---\n\n{logs_output}"
        )
    except Exception as e:
        return f"Error restarting service: {str(e)}"

# ===========================
# System Health Monitoring Tools
# ===========================

@mcp.tool()
async def check_memory_usage() -> str:
    """
    Check RAM and swap memory usage on the remote server.

    Returns formatted memory statistics including total, used, free, shared,
    buff/cache, and available memory for both RAM and swap.
    """
    try:
        output = await run_ssh_command("free -h")
        return f"Memory usage on remote server:\n\n{output}"
    except Exception as e:
        return f"Error checking memory usage: {str(e)}"


@mcp.tool()
async def check_system_load() -> str:
    """
    Check system uptime and load averages.

    Returns uptime and 1/5/15 minute load averages. Load averages indicate
    system activity — values below CPU count are normal, above indicates saturation.
    """
    try:
        output = await run_ssh_command("uptime")
        return f"System load on remote server:\n\n{output}"
    except Exception as e:
        return f"Error checking system load: {str(e)}"


@mcp.tool()
async def check_top_processes(sort_by: str = "memory", limit: int = 10) -> str:
    """
    Show top processes sorted by memory or CPU usage.

    Args:
        sort_by: Sort criterion - "memory" (default) or "cpu"
        limit: Number of processes to show (1-50, default 10)

    Returns:
        Top N processes with USER, PID, CPU%, MEM%, VSZ, RSS, TTY, STAT, START, TIME, and COMMAND
    """
    try:
        # Validate limit
        if not isinstance(limit, int) or limit < 1 or limit > 50:
            return "Error: limit must be between 1 and 50"

        # Map sort_by to ps sort parameter
        sort_map = {
            "memory": "-%mem",
            "cpu": "-%cpu"
        }

        if sort_by not in sort_map:
            return f"Error: sort_by must be 'memory' or 'cpu', got '{sort_by}'"

        sort_param = sort_map[sort_by]

        # Use ps aux with sort and head to get top N processes
        command = f"ps aux --sort={sort_param} | head -n {limit + 1}"
        output = await run_ssh_command(command)

        return f"Top {limit} processes by {sort_by}:\n\n{output}"

    except Exception as e:
        return f"Error checking top processes: {str(e)}"


# ===========================
# Docker Monitoring Tools
# ===========================

@mcp.tool()
async def docker_container_logs(container_name: str, lines: int = 100) -> str:
    """
    Tail logs from a specific Docker container.

    Args:
        container_name: Name of the container (alphanumeric, dots, underscores, hyphens only)
        lines: Number of log lines to retrieve (1-1000, default 100)

    Returns:
        Recent log output from the specified container
    """
    try:
        # Validate container name
        _sanitize_identifier(container_name, "container_name")

        # Validate lines parameter
        if not isinstance(lines, int) or lines < 1 or lines > 1000:
            return "Error: lines must be between 1 and 1000"

        command = f"docker logs --tail {lines} {shlex.quote(container_name)}"
        output = await run_ssh_command(command)

        return f"Logs from container '{container_name}' (last {lines} lines):\n\n{output}"

    except ValueError as e:
        return f"Validation error: {str(e)}"
    except Exception as e:
        return f"Error fetching container logs: {str(e)}"


@mcp.tool()
async def docker_container_stats() -> str:
    """
    Get live resource usage statistics for all Docker containers.

    Returns CPU%, memory usage/limit, memory%, network I/O, and block I/O
    for each running container. This is a snapshot (not streaming).
    """
    try:
        command = 'docker stats --no-stream --format "table {{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}\\t{{.MemPerc}}\\t{{.NetIO}}\\t{{.BlockIO}}"'
        output = await run_ssh_command(command)

        return f"Docker container resource usage:\n\n{output}"

    except Exception as e:
        return f"Error fetching container stats: {str(e)}"


@mcp.tool()
async def check_app_containers(name_filter: str = "") -> str:
    """
    Check health status of Docker containers, optionally filtered by name.

    Returns status, uptime, and health check information for matching containers.

    Args:
        name_filter: Optional container name filter (e.g., "my-app", "nginx"). Empty shows all containers.
    """
    try:
        filter_clause = ""
        if name_filter:
            if not re.match(r'^[a-zA-Z0-9._-]+$', name_filter):
                return "Error: Invalid name filter. Only alphanumeric, dots, underscores, and hyphens allowed."
            filter_clause = f" --filter name={shlex.quote(name_filter)}"

        list_command = f'docker ps -a{filter_clause} --format "table {{{{.Names}}}}\\t{{{{.Status}}}}\\t{{{{.Ports}}}}"'
        list_output = await run_ssh_command(list_command)

        containers = []
        for line in list_output.strip().split('\n')[1:]:
            parts = line.split('\t')
            if parts:
                containers.append(parts[0])

        filter_label = f" (filter: {name_filter})" if name_filter else ""
        result = f"Container health{filter_label}:\n\n{list_output}\n"

        if containers:
            result += "\n--- Health Details ---\n"
            for container in containers:
                health_command = f'docker inspect --format="{{{{.Name}}}}: {{{{.State.Health.Status}}}}" {shlex.quote(container)} 2>/dev/null || echo "{container}: no health check configured"'
                health_output = await run_ssh_command(health_command)
                result += f"{health_output}\n"

        return result

    except Exception as e:
        return f"Error checking container health: {str(e)}"


# ===========================
# Disk & I/O Monitoring Tools
# ===========================

@mcp.tool()
async def check_disk_io() -> str:
    """
    Check disk I/O statistics for all devices.

    Returns read/write throughput, IOPS, queue depth, and utilization per device.
    Requires iostat (sysstat package). Falls back to /proc/diskstats if unavailable.
    """
    try:
        # Try iostat first (more readable)
        output = await run_ssh_command("iostat -dx 1 1 2>/dev/null || cat /proc/diskstats")
        return f"Disk I/O statistics:\n\n{output}"

    except Exception as e:
        return f"Error checking disk I/O: {str(e)}"


@mcp.tool()
async def check_inode_usage() -> str:
    """
    Check inode usage for all filesystems.

    Servers can exhaust inodes before running out of disk space due to
    many small files. This shows inode counts and usage percentages.
    """
    try:
        output = await run_ssh_command("df -i")
        return f"Inode usage on remote server:\n\n{output}"

    except Exception as e:
        return f"Error checking inode usage: {str(e)}"


@mcp.tool()
async def check_disk_usage_by_path(path: str = "/") -> str:
    """
    Get disk usage breakdown for all subdirectories under a specific path.

    Args:
        path: Directory path to analyze (default: "/")
              Must start with / and contain only alphanumeric, /, _, ., - characters
              Maximum 512 characters

    Returns:
        Human-readable size summary for each immediate subdirectory
    """
    try:
        # Validate path to prevent command injection
        if not path:
            path = "/"

        if len(path) > 512:
            return "Error: path exceeds maximum length of 512 characters"

        # Strict path validation: must start with / and contain only safe characters
        path_regex = re.compile(r'^[a-zA-Z0-9/_.\-]+$')
        if not path.startswith('/') or not path_regex.match(path):
            return "Error: path must start with / and contain only alphanumeric, /, _, ., - characters"

        # Use shlex.quote for additional safety
        command = f"du -sh {shlex.quote(path)}/* 2>/dev/null | sort -rh"
        output = await run_ssh_command(command)

        if not output.strip():
            return f"No subdirectories found under {path} or path does not exist"

        return f"Disk usage breakdown for {path}:\n\n{output}"

    except Exception as e:
        return f"Error checking disk usage by path: {str(e)}"


# ===========================
# Network Monitoring Tools
# ===========================

@mcp.tool()
async def check_network_stats() -> str:
    """
    Get network interface statistics.

    Returns RX/TX bytes, packets, errors, and drops for each network interface.
    Useful for identifying network saturation or hardware issues.
    """
    try:
        output = await run_ssh_command("ip -s link")
        return f"Network interface statistics:\n\n{output}"

    except Exception as e:
        return f"Error checking network stats: {str(e)}"


@mcp.tool()
async def check_network_connections() -> str:
    """
    Get TCP connection state summary.

    Returns counts of connections in each state (ESTABLISHED, TIME-WAIT, CLOSE-WAIT, etc.).
    High TIME-WAIT or CLOSE-WAIT counts can indicate application issues.
    """
    try:
        output = await run_ssh_command("ss -s")
        return f"Network connection summary:\n\n{output}"

    except Exception as e:
        return f"Error checking network connections: {str(e)}"


@mcp.tool()
async def check_open_ports() -> str:
    """
    List all TCP listening ports with process information.

    Shows local address, port, and process name/PID for each listening socket.
    Essential for security audits and service discovery.
    """
    try:
        output = await run_ssh_command("ss -tlnp")
        return f"Open TCP listening ports:\n\n{output}"

    except Exception as e:
        return f"Error checking open ports: {str(e)}"


# ===========================
# Services & Logs Tools
# ===========================

@mcp.tool()
async def check_failed_services() -> str:
    """
    List all failed systemd services.

    Quick health check to identify any systemd units in failed state.
    Empty output means all services are healthy.
    """
    try:
        output = await run_ssh_command("systemctl --failed")

        if not output.strip() or "0 loaded units listed" in output:
            return "All systemd services are healthy (no failed units)"

        return f"Failed systemd services:\n\n{output}"

    except Exception as e:
        return f"Error checking failed services: {str(e)}"


@mcp.tool()
async def check_journal_logs(unit: str, lines: int = 50) -> str:
    """
    View logs for a specific systemd service.

    Args:
        unit: Service unit name (e.g., "nginx", "my-app")
              Alphanumeric, dots, underscores, hyphens only
        lines: Number of log lines to retrieve (1-500, default 50)

    Returns:
        Recent journal logs for the specified service
    """
    try:
        # Validate unit name
        _sanitize_identifier(unit, "unit")

        # Validate lines parameter
        if not isinstance(lines, int) or lines < 1 or lines > 500:
            return "Error: lines must be between 1 and 500"

        command = f"journalctl -u {shlex.quote(unit)} --no-pager -n {lines}"
        output = await run_ssh_command(command)

        return f"Journal logs for '{unit}' (last {lines} lines):\n\n{output}"

    except ValueError as e:
        return f"Validation error: {str(e)}"
    except Exception as e:
        return f"Error fetching journal logs: {str(e)}"


@mcp.tool()
async def check_dmesg_errors(lines: int = 50) -> str:
    """
    View recent kernel errors and warnings from dmesg.

    Shows OOM kills, hardware failures, disk errors, and other kernel-level issues.
    Critical for diagnosing system-level problems.

    Args:
        lines: Number of log lines to retrieve (1-500, default 50)

    Returns:
        Recent kernel error and warning messages with timestamps
    """
    try:
        # Validate lines parameter
        if not isinstance(lines, int) or lines < 1 or lines > 500:
            return "Error: lines must be between 1 and 500"

        # Use dmesg with human-readable timestamps and filter for errors/warnings
        command = f"dmesg --level=err,warn -T | tail -n {lines}"
        output = await run_ssh_command(command)

        if not output.strip():
            return "No recent kernel errors or warnings found"

        return f"Recent kernel errors/warnings (last {lines} lines):\n\n{output}"

    except Exception as e:
        return f"Error checking dmesg errors: {str(e)}"


# ===========================
# DNS & Security Tools
# ===========================

@mcp.tool()
async def check_dns_resolution(domain: str) -> str:
    """
    Test DNS resolution for a domain from the server's perspective.

    Performs both A record and MX record lookups. Essential for debugging
    connectivity issues and verifying DNS propagation.

    Args:
        domain: Domain name to resolve (alphanumeric, dots, hyphens only)

    Returns:
        A record and MX record resolution results
    """
    try:
        # Validate domain name
        _sanitize_identifier(domain, "domain")

        # Query A records
        a_command = f"dig +short {shlex.quote(domain)} A"
        a_output = await run_ssh_command(a_command)

        # Query MX records
        mx_command = f"dig +short {shlex.quote(domain)} MX"
        mx_output = await run_ssh_command(mx_command)

        result = f"DNS resolution for '{domain}':\n\n"
        result += "--- A Records ---\n"
        result += a_output.strip() if a_output.strip() else "(no A records found)\n"
        result += "\n\n--- MX Records ---\n"
        result += mx_output.strip() if mx_output.strip() else "(no MX records found)"

        return result

    except ValueError as e:
        return f"Validation error: {str(e)}"
    except Exception as e:
        return f"Error checking DNS resolution: {str(e)}"


@mcp.tool()
async def check_recent_logins(lines: int = 20) -> str:
    """
    Show recent login sessions to the server.

    Lists user logins with timestamps, source IPs, and session duration.
    Useful for security audits and tracking access patterns.

    Args:
        lines: Number of login records to show (1-100, default 20)

    Returns:
        Recent login history from wtmp
    """
    try:
        # Validate lines parameter
        if not isinstance(lines, int) or lines < 1 or lines > 100:
            return "Error: lines must be between 1 and 100"

        command = f"last -n {lines}"
        output = await run_ssh_command(command)

        return f"Recent login sessions (last {lines} entries):\n\n{output}"

    except Exception as e:
        return f"Error checking recent logins: {str(e)}"


