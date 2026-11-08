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


# ===========================
# Runtime & Platform Detection
# ===========================

@mcp.tool()
async def detect_runtime_environment() -> str:
    """
    Probe the remote server and detect ALL runtime platforms, OS info, and resource summary.

    Runs multiple checks in parallel for speed. Reports which platforms are available
    (Docker, Kubernetes, systemd, PM2, Supervisor) along with OS details and basic
    resource usage. This is the recommended first tool to run on a new server.
    """
    try:
        probes = await asyncio.gather(
            run_ssh_command("cat /etc/os-release 2>/dev/null | head -5"),
            run_ssh_command("hostname -f 2>/dev/null || hostname"),
            run_ssh_command("uptime"),
            run_ssh_command("free -h 2>/dev/null | head -2"),
            run_ssh_command("df -h / 2>/dev/null | tail -1"),
            run_ssh_command("nproc 2>/dev/null || echo unknown"),
            run_ssh_command("docker --version 2>/dev/null || echo NOT_INSTALLED"),
            run_ssh_command("docker ps -a --format '{{.Names}}\t{{.Status}}' 2>/dev/null || echo ''"),
            run_ssh_command("docker compose version 2>/dev/null || docker-compose --version 2>/dev/null || echo NOT_INSTALLED"),
            run_ssh_command("kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1 || echo NOT_INSTALLED"),
            run_ssh_command("kubectl get pods -A --no-headers 2>/dev/null | wc -l || echo 0"),
            run_ssh_command("systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | wc -l || echo 0"),
            run_ssh_command("systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null | wc -l || echo 0"),
            run_ssh_command("pm2 --version 2>/dev/null || echo NOT_INSTALLED"),
            run_ssh_command("supervisorctl version 2>/dev/null || echo NOT_INSTALLED"),
            return_exceptions=True
        )

        def safe(idx):
            r = probes[idx]
            return r.strip() if isinstance(r, str) else "(unavailable)"

        os_info = safe(0)
        hostname = safe(1)
        uptime_info = safe(2)
        memory_info = safe(3)
        disk_info = safe(4)
        cpu_count = safe(5)

        docker_ver = safe(6)
        docker_containers = safe(7)
        compose_ver = safe(8)
        kubectl_ver = safe(9)
        k8s_pods = safe(10)
        systemd_running = safe(11)
        systemd_failed = safe(12)
        pm2_ver = safe(13)
        supervisor_ver = safe(14)

        has_docker = "NOT_INSTALLED" not in docker_ver and "unavailable" not in docker_ver
        has_compose = "NOT_INSTALLED" not in compose_ver and "unavailable" not in compose_ver
        has_kubectl = "NOT_INSTALLED" not in kubectl_ver and "unavailable" not in kubectl_ver
        has_pm2 = "NOT_INSTALLED" not in pm2_ver and "unavailable" not in pm2_ver
        has_supervisor = "NOT_INSTALLED" not in supervisor_ver and "unavailable" not in supervisor_ver

        container_count = len([l for l in docker_containers.split('\n') if l.strip()]) if has_docker and docker_containers else 0
        running_containers = len([l for l in docker_containers.split('\n') if 'Up' in l]) if has_docker and docker_containers else 0

        result = "=== Server Runtime Environment ===\n\n"
        result += f"Host:        {hostname}\n"

        os_name = ""
        for line in os_info.split('\n'):
            if line.startswith("PRETTY_NAME="):
                os_name = line.split('=', 1)[1].strip('"')
                break
        if os_name:
            result += f"OS:          {os_name}\n"

        result += f"CPUs:        {cpu_count}\n"
        result += f"Uptime:      {uptime_info}\n"
        result += f"Memory:      {memory_info}\n"
        result += f"Root Disk:   {disk_info}\n\n"

        result += "--- Platforms Detected ---\n"

        if has_docker:
            result += f"  [x] Docker — {docker_ver} ({container_count} containers, {running_containers} running)\n"
        else:
            result += "  [ ] Docker — not installed\n"

        if has_compose:
            result += f"  [x] Docker Compose — {compose_ver}\n"
        else:
            result += "  [ ] Docker Compose — not installed\n"

        if has_kubectl:
            result += f"  [x] Kubernetes — {kubectl_ver} ({k8s_pods} pods across all namespaces)\n"
        else:
            result += "  [ ] Kubernetes (kubectl) — not installed\n"

        result += f"  [x] systemd — {systemd_running} services running, {systemd_failed} failed\n"

        if has_pm2:
            result += f"  [x] PM2 — v{pm2_ver}\n"
        else:
            result += "  [ ] PM2 — not installed\n"

        if has_supervisor:
            result += f"  [x] Supervisor — v{supervisor_ver}\n"
        else:
            result += "  [ ] Supervisor — not installed\n"

        if has_docker and docker_containers and container_count > 0:
            result += "\n--- Docker Containers ---\n"
            for line in docker_containers.split('\n'):
                if line.strip():
                    result += f"  {line}\n"

        return result

    except Exception as e:
        return f"Error detecting runtime environment: {str(e)}"


@mcp.tool()
async def detect_docker_environment() -> str:
    """
    Detailed Docker environment probe.

    Checks Docker installation, daemon status, lists all containers with their
    status and images, detects Docker Compose and Docker Swarm. Use this for
    a deep dive into Docker when detect_runtime_environment shows Docker is present.
    """
    try:
        version_output = await run_ssh_command("docker --version 2>/dev/null || echo NOT_INSTALLED")

        if "NOT_INSTALLED" in version_output:
            return "Docker is not installed on this server."

        probes = await asyncio.gather(
            run_ssh_command("docker info --format '{{.ServerVersion}}' 2>/dev/null || echo DAEMON_NOT_RUNNING"),
            run_ssh_command('docker ps -a --format "table {{.ID}}\\t{{.Names}}\\t{{.Status}}\\t{{.Image}}\\t{{.Ports}}" 2>/dev/null'),
            run_ssh_command("docker compose version 2>/dev/null || docker-compose --version 2>/dev/null || echo NOT_INSTALLED"),
            run_ssh_command("docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || echo unknown"),
            run_ssh_command('docker network ls --format "table {{.Name}}\\t{{.Driver}}\\t{{.Scope}}" 2>/dev/null'),
            run_ssh_command('docker volume ls --format "table {{.Name}}\\t{{.Driver}}" 2>/dev/null | head -20'),
            return_exceptions=True
        )

        def safe(idx):
            r = probes[idx]
            return r.strip() if isinstance(r, str) else "(unavailable)"

        daemon_ver = safe(0)
        containers = safe(1)
        compose = safe(2)
        swarm_state = safe(3)
        networks = safe(4)
        volumes = safe(5)

        result = "=== Docker Environment ===\n\n"
        result += f"Docker Version:   {version_output.strip()}\n"

        if "DAEMON_NOT_RUNNING" in daemon_ver:
            result += "Daemon Status:    NOT RUNNING\n"
        else:
            result += f"Daemon Status:    Running (Server v{daemon_ver})\n"

        if "NOT_INSTALLED" not in compose:
            result += f"Docker Compose:   {compose}\n"
        else:
            result += "Docker Compose:   Not installed\n"

        result += f"Swarm State:      {swarm_state}\n\n"

        result += "--- Containers ---\n"
        result += f"{containers}\n\n" if containers else "  (no containers)\n\n"

        result += "--- Networks ---\n"
        result += f"{networks}\n\n" if networks else "  (no networks)\n\n"

        result += "--- Volumes (first 20) ---\n"
        result += f"{volumes}\n" if volumes else "  (no volumes)\n"

        return result

    except Exception as e:
        return f"Error detecting Docker environment: {str(e)}"


@mcp.tool()
async def detect_kubernetes_environment() -> str:
    """
    Probe Kubernetes environment via kubectl.

    Checks if kubectl is installed and configured, shows cluster info,
    namespaces, pods, services, and deployments. Requires kubectl to be
    available and configured on the remote server.
    """
    try:
        kubectl_check = await run_ssh_command("kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1 || echo NOT_INSTALLED")

        if "NOT_INSTALLED" in kubectl_check:
            return "Kubernetes (kubectl) is not installed on this server."

        cluster_check = await run_ssh_command("kubectl cluster-info 2>/dev/null || echo CLUSTER_NOT_REACHABLE")

        if "CLUSTER_NOT_REACHABLE" in cluster_check:
            return f"kubectl is installed ({kubectl_check.strip()}) but cannot reach a cluster. The kubeconfig may not be set up for this SSH user."

        probes = await asyncio.gather(
            run_ssh_command("kubectl get namespaces --no-headers 2>/dev/null | head -30"),
            run_ssh_command("kubectl get pods -A --no-headers 2>/dev/null | head -50"),
            run_ssh_command("kubectl get services -A --no-headers 2>/dev/null | head -50"),
            run_ssh_command("kubectl get deployments -A --no-headers 2>/dev/null | head -30"),
            return_exceptions=True
        )

        def safe(idx):
            r = probes[idx]
            return r.strip() if isinstance(r, str) else "(unavailable)"

        namespaces = safe(0)
        pods = safe(1)
        services = safe(2)
        deployments = safe(3)

        result = "=== Kubernetes Environment ===\n\n"
        result += f"kubectl:     {kubectl_check.strip()}\n"
        result += f"Cluster:     {cluster_check.strip().split(chr(10))[0]}\n\n"

        result += "--- Namespaces ---\n"
        result += f"{namespaces}\n\n" if namespaces else "  (none)\n\n"

        result += "--- Pods (first 50) ---\n"
        result += f"{pods}\n\n" if pods else "  (no pods)\n\n"

        result += "--- Services (first 50) ---\n"
        result += f"{services}\n\n" if services else "  (no services)\n\n"

        result += "--- Deployments (first 30) ---\n"
        result += f"{deployments}\n" if deployments else "  (no deployments)\n"

        return result

    except Exception as e:
        return f"Error detecting Kubernetes environment: {str(e)}"


@mcp.tool()
async def detect_systemd_services(state_filter: str = "active") -> str:
    """
    List systemd services filtered by state.

    Provides a full inventory of systemd services, unlike check_failed_services
    which only shows failed units.

    Args:
        state_filter: One of "active", "failed", "inactive", "all" (default "active")
    """
    try:
        if state_filter not in ALLOWED_SERVICE_STATES:
            return f"Error: state_filter must be one of {', '.join(sorted(ALLOWED_SERVICE_STATES))}. Got: '{state_filter}'"

        if state_filter == "all":
            command = "systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | head -80"
        else:
            command = f"systemctl list-units --type=service --state={state_filter} --no-pager --no-legend 2>/dev/null | head -80"

        output = await run_ssh_command(command)

        if not output.strip():
            return f"No systemd services found with state '{state_filter}'"

        count = len([l for l in output.strip().split('\n') if l.strip()])
        result = f"=== systemd Services (state: {state_filter}) ===\n\n"
        result += f"{output}\n\n"
        result += f"--- Showing {count} service(s) (capped at 80) ---"

        return result

    except Exception as e:
        return f"Error detecting systemd services: {str(e)}"


@mcp.tool()
async def detect_process_managers() -> str:
    """
    Detect PM2, Supervisor, and other process managers on the remote server.

    Checks for PM2, Supervisor, and forever. For each detected manager,
    lists the processes it manages.
    """
    try:
        probes = await asyncio.gather(
            run_ssh_command("pm2 --version 2>/dev/null || echo NOT_INSTALLED"),
            run_ssh_command("pm2 list 2>/dev/null || echo ''"),
            run_ssh_command("supervisorctl version 2>/dev/null || echo NOT_INSTALLED"),
            run_ssh_command("supervisorctl status 2>/dev/null || echo ''"),
            run_ssh_command("forever list 2>/dev/null || echo NOT_INSTALLED"),
            return_exceptions=True
        )

        def safe(idx):
            r = probes[idx]
            return r.strip() if isinstance(r, str) else "(unavailable)"

        pm2_ver = safe(0)
        pm2_list = safe(1)
        supervisor_ver = safe(2)
        supervisor_status = safe(3)
        forever_list = safe(4)

        has_pm2 = "NOT_INSTALLED" not in pm2_ver
        has_supervisor = "NOT_INSTALLED" not in supervisor_ver
        has_forever = "NOT_INSTALLED" not in forever_list

        if not has_pm2 and not has_supervisor and not has_forever:
            return "No additional process managers detected (PM2, Supervisor, forever are not installed)."

        result = "=== Process Managers Detected ===\n\n"

        if has_pm2:
            result += f"--- PM2 (v{pm2_ver}) ---\n"
            result += f"{pm2_list}\n\n" if pm2_list else "  (no processes)\n\n"
        else:
            result += "--- PM2 ---\n  Not installed\n\n"

        if has_supervisor:
            result += f"--- Supervisor (v{supervisor_ver}) ---\n"
            result += f"{supervisor_status}\n\n" if supervisor_status else "  (no processes)\n\n"
        else:
            result += "--- Supervisor ---\n  Not installed\n\n"

        if has_forever:
            result += f"--- forever ---\n{forever_list}\n"
        else:
            result += "--- forever ---\n  Not installed\n"

        return result

    except Exception as e:
        return f"Error detecting process managers: {str(e)}"


# ===========================
# Application Stack Detection & Diagnostics
# ===========================

@mcp.tool()
async def detect_application_stack() -> str:
    """
    Auto-detect the application stack running on the server.

    Identifies web servers (nginx, Apache, Caddy), databases (MySQL, PostgreSQL, MongoDB,
    Redis), language runtimes (Node.js, Python, Java, Go, Ruby, .NET), and other
    common services by examining running processes, listening ports, and installed runtimes.
    """
    try:
        probes = await asyncio.gather(
            run_ssh_command("ps aux 2>/dev/null | grep -E '(nginx|apache2|httpd|caddy|lighttpd|haproxy)' | grep -v grep | head -10"),
            run_ssh_command("ps aux 2>/dev/null | grep -E '(mysqld|mariadbd|postgres|mongod|mongos|redis-server|memcached|elasticsearch|clickhouse)' | grep -v grep | head -10"),
            run_ssh_command("ps aux 2>/dev/null | grep -E '(node |python3?|java |ruby |dotnet |beam.smp|php-fpm|gunicorn|uvicorn|puma|pm2)' | grep -v grep | head -15"),
            run_ssh_command("ss -tlnp 2>/dev/null | grep LISTEN | head -30"),
            run_ssh_command("command -v node && node --version 2>/dev/null || echo ''"),
            run_ssh_command("command -v python3 && python3 --version 2>/dev/null || echo ''"),
            run_ssh_command("command -v java && java -version 2>&1 | head -1 || echo ''"),
            run_ssh_command("command -v go && go version 2>/dev/null || echo ''"),
            run_ssh_command("command -v ruby && ruby --version 2>/dev/null || echo ''"),
            run_ssh_command("command -v dotnet && dotnet --version 2>/dev/null || echo ''"),
            run_ssh_command("command -v php && php --version 2>/dev/null | head -1 || echo ''"),
            return_exceptions=True
        )

        def safe(idx):
            r = probes[idx]
            return r.strip() if isinstance(r, str) else ""

        web_servers = safe(0)
        databases = safe(1)
        app_processes = safe(2)
        listening_ports = safe(3)
        node_ver = safe(4)
        python_ver = safe(5)
        java_ver = safe(6)
        go_ver = safe(7)
        ruby_ver = safe(8)
        dotnet_ver = safe(9)
        php_ver = safe(10)

        result = "=== Application Stack Detection ===\n\n"

        result += "--- Web Servers / Reverse Proxies ---\n"
        if web_servers:
            for line in web_servers.split('\n'):
                if line.strip():
                    parts = line.split()
                    result += f"  {parts[10] if len(parts) > 10 else parts[-1]} (PID: {parts[1] if len(parts) > 1 else '?'})\n"
        else:
            result += "  (none detected)\n"

        result += "\n--- Databases & Data Stores ---\n"
        if databases:
            for line in databases.split('\n'):
                if line.strip():
                    parts = line.split()
                    result += f"  {parts[10] if len(parts) > 10 else parts[-1]} (PID: {parts[1] if len(parts) > 1 else '?'})\n"
        else:
            result += "  (none detected)\n"

        result += "\n--- Application Processes ---\n"
        if app_processes:
            for line in app_processes.split('\n'):
                if line.strip():
                    parts = line.split()
                    result += f"  {' '.join(parts[10:]) if len(parts) > 10 else parts[-1]} (User: {parts[0] if parts else '?'}, PID: {parts[1] if len(parts) > 1 else '?'})\n"
        else:
            result += "  (none detected)\n"

        result += "\n--- Installed Language Runtimes ---\n"
        runtimes = [
            ("Node.js", node_ver), ("Python", python_ver), ("Java", java_ver),
            ("Go", go_ver), ("Ruby", ruby_ver), (".NET", dotnet_ver), ("PHP", php_ver)
        ]
        found_any = False
        for name, ver in runtimes:
            if ver and "command -v" not in ver:
                result += f"  {name}: {ver.split(chr(10))[-1]}\n"
                found_any = True
        if not found_any:
            result += "  (none detected)\n"

        result += "\n--- Listening Ports ---\n"
        if listening_ports:
            result += f"{listening_ports}\n"
        else:
            result += "  (none detected)\n"

        return result

    except Exception as e:
        return f"Error detecting application stack: {str(e)}"


@mcp.tool()
async def find_application(name: str) -> str:
    """
    Find an application or service across all platforms.

    Searches Docker containers, systemd services, Kubernetes pods, PM2 processes,
    and system processes for the given name.

    Args:
        name: Application or service name to search for (partial match)
    """
    try:
        _sanitize_identifier(name, "name")
        quoted_name = shlex.quote(name)

        probes = await asyncio.gather(
            run_ssh_command(f'docker ps -a --filter "name={quoted_name}" --format "table {{{{.Names}}}}\\t{{{{.Status}}}}\\t{{{{.Image}}}}\\t{{{{.Ports}}}}" 2>/dev/null || echo ""'),
            run_ssh_command(f"systemctl list-units --type=service --no-pager --no-legend 2>/dev/null | grep -i {quoted_name} || echo ''"),
            run_ssh_command(f"kubectl get pods -A --no-headers 2>/dev/null | grep -i {quoted_name} | head -20 || echo ''"),
            run_ssh_command(f"pm2 show {quoted_name} 2>/dev/null | head -20 || echo ''"),
            run_ssh_command(f"pgrep -a -i {quoted_name} 2>/dev/null | head -20 || echo ''"),
            return_exceptions=True
        )

        def safe(idx):
            r = probes[idx]
            return r.strip() if isinstance(r, str) else ""

        docker_result = safe(0)
        systemd_result = safe(1)
        k8s_result = safe(2)
        pm2_result = safe(3)
        process_result = safe(4)

        found_anywhere = False
        result = f"=== Search Results for '{name}' ===\n\n"

        result += "--- Docker ---\n"
        if docker_result and "NAMES" in docker_result and len(docker_result.split('\n')) > 1:
            result += f"  {docker_result}\n\n"
            found_anywhere = True
        elif docker_result and "NAMES" not in docker_result and docker_result:
            result += f"  {docker_result}\n\n"
            found_anywhere = True
        else:
            result += "  (not found in Docker containers)\n\n"

        result += "--- systemd ---\n"
        if systemd_result:
            result += f"  {systemd_result}\n\n"
            found_anywhere = True
        else:
            result += "  (not found in systemd services)\n\n"

        result += "--- Kubernetes ---\n"
        if k8s_result:
            result += f"  {k8s_result}\n\n"
            found_anywhere = True
        else:
            result += "  (not found in Kubernetes pods)\n\n"

        result += "--- PM2 ---\n"
        if pm2_result:
            result += f"  {pm2_result}\n\n"
            found_anywhere = True
        else:
            result += "  (not found in PM2)\n\n"

        result += "--- System Processes ---\n"
        if process_result:
            result += f"  {process_result}\n"
            found_anywhere = True
        else:
            result += "  (no matching processes found)\n"

        if not found_anywhere:
            result += f"\nApplication '{name}' was not found on any platform."

        return result

    except ValueError as e:
        return f"Validation error: {str(e)}"
    except Exception as e:
        return f"Error finding application: {str(e)}"


@mcp.tool()
async def get_application_logs(name: str, platform: str = "auto", lines: int = 100) -> str:
    """
    Get logs for an application regardless of which platform runs it.

    Auto-detects the platform or uses the specified one to fetch logs.

    Args:
        name: Application/container/service name
        platform: One of "auto", "docker", "systemd", "kubernetes", "pm2" (default "auto")
        lines: Number of log lines to retrieve (1-1000, default 100)
    """
    try:
        _sanitize_identifier(name, "name")

        if platform not in ALLOWED_PLATFORMS:
            return f"Error: platform must be one of {', '.join(sorted(ALLOWED_PLATFORMS))}. Got: '{platform}'"

        if not isinstance(lines, int) or lines < 1 or lines > 1000:
            return "Error: lines must be between 1 and 1000"

        quoted_name = shlex.quote(name)

        if platform == "auto":
            # Try each platform in order, return first successful result
            platforms_to_try = ["docker", "systemd", "kubernetes", "pm2"]
        else:
            platforms_to_try = [platform]

        for plat in platforms_to_try:
            try:
                if plat == "docker":
                    output = await run_ssh_command(f"docker logs --tail {lines} {quoted_name} 2>&1")
                    if output.strip() and "No such container" not in output and "Error" not in output.split('\n')[0]:
                        return f"Logs from Docker container '{name}' (last {lines} lines):\n\n{output}"
                elif plat == "systemd":
                    output = await run_ssh_command(f"journalctl -u {quoted_name} --no-pager -n {lines} 2>/dev/null")
                    if output.strip() and "No entries" not in output and "-- No entries --" not in output:
                        return f"Logs from systemd unit '{name}' (last {lines} lines):\n\n{output}"
                elif plat == "kubernetes":
                    # First find the pod
                    pod_output = await run_ssh_command(f"kubectl get pods -A --no-headers 2>/dev/null | grep -i {quoted_name} | head -1")
                    if pod_output.strip():
                        parts = pod_output.strip().split()
                        if len(parts) >= 2:
                            namespace = parts[0]
                            pod_name = parts[1]
                            output = await run_ssh_command(f"kubectl logs {shlex.quote(pod_name)} -n {shlex.quote(namespace)} --tail={lines} 2>/dev/null")
                            if output.strip():
                                return f"Logs from Kubernetes pod '{pod_name}' in namespace '{namespace}' (last {lines} lines):\n\n{output}"
                elif plat == "pm2":
                    output = await run_ssh_command(f"pm2 logs {quoted_name} --lines {lines} --nostream 2>/dev/null")
                    if output.strip():
                        return f"Logs from PM2 process '{name}' (last {lines} lines):\n\n{output}"
            except Exception:
                continue

        return f"Could not find logs for '{name}' on any platform ({', '.join(platforms_to_try)}). Use find_application to locate it first."

    except ValueError as e:
        return f"Validation error: {str(e)}"
    except Exception as e:
        return f"Error fetching application logs: {str(e)}"


@mcp.tool()
async def check_application_health(name: str) -> str:
    """
    Comprehensive health check for a named application across all platforms.

    Checks running status, resource usage, recent errors, and listening ports
    for the application on Docker, systemd, Kubernetes, and PM2.

    Args:
        name: Application or service name to check
    """
    try:
        _sanitize_identifier(name, "name")
        quoted_name = shlex.quote(name)

        probes = await asyncio.gather(
            run_ssh_command(f'docker inspect --format "Status: {{{{.State.Status}}}}  Health: {{{{.State.Health.Status}}}}  Restarts: {{{{.RestartCount}}}}" {quoted_name} 2>/dev/null || docker inspect --format "Status: {{{{.State.Status}}}}  Restarts: {{{{.RestartCount}}}}" {quoted_name} 2>/dev/null || echo NOT_FOUND'),
            run_ssh_command(f"docker stats --no-stream --format 'CPU: {{{{.CPUPerc}}}}  Memory: {{{{.MemUsage}}}} ({{{{.MemPerc}}}})' {quoted_name} 2>/dev/null || echo ''"),
            run_ssh_command(f"systemctl show {quoted_name} --property=ActiveState,SubState,MainPID,MemoryCurrent --no-pager 2>/dev/null || echo ''"),
            run_ssh_command(f"kubectl get pods -A --no-headers 2>/dev/null | grep -i {quoted_name} | head -5 || echo ''"),
            run_ssh_command(f"pm2 show {quoted_name} 2>/dev/null | grep -E '(status|cpu|memory|restarts|uptime)' | head -10 || echo ''"),
            run_ssh_command(f"docker logs --tail 10 {quoted_name} 2>&1 | grep -iE '(error|exception|fatal|panic|critical)' | tail -5 || echo ''"),
            run_ssh_command(f"journalctl -u {quoted_name} -p err --no-pager -n 5 2>/dev/null || echo ''"),
            return_exceptions=True
        )

        def safe(idx):
            r = probes[idx]
            return r.strip() if isinstance(r, str) else ""

        docker_status = safe(0)
        docker_stats = safe(1)
        systemd_status = safe(2)
        k8s_pods = safe(3)
        pm2_status = safe(4)
        docker_errors = safe(5)
        systemd_errors = safe(6)

        found_on = []
        result = f"=== Health Check: {name} ===\n\n"

        if "NOT_FOUND" not in docker_status:
            found_on.append("Docker")
            result += "--- Docker ---\n"
            result += f"  {docker_status}\n"
            if docker_stats:
                result += f"  Resources: {docker_stats}\n"
            if docker_errors:
                result += f"  Recent Errors:\n"
                for line in docker_errors.split('\n'):
                    if line.strip():
                        result += f"    {line.strip()}\n"
            result += "\n"

        if systemd_status and "ActiveState=" in systemd_status:
            found_on.append("systemd")
            result += "--- systemd ---\n"
            for line in systemd_status.split('\n'):
                if line.strip() and '=' in line:
                    result += f"  {line.strip()}\n"
            if systemd_errors:
                result += f"  Recent Errors:\n"
                for line in systemd_errors.split('\n'):
                    if line.strip():
                        result += f"    {line.strip()}\n"
            result += "\n"

        if k8s_pods:
            found_on.append("Kubernetes")
            result += "--- Kubernetes ---\n"
            for line in k8s_pods.split('\n'):
                if line.strip():
                    result += f"  {line.strip()}\n"
            result += "\n"

        if pm2_status:
            found_on.append("PM2")
            result += "--- PM2 ---\n"
            for line in pm2_status.split('\n'):
                if line.strip():
                    result += f"  {line.strip()}\n"
            result += "\n"

        if found_on:
            result += f"--- Overall: Found on {', '.join(found_on)} ---"
        else:
            result += f"Application '{name}' was not found on any platform (Docker, systemd, Kubernetes, PM2)."

        return result

    except ValueError as e:
        return f"Validation error: {str(e)}"
    except Exception as e:
        return f"Error checking application health: {str(e)}"


@mcp.tool()
async def find_application_errors(name: str, hours: int = 24, platform: str = "auto") -> str:
    """
    Search for recent errors in an application's logs across platforms.

    Looks for error, exception, fatal, panic, and critical messages in the
    application's logs within the specified time window.

    Args:
        name: Application or service name
        hours: Hours to look back (1-168, default 24)
        platform: One of "auto", "docker", "systemd", "kubernetes", "pm2" (default "auto")
    """
    try:
        _sanitize_identifier(name, "name")

        if platform not in ALLOWED_PLATFORMS:
            return f"Error: platform must be one of {', '.join(sorted(ALLOWED_PLATFORMS))}. Got: '{platform}'"

        if not isinstance(hours, int) or hours < 1 or hours > 168:
            return "Error: hours must be between 1 and 168"

        quoted_name = shlex.quote(name)
        error_grep = "grep -iE '(error|exception|fatal|panic|critical|traceback)'"

        platforms_to_try = ["docker", "systemd", "kubernetes", "pm2"] if platform == "auto" else [platform]

        result = f"=== Error Search: {name} (last {hours} hours) ===\n\n"
        total_errors = 0

        for plat in platforms_to_try:
            try:
                if plat == "docker":
                    output = await run_ssh_command(f"docker logs --since {hours}h {quoted_name} 2>&1 | {error_grep} | tail -30 || echo ''")
                    if output.strip():
                        count = len([l for l in output.strip().split('\n') if l.strip()])
                        total_errors += count
                        result += f"--- Docker ({count} matches) ---\n{output}\n\n"
                elif plat == "systemd":
                    output = await run_ssh_command(f'journalctl -u {quoted_name} --since "{hours} hours ago" -p err --no-pager -n 30 2>/dev/null || echo ""')
                    if output.strip():
                        count = len([l for l in output.strip().split('\n') if l.strip()])
                        total_errors += count
                        result += f"--- systemd ({count} matches) ---\n{output}\n\n"
                elif plat == "kubernetes":
                    pod_output = await run_ssh_command(f"kubectl get pods -A --no-headers 2>/dev/null | grep -i {quoted_name} | head -1")
                    if pod_output.strip():
                        parts = pod_output.strip().split()
                        if len(parts) >= 2:
                            output = await run_ssh_command(f"kubectl logs {shlex.quote(parts[1])} -n {shlex.quote(parts[0])} --since={hours}h 2>/dev/null | {error_grep} | tail -30 || echo ''")
                            if output.strip():
                                count = len([l for l in output.strip().split('\n') if l.strip()])
                                total_errors += count
                                result += f"--- Kubernetes ({count} matches) ---\n{output}\n\n"
                elif plat == "pm2":
                    output = await run_ssh_command(f"pm2 logs {quoted_name} --lines 500 --nostream 2>/dev/null | {error_grep} | tail -30 || echo ''")
                    if output.strip():
                        count = len([l for l in output.strip().split('\n') if l.strip()])
                        total_errors += count
                        result += f"--- PM2 ({count} matches) ---\n{output}\n\n"
            except Exception:
                continue

        if total_errors == 0:
            result += f"No errors found for '{name}' in the last {hours} hours."
        else:
            result += f"--- Total: {total_errors} error(s) found ---"

        return result

    except ValueError as e:
        return f"Validation error: {str(e)}"
    except Exception as e:
        return f"Error searching application errors: {str(e)}"


# ===========================
# Smart Troubleshooting
# ===========================

@mcp.tool()
async def full_system_health_scan() -> str:
    """
    One-shot comprehensive system health scan with intelligent threshold checks.

    Checks disk, memory, CPU load, inodes, failed services, Docker containers,
    kernel errors, and network connections. Flags issues as OK, WARNING, or CRITICAL.
    This is the recommended first troubleshooting tool when something seems wrong.
    """
    try:
        probes = await asyncio.gather(
            run_ssh_command("uptime"),
            run_ssh_command("cat /proc/loadavg"),
            run_ssh_command("nproc 2>/dev/null || echo 1"),
            run_ssh_command("free -m 2>/dev/null"),
            run_ssh_command("df -h 2>/dev/null"),
            run_ssh_command("df -i 2>/dev/null"),
            run_ssh_command("systemctl --failed --no-pager --no-legend 2>/dev/null"),
            run_ssh_command('docker ps -a --format "{{.Names}}\t{{.Status}}" 2>/dev/null || echo ""'),
            run_ssh_command("dmesg --level=err,warn -T 2>/dev/null | tail -5 || echo ''"),
            run_ssh_command("ss -s 2>/dev/null"),
            run_ssh_command("ps aux 2>/dev/null | awk '$8==\"Z\"' | head -5 || echo ''"),
            return_exceptions=True
        )

        def safe(idx):
            r = probes[idx]
            return r.strip() if isinstance(r, str) else "(unavailable)"

        uptime_info = safe(0)
        loadavg = safe(1)
        cpus = safe(2)
        memory = safe(3)
        disk = safe(4)
        inodes = safe(5)
        failed_services = safe(6)
        docker_containers = safe(7)
        dmesg_errors = safe(8)
        network_summary = safe(9)
        zombies = safe(10)

        warnings = 0
        criticals = 0
        result = "=== Full System Health Scan ===\n\n"

        # Load average check
        try:
            cpu_count = int(cpus) if cpus.isdigit() else 1
            load_parts = loadavg.split()
            load_1m = float(load_parts[0])
            if load_1m > cpu_count * 2:
                status = "CRITICAL"
                criticals += 1
            elif load_1m > cpu_count:
                status = "WARNING"
                warnings += 1
            else:
                status = "OK"
            result += f"--- System Load ---\n"
            result += f"  {uptime_info}\n"
            result += f"  Load 1m: {load_1m} / {cpu_count} CPUs  [{status}]\n\n"
        except Exception:
            result += f"--- System Load ---\n  {uptime_info}  [OK]\n\n"

        # Memory check
        result += "--- Memory ---\n"
        try:
            mem_lines = memory.split('\n')
            for line in mem_lines:
                result += f"  {line}\n"
            # Parse memory percentage from 'free -m' output
            if len(mem_lines) >= 2:
                parts = mem_lines[1].split()
                if len(parts) >= 3:
                    total = int(parts[1])
                    used = int(parts[2])
                    pct = (used / total * 100) if total > 0 else 0
                    if pct > 95:
                        result += f"  Usage: {pct:.0f}%  [CRITICAL]\n"
                        criticals += 1
                    elif pct > 85:
                        result += f"  Usage: {pct:.0f}%  [WARNING]\n"
                        warnings += 1
                    else:
                        result += f"  Usage: {pct:.0f}%  [OK]\n"
        except Exception:
            result += f"  {memory}\n"
        result += "\n"

        # Disk check
        result += "--- Disk ---\n"
        try:
            for line in disk.split('\n'):
                if line.strip() and not line.startswith("Filesystem"):
                    parts = line.split()
                    if len(parts) >= 5:
                        use_pct = parts[4].rstrip('%')
                        if use_pct.isdigit():
                            pct = int(use_pct)
                            if pct > 95:
                                result += f"  {line}  [CRITICAL]\n"
                                criticals += 1
                            elif pct > 85:
                                result += f"  {line}  [WARNING]\n"
                                warnings += 1
                            else:
                                result += f"  {line}  [OK]\n"
                        else:
                            result += f"  {line}\n"
                    else:
                        result += f"  {line}\n"
        except Exception:
            result += f"  {disk}\n"
        result += "\n"

        # Inode check
        result += "--- Inodes ---\n"
        try:
            inode_issues = False
            for line in inodes.split('\n'):
                if line.strip() and not line.startswith("Filesystem"):
                    parts = line.split()
                    if len(parts) >= 5:
                        use_pct = parts[4].rstrip('%')
                        if use_pct.isdigit() and int(use_pct) > 80:
                            result += f"  {line}  [WARNING]\n"
                            warnings += 1
                            inode_issues = True
            if not inode_issues:
                result += "  All filesystems OK\n"
        except Exception:
            result += "  (could not check)\n"
        result += "\n"

        # Failed services
        result += "--- Failed Services ---\n"
        if failed_services and "0 loaded units listed" not in failed_services:
            count = len([l for l in failed_services.split('\n') if l.strip()])
            result += f"  {failed_services}\n"
            result += f"  [{count} failed service(s) — WARNING]\n"
            warnings += count
        else:
            result += "  None  [OK]\n"
        result += "\n"

        # Docker containers
        result += "--- Docker Containers ---\n"
        if docker_containers:
            stopped = []
            running = 0
            for line in docker_containers.split('\n'):
                if line.strip():
                    if 'Up' in line:
                        running += 1
                    else:
                        stopped.append(line.strip())
            result += f"  Running: {running}\n"
            if stopped:
                for s in stopped:
                    result += f"  Stopped: {s}  [WARNING]\n"
                    warnings += 1
            else:
                result += "  All containers running  [OK]\n"
        else:
            result += "  Docker not available or no containers\n"
        result += "\n"

        # Kernel errors
        result += "--- Recent Kernel Issues ---\n"
        if dmesg_errors:
            result += f"  {dmesg_errors}\n"
            result += "  [WARNING — kernel errors detected]\n"
            warnings += 1
        else:
            result += "  None  [OK]\n"
        result += "\n"

        # Zombie processes
        result += "--- Zombie Processes ---\n"
        if zombies:
            count = len([l for l in zombies.split('\n') if l.strip()])
            result += f"  {count} zombie process(es) found  [WARNING]\n"
            warnings += 1
        else:
            result += "  None  [OK]\n"
        result += "\n"

        # Network
        result += "--- Network ---\n"
        result += f"  {network_summary}\n\n"

        # Summary
        if criticals > 0:
            overall = "CRITICAL"
        elif warnings > 0:
            overall = "WARNINGS"
        else:
            overall = "HEALTHY"

        result += f"=== Overall: {overall} ({criticals} critical, {warnings} warnings) ==="

        return result

    except Exception as e:
        return f"Error running system health scan: {str(e)}"


@mcp.tool()
async def check_port_connectivity(port: int, host: str = "localhost") -> str:
    """
    Check if a specific port is listening, what process owns it, and test connectivity.

    Args:
        port: Port number to check (1-65535)
        host: Host to check (default "localhost")
    """
    try:
        if not isinstance(port, int) or port < 1 or port > 65535:
            return "Error: port must be between 1 and 65535"

        _sanitize_identifier(host, "host")

        quoted_host = shlex.quote(host)

        probes = await asyncio.gather(
            run_ssh_command(f"ss -tlnp 2>/dev/null | grep ':{port} ' || echo 'NOT_LISTENING'"),
            run_ssh_command(f'timeout 5 bash -c "echo >/dev/tcp/{quoted_host}/{port}" 2>/dev/null && echo OPEN || echo CLOSED'),
            run_ssh_command(f'curl -s -o /dev/null -w "%{{http_code}}" --connect-timeout 5 http://{quoted_host}:{port}/ 2>/dev/null || echo NO_HTTP'),
            return_exceptions=True
        )

        def safe(idx):
            r = probes[idx]
            return r.strip() if isinstance(r, str) else "(unavailable)"

        ss_output = safe(0)
        tcp_test = safe(1)
        http_test = safe(2)

        result = f"=== Port Check: {port} on {host} ===\n\n"

        if "NOT_LISTENING" in ss_output:
            result += "Listening:    No — nothing is bound to this port\n"
        else:
            result += "Listening:    Yes\n"
            for line in ss_output.split('\n'):
                if line.strip():
                    result += f"  {line.strip()}\n"

        result += f"\nTCP Test:     {tcp_test}\n"

        if http_test and http_test != "NO_HTTP":
            result += f"HTTP Test:    Status {http_test}\n"
        else:
            result += "HTTP Test:    No HTTP response (not an HTTP service or connection refused)\n"

        return result

    except ValueError as e:
        return f"Validation error: {str(e)}"
    except Exception as e:
        return f"Error checking port connectivity: {str(e)}"


@mcp.tool()
async def check_ssl_certificate(host: str, port: int = 443) -> str:
    """
    Check SSL/TLS certificate validity, expiration, and issuer.

    Connects to the specified host:port and retrieves certificate details
    including subject, issuer, validity dates, and days until expiration.

    Args:
        host: Hostname or IP to check
        port: Port number (default 443)
    """
    try:
        _sanitize_identifier(host, "host")

        if not isinstance(port, int) or port < 1 or port > 65535:
            return "Error: port must be between 1 and 65535"

        quoted_host = shlex.quote(host)

        cert_output = await run_ssh_command(
            f"echo | openssl s_client -connect {quoted_host}:{port} -servername {quoted_host} 2>/dev/null "
            f"| openssl x509 -noout -subject -issuer -dates -serial 2>/dev/null"
        )

        if not cert_output.strip():
            return f"Could not retrieve SSL certificate from {host}:{port}. The host may not support SSL/TLS on this port, or openssl is not installed."

        expiry_check = await run_ssh_command(
            f"echo | openssl s_client -connect {quoted_host}:{port} -servername {quoted_host} 2>/dev/null "
            f"| openssl x509 -noout -checkend 2592000 2>/dev/null && echo VALID_30D || echo EXPIRING_30D"
        )

        result = f"=== SSL Certificate: {host}:{port} ===\n\n"

        for line in cert_output.strip().split('\n'):
            if line.strip():
                result += f"  {line.strip()}\n"

        result += "\n"

        if "EXPIRING_30D" in expiry_check:
            result += "Status: WARNING — certificate expires within 30 days!\n"
        else:
            result += "Status: VALID (not expiring within 30 days)\n"

        return result

    except ValueError as e:
        return f"Validation error: {str(e)}"
    except Exception as e:
        return f"Error checking SSL certificate: {str(e)}"


@mcp.tool()
async def find_error_patterns(hours: int = 1, pattern: str = "error") -> str:
    """
    Search ALL log sources for error patterns.

    Scans system journal, kernel logs (dmesg), Docker container logs, and /var/log
    files for the specified error pattern within the time window.

    Args:
        hours: Hours to look back (1-72, default 1)
        pattern: Error pattern to search for (default "error"). Must be one of:
                 error, exception, fatal, panic, critical, warning, oom, timeout,
                 refused, denied, traceback, segfault, killed, fail
    """
    try:
        if not isinstance(hours, int) or hours < 1 or hours > 72:
            return "Error: hours must be between 1 and 72"

        pattern_lower = pattern.lower().strip()
        if pattern_lower not in ALLOWED_ERROR_PATTERNS:
            return (
                f"Error: pattern must be one of: {', '.join(sorted(ALLOWED_ERROR_PATTERNS))}. "
                f"Got: '{pattern}'"
            )

        quoted_pattern = shlex.quote(pattern_lower)

        probes = await asyncio.gather(
            run_ssh_command(f'journalctl --since "{hours} hours ago" -p err --no-pager -n 30 2>/dev/null || echo ""'),
            run_ssh_command(f"dmesg --level=err,warn -T 2>/dev/null | tail -20 || echo ''"),
            run_ssh_command(
                f"docker ps -q 2>/dev/null | head -5 | while read cid; do "
                f"name=$(docker inspect --format '{{{{.Name}}}}' $cid 2>/dev/null | tr -d '/'); "
                f"docker logs --since {hours}h $cid 2>&1 | grep -i {quoted_pattern} | tail -3 | "
                f"while read line; do echo \"[$name] $line\"; done; done || echo ''"
            ),
            run_ssh_command(
                f"find /var/log -name '*.log' -mmin -{hours * 60} -readable 2>/dev/null | head -10 | "
                f"xargs -I{{}} sh -c 'grep -li {quoted_pattern} {{}} 2>/dev/null' | head -10 || echo ''"
            ),
            return_exceptions=True
        )

        def safe(idx):
            r = probes[idx]
            return r.strip() if isinstance(r, str) else ""

        journal_errors = safe(0)
        dmesg_errors = safe(1)
        docker_errors = safe(2)
        log_files = safe(3)

        total_matches = 0
        result = f"=== Error Pattern Scan (last {hours} hour(s), pattern: '{pattern_lower}') ===\n\n"

        result += "--- System Journal ---\n"
        if journal_errors:
            count = len([l for l in journal_errors.split('\n') if l.strip()])
            total_matches += count
            result += f"  ({count} entries)\n{journal_errors}\n\n"
        else:
            result += "  (no matches)\n\n"

        result += "--- Kernel (dmesg) ---\n"
        if dmesg_errors:
            count = len([l for l in dmesg_errors.split('\n') if l.strip()])
            total_matches += count
            result += f"  ({count} entries)\n{dmesg_errors}\n\n"
        else:
            result += "  (no matches)\n\n"

        result += "--- Docker Containers ---\n"
        if docker_errors:
            count = len([l for l in docker_errors.split('\n') if l.strip()])
            total_matches += count
            result += f"  ({count} entries)\n{docker_errors}\n\n"
        else:
            result += "  (no matches or Docker not available)\n\n"

        result += "--- Log Files with Matches ---\n"
        if log_files:
            for f in log_files.split('\n'):
                if f.strip():
                    result += f"  {f.strip()}\n"
        else:
            result += "  (no matching log files found)\n"

        result += f"\n--- Summary: {total_matches} match(es) found ---"

        return result

    except Exception as e:
        return f"Error searching error patterns: {str(e)}"


@mcp.tool()
async def check_docker_compose_services(project_dir: str = None) -> str:
    """
    Detect Docker Compose projects and show service status.

    Lists all running Compose projects, or checks a specific project directory.
    Many applications deploy via docker-compose.yml — this tool understands that structure.

    Args:
        project_dir: Optional path to directory with docker-compose.yml
                     (must start with /, alphanumeric and /_.- only, max 512 chars)
    """
    try:
        # Check Docker Compose is available
        compose_check = await run_ssh_command("docker compose version 2>/dev/null || docker-compose --version 2>/dev/null || echo NOT_INSTALLED")

        if "NOT_INSTALLED" in compose_check:
            return "Docker Compose is not installed on this server."

        if project_dir:
            if len(project_dir) > 512:
                return "Error: project_dir exceeds maximum length of 512 characters"
            path_regex = re.compile(r'^[a-zA-Z0-9/_.\-]+$')
            if not project_dir.startswith('/') or not path_regex.match(project_dir):
                return "Error: project_dir must start with / and contain only alphanumeric, /, _, ., - characters"

            quoted_dir = shlex.quote(project_dir)
            output = await run_ssh_command(
                f"docker compose -f {quoted_dir}/docker-compose.yml ps 2>/dev/null || "
                f"docker-compose -f {quoted_dir}/docker-compose.yml ps 2>/dev/null || "
                f"echo 'No docker-compose.yml found or Compose project not running at this path'"
            )

            return f"=== Docker Compose Services ({project_dir}) ===\n\n{output}"

        # List all Compose projects
        projects_output = await run_ssh_command("docker compose ls 2>/dev/null || echo ''")

        if not projects_output.strip():
            return "No running Docker Compose projects found (or Compose v2 not available for listing)."

        result = "=== Docker Compose Projects ===\n\n"
        result += f"{projects_output}\n"

        # Get detailed status for each project (first 5)
        lines = projects_output.strip().split('\n')
        if len(lines) > 1:
            for line in lines[1:6]:
                parts = line.split()
                if parts:
                    project_name = parts[0]
                    quoted_project = shlex.quote(project_name)
                    try:
                        ps_output = await run_ssh_command(f"docker compose -p {quoted_project} ps 2>/dev/null")
                        if ps_output.strip():
                            result += f"\n--- Project: {project_name} ---\n{ps_output}\n"
                    except Exception:
                        continue

        return result

    except Exception as e:
        return f"Error checking Docker Compose services: {str(e)}"


