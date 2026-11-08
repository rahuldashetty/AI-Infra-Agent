# CLAUDE.md — InfraAgent MCP

## Project Status: WORKING

This codebase is fully functional and deployed. All changes must be **additive only**.
Do NOT refactor, rewrite, or change any existing working logic. Do NOT remove or rename
existing functions, parameters, constants, or tool definitions. New features are added
alongside existing code — never by replacing it.

## What This Project Is

**InfraAgent** is an AI-powered MCP (Model Context Protocol) server that acts as a
**junior DevOps engineer** for autonomous server troubleshooting. It SSHes into any remote
server, auto-detects the runtime environment (Docker, Kubernetes, systemd, PM2, Supervisor),
identifies the full application stack, and performs intelligent diagnostics to pinpoint issues.

Its **workflow tools** run full diagnostic decision trees — investigating issues the way a
DevOps engineer would (check process → logs → ports → resources → dependencies) and return
structured diagnostic reports with severity-ranked findings and recommended next steps.

All logic lives in a single file: `server.py` (PEP 723 inline metadata, no pyproject.toml).

## Architecture

- **Single file**: `server.py` — all tools, helpers, and constants
- **Runtime**: Python 3.10+, run via `uv run server.py`
- **Transport**: stdio (MCP protocol over stdin/stdout)
- **Remote access**: SSH (asyncssh) with key-based auth
- **Database**: Remote MariaDB via `mysql` CLI over SSH (database tools)
- **Config**: `.env` file for SSH/DB credentials (never committed)

## Key Design Decisions

- **Read-only by default**: All new tools are read-only. SQL queries are validated to block
  mutating SQL. The only mutating tool is `restart_service`.
- **Input sanitization**: `_sanitize_identifier()` validates user-provided names.
  `ALLOWED_ERROR_PATTERNS` is an allowlist for log search patterns.
- **Shell safety**: All values interpolated into shell commands use `shlex.quote()`.
- **Graceful degradation**: Detection tools handle "tool not found" gracefully (e.g.,
  "Docker is not installed" instead of an exception).
- **Parallel probing**: Workflow and detection tools use
  `asyncio.gather(return_exceptions=True)` for concurrent SSH probes (5-15 parallel checks).
- **Structured diagnostics**: Workflow tools return reports with OK/WARNING/CRITICAL findings.

## Tool Categories (43 tools total)

| Category                          | Tools | Notes                                           |
|-----------------------------------|-------|-------------------------------------------------|
| Database & Service Management     | 4     | SQL queries, service status/restart             |
| System Health Monitoring          | 3     | memory, load, top processes                     |
| Docker Monitoring                 | 3     | logs, stats, container health                   |
| Disk & I/O Monitoring             | 3     | disk IO, inodes, usage by path                  |
| Network Monitoring                | 3     | interfaces, connections, open ports             |
| Services & Logs                   | 3     | failed services, journal, dmesg                 |
| DNS & Security                    | 2     | DNS resolution, recent logins                   |
| Runtime & Platform Detection      | 5     | Docker, Kubernetes, systemd, PM2, Supervisor    |
| Application Stack & Diagnostics   | 5     | stack detection, find app, logs, health, errors |
| Smart Troubleshooting             | 5     | health scan, ports, SSL, error patterns, Compose|
| Junior DevOps Workflows           | 6     | HTTP errors, crashes, resources, connectivity   |

## Environment Variables (.env)

```
SSH_HOST, SSH_USER, SSH_KEY_PATH
DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME
```

## Rules for Changes

1. **Additive only** — never delete or alter working tool functions, helper functions,
   constants, or validation logic.
2. New tools go at the bottom of their category section (or in a new section).
3. New tools should be read-only unless there is a strong reason to mutate.
4. Mark any new mutating tool clearly in its docstring.
5. All user-supplied values must be validated (`_sanitize_identifier` or equivalent)
   and shell-quoted (`shlex.quote`) before use.
6. SQL queries must pass through `_validate_sql_readonly` or be hardcoded read-only.
7. For log search patterns, use `ALLOWED_ERROR_PATTERNS` allowlist — no free-form grep.
8. Detection tools must handle "not installed" gracefully — return a clear message, never crash.
9. Test new tools manually with `uv run server.py` before considering them done.
