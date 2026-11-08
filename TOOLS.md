# InfraAgent — MCP Tools Reference

All 53 tools available in InfraAgent. The server acts as an AI junior DevOps engineer, performing intelligent diagnostics over SSH with auto-detection of runtime platforms.

**Tool Summary:**
- **52 read-only tools** — safe for monitoring, detection, and analysis
- **1 mutating tool** — modifies server state (clearly marked with ⚠️)

## Table of Contents

1. [Junior DevOps Workflows](#junior-devops-workflows) (6 tools) — Smart diagnostic chains
2. [Runtime & Platform Detection](#runtime--platform-detection) (5 tools)
3. [Application Stack & Diagnostics](#application-stack--diagnostics) (5 tools)
4. [Smart Troubleshooting](#smart-troubleshooting) (5 tools)
5. [Database & Service Management](#database--service-management) (14 tools)
6. [System Health Monitoring](#system-health-monitoring) (3 tools)
7. [Docker Monitoring](#docker-monitoring) (3 tools)
8. [Disk & I/O Monitoring](#disk--io-monitoring) (4 tools)
9. [Network Monitoring](#network-monitoring) (3 tools)
10. [Services & Logs](#services--logs) (3 tools)
11. [DNS & Security](#dns--security) (2 tools)

---

## Junior DevOps Workflows

Smart diagnostic chains that run 5–15 checks in one call and return structured diagnostic reports with OK/WARNING/CRITICAL findings and recommended next steps.

### diagnose_http_error

Full investigation for HTTP 4xx/5xx errors — checks app status, logs, ports, database, resources, and OOM events.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `app_name` | string | *required* | Name of the application to investigate |
| `port` | integer | `80` | Port the application should be listening on |
| `error_code` | integer | `500` | HTTP error code being investigated (400–599) |

**Example prompts:**
- "I'm getting 500 errors on my API — diagnose it"
- "Why is my-app returning 502 on port 8080?"
- "Investigate HTTP 503 errors for nginx"

---

### diagnose_container_crash

Diagnose why a Docker container keeps crashing or exiting. Analyzes exit codes (137=OOM, 139=segfault, 143=SIGTERM, 1=app error), OOMKilled status, memory limits, host resources, and recent logs.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `container_name` | string | *required* | Name of the Docker container to investigate |

**Example prompts:**
- "My container keeps crashing — why?"
- "Diagnose why the api-server container is dying"
- "Container my-app restarted 10 times — investigate"

---

### diagnose_high_resource_usage

Identify CPU, memory, or disk bottlenecks. Checks load averages, memory/swap, disk usage, top consumers, I/O wait, and kernel errors.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `resource` | string | `"auto"` | Resource to investigate: `auto`, `cpu`, `memory`, `disk`, or `all` |

**Example prompts:**
- "The server feels slow — what's the bottleneck?"
- "Check why memory is so high"
- "Run a full resource diagnostic"

---

### diagnose_service_down

Diagnose why a service is down or not responding. Searches across Docker, systemd, Kubernetes, and PM2. Checks process status, logs, port binding, dependencies, and resources.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `service_name` | string | *required* | Name of the service to investigate |
| `port` | integer | `None` | Optional port the service should be listening on |

**Example prompts:**
- "My API isn't responding on port 3000 — investigate"
- "Why is my-app down?"
- "Service backend is unreachable — diagnose"

---

### diagnose_deployment_issue

Diagnose issues after a deployment — app won't start, crashes on startup, port conflicts, missing env vars, permission errors, migration failures.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `app_name` | string | *required* | Name of the application |
| `platform` | string | `"auto"` | Platform to check: `auto`, `docker`, `systemd`, `kubernetes`, or `pm2` |

**Example prompts:**
- "I just deployed and the app won't start — help"
- "My deploy failed on Docker — diagnose"
- "App crashes on startup after the latest release"

---

### diagnose_connectivity_issue

Layer-by-layer connectivity analysis: DNS resolution, port listening, TCP connectivity, HTTP response, SSL certificate, and firewall rules.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `host` | string | *required* | Hostname or IP to test connectivity to |
| `port` | integer | *required* | Port number to test |
| `protocol` | string | `"tcp"` | Protocol to test: `tcp`, `http`, or `https` |

**Example prompts:**
- "I can't reach my service from outside — check connectivity to api.example.com:443"
- "Is port 8080 reachable on my server?"
- "Diagnose HTTPS connectivity to my-domain.com"

---

## Runtime & Platform Detection

### detect_runtime_environment

Master detection — probes all platforms (Docker, Kubernetes, systemd, PM2, Supervisor) in parallel. Returns OS info, resource summary, and which platforms are available.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "What runtime platforms are on this server?"
- "Connect to my server and tell me what's running"
- "Detect the full environment"

---

### detect_docker_environment

Deep Docker probe: version, daemon info, running/stopped containers, Compose projects, Swarm status.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "Give me a full Docker breakdown"
- "What Docker containers are running?"
- "Is Docker Swarm active?"

---

### detect_kubernetes_environment

Kubernetes cluster detection: kubectl availability, cluster info, namespaces, pods, services, and deployments.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "Is Kubernetes running on this server?"
- "Show me all K8s pods and services"
- "Get Kubernetes cluster info"

---

### detect_systemd_services

List systemd services filtered by state.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `state_filter` | string | `"all"` | Filter by state: `active`, `failed`, `inactive`, or `all` |

**Example prompts:**
- "Show all failed systemd services"
- "List active services"
- "What systemd services are configured?"

---

### detect_process_managers

Detect PM2, Supervisor, and forever process managers and their managed processes.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "Is PM2 running any processes?"
- "Check for process managers"
- "Are there any Supervisor-managed services?"

---

## Application Stack & Diagnostics

### detect_application_stack

Auto-detect the full application stack: web servers, databases, caches, message queues, and language runtimes via process list and port scan.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "What's the full application stack on this server?"
- "Detect all running services and databases"
- "What web servers and databases are installed?"

---

### find_application

Find an application across all platforms — Docker, systemd, Kubernetes, PM2, and raw processes.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `name` | string | *required* | Application name to search for |

**Example prompts:**
- "Find where my-app is running"
- "Is nginx running as a container or a systemd service?"
- "Locate the backend service across all platforms"

---

### get_application_logs

Get application logs regardless of platform (auto-detects or uses explicit platform).

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `name` | string | *required* | Application name |
| `platform` | string | `"auto"` | Platform: `auto`, `docker`, `systemd`, `kubernetes`, or `pm2` |
| `lines` | integer | `100` | Number of log lines to retrieve (1–1000) |

**Example prompts:**
- "Show me the last 200 lines of my-app logs"
- "Get Docker logs for the api container"
- "What are the recent logs for the backend service?"

---

### check_application_health

Health check: running status, resource usage, port binding, and recent errors for an application.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `name` | string | *required* | Application name |

**Example prompts:**
- "Is my-app healthy?"
- "Check the health of the api service"
- "How is nginx doing?"

---

### find_application_errors

Search for errors in an application's logs across platforms.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `name` | string | *required* | Application name |
| `hours` | integer | `24` | Hours to look back (1–168) |
| `platform` | string | `"auto"` | Platform: `auto`, `docker`, `systemd`, `kubernetes`, or `pm2` |

**Example prompts:**
- "Find errors in my-app logs from the last 6 hours"
- "Are there any exceptions in the backend service?"
- "Show me recent fatal errors for the api container"

---

## Smart Troubleshooting

### full_system_health_scan

One-shot health scan covering disk, memory, CPU, services, containers, and kernel errors. Flags each as OK, WARNING, or CRITICAL.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "Run a full system health scan"
- "Is this server healthy?"
- "Give me a quick health check"

---

### check_port_connectivity

Check if a port is listening, which process owns it, and test TCP + HTTP connectivity.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `port` | integer | *required* | Port number to check (1–65535) |
| `host` | string | `"localhost"` | Host to check |

**Example prompts:**
- "Is anything listening on port 8080?"
- "Check port 443 connectivity"
- "Who owns port 3000?"

---

### check_ssl_certificate

Check SSL certificate validity, expiry date, issuer, and days remaining.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `host` | string | *required* | Hostname to check |
| `port` | integer | `443` | Port for SSL connection |

**Example prompts:**
- "Check the SSL certificate for example.com"
- "Is my cert about to expire?"
- "Verify SSL on mail.example.com:465"

---

### find_error_patterns

Search all log sources (journal, dmesg, Docker, /var/log) for error patterns.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `hours` | integer | `1` | Hours to look back (1–168) |
| `pattern` | string | `"error"` | Error pattern from allowlist: error, exception, fatal, panic, critical, warning, oom, timeout, refused, denied, traceback, segfault, killed, fail |

**Example prompts:**
- "Find all errors from the last hour"
- "Search for OOM events in the last 24 hours"
- "Are there any fatal errors in the logs?"

---

### check_docker_compose_services

Detect Docker Compose projects and show service status for each.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `project_dir` | string | `None` | Optional directory containing docker-compose.yml |

**Example prompts:**
- "Show me which Docker Compose projects are running"
- "Check the status of Compose services in /opt/app"
- "List all Compose projects on this server"

---

## Database & Service Management

### run_sql_query

Run a read-only SQL query against the remote database.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `query` | string | *required* | SQL query (SELECT, SHOW, DESCRIBE, DESC, EXPLAIN only) |

**Example prompts:**
- "Run SELECT COUNT(*) FROM users"
- "Show me the database tables"
- "Describe the orders table"

---

### check_service_status

Check the status of a systemd service and its recent logs.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `service_name` | string | *required* | Name of the systemd service (e.g., "nginx", "my-app") |

**Example prompts:**
- "Check the status of the nginx service"
- "Is my-app running as a systemd service?"
- "Show me the logs for the backend service"

---

### restart_service

Restart a systemd service and verify it's running.

**Badge:** ⚠️ **Mutating** — modifies server state

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `service_name` | string | *required* | Name of the systemd service to restart |

**Example prompts:**
- "Restart the nginx service"
- "Restart my-app and check if it comes back up"

---


### check_app_containers

Check health status of Docker containers, optionally filtered by name.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `name_filter` | string | `""` | Optional container name filter (empty shows all) |

**Example prompts:**
- "Check health of all Docker containers"
- "Show container health for 'my-app'"
- "Are there any unhealthy containers?"

---

## System Health Monitoring

### check_memory_usage

Check memory and swap usage on the remote server.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "How much memory is being used?"
- "Check RAM and swap usage"

---

### check_system_load

Check CPU load averages and uptime.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "What's the CPU load?"
- "How long has the server been up?"

---

### check_top_processes

Show the top resource-consuming processes.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "What's eating the most CPU and memory?"
- "Show me the top processes"

---

## Docker Monitoring

### check_docker_containers

List all Docker containers with status, ports, and image info.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "List all Docker containers"
- "What containers are running?"

---

### docker_container_logs

Get logs from a specific Docker container.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `container_name` | string | *required* | Name of the Docker container |
| `lines` | integer | `100` | Number of log lines (1–1000) |

**Example prompts:**
- "Show me the last 200 lines of my-app container logs"
- "Get Docker logs for nginx"

---

### docker_container_stats

Get real-time resource usage (CPU, memory, network, I/O) for all running containers.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "Show Docker container resource usage"
- "Which container is using the most memory?"

---

## Disk & I/O Monitoring

### check_disk_usage

Check disk usage across all mounted filesystems.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "How full are the disks?"
- "Check disk space"

---

### check_disk_io

Check disk I/O statistics: read/write throughput, IOPS, queue depth, and utilization.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "Show disk I/O stats"
- "Is there high disk I/O?"

---

### check_inode_usage

Check inode usage across filesystems.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "Check inode usage"
- "Are we running out of inodes?"

---

### check_disk_usage_by_path

Check disk usage for a specific path, showing the largest subdirectories.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `path` | string | `"/"` | Path to check |

**Example prompts:**
- "What's using space in /var/log?"
- "Show disk usage for /opt"

---

## Network Monitoring

### check_network_stats

Show network interface statistics: received/transmitted bytes, packets, errors, and drops.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "Show network interface stats"
- "Are there any network errors?"

---

### check_network_connections

Show active network connections grouped by state.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "Show active network connections"
- "How many connections are established?"

---

### check_open_ports

List all open/listening ports and the processes that own them.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "What ports are open?"
- "Which processes are listening on which ports?"

---

## Services & Logs

### check_failed_services

List all failed systemd services.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "Are there any failed services?"
- "Show me crashed systemd units"

---

### check_journal_logs

Get journal logs for a specific systemd unit.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `unit` | string | *required* | Service unit name (e.g., "nginx", "my-app") |
| `lines` | integer | `100` | Number of log lines (1–1000) |

**Example prompts:**
- "Show journal logs for nginx"
- "Get the last 500 lines of my-app logs"

---

### check_dmesg_errors

Check kernel ring buffer for errors and warnings.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "Are there any kernel errors?"
- "Check dmesg for issues"

---

## DNS & Security

### check_dns_resolution

Resolve a hostname from the remote server — shows A and MX records.

**Badge:** 🔍 Read-only

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `hostname` | string | *required* | Hostname to resolve |

**Example prompts:**
- "Resolve example.com from the server"
- "Check DNS for mail.example.com"

---

### check_recent_logins

Show recent login attempts and sessions.

**Badge:** 🔍 Read-only

**Parameters:** None

**Example prompts:**
- "Who logged in recently?"
- "Show recent SSH login attempts"

---
