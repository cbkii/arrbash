# API Reliability and Error Handling

## Overview

This document describes the retry logic, session recovery, error handling, and diagnostics features implemented to improve reliability and observability of the arrbash stack.

## Automatic Retry Logic

### Gluetun API

The Gluetun API now includes automatic retry logic with configurable delays:

**Configuration Variables:**
- `GLUETUN_API_RETRY_COUNT` - Number of retry attempts (default: 3)
- `GLUETUN_API_RETRY_DELAY` - Delay between retries in seconds (default: 2)
- `GLUETUN_API_TIMEOUT` - Request timeout in seconds (default: 8)

**Example:**
```bash
export GLUETUN_API_RETRY_COUNT=5
export GLUETUN_API_RETRY_DELAY=3
./arr.sh
```

**Behavior:**
- API requests automatically retry on failure
- Each retry attempt is logged with `[RETRY]` prefix
- After all attempts fail, logs `[ERROR]` with actionable guidance
- Exponential backoff can be implemented by adjusting delay values

### qBittorrent API

Similar retry logic is implemented for qBittorrent API with session recovery:

**Configuration Variables:**
- `QBT_API_RETRY_COUNT` - Number of retry attempts (default: 3)
- `QBT_API_RETRY_DELAY` - Delay between retries in seconds (default: 2)
- `QBT_API_TIMEOUT` - Request timeout in seconds (default: 10)

**Session Recovery:**
- Automatically detects expired sessions (401/403 errors)
- Re-authenticates transparently without user intervention
- Retries the original request after successful re-authentication

**Example:**
```bash
export QBT_API_RETRY_COUNT=5
export QBT_API_RETRY_DELAY=3
./arr.sh
```

## Error Handling with Severity Levels

### Severity Prefixes

All error messages now use standardized severity prefixes:

| Prefix | Severity | Color | Usage |
|--------|----------|-------|-------|
| `[INFO]` | Informational | Blue | General information, no action required |
| `[WARN]` | Warning | Yellow | Potential issues, system continues |
| `[ERROR]` | Error | Red | Serious issues, may cause failure |
| `[FATAL]` | Fatal | Red Bold | Unrecoverable errors, will exit |
| `[RETRY]` | Retry | Cyan | Temporary failures, retrying |
| `[ACTION]` | Action | Cyan | Actionable guidance for users |

### Helper Functions

Use these functions in your scripts:

```bash
# Source the common library
. scripts/stack-common.sh

# Use severity-prefixed logging
arr_info "Service initialized successfully"
arr_warn "Port forwarding is disabled"
arr_error "Failed to connect to API"
arr_fatal "Critical configuration missing"
arr_retry "API request failed, retrying..."
arr_action "Check logs at /var/log/arr.log"
```

### Actionable Guidance

Error messages now include specific guidance:

**Before:**
```
[ERROR] qBittorrent authentication failed after 3 attempts
```

**After:**
```
[ERROR] qBittorrent authentication failed after 3 attempts
[ACTION] → Check QBT_USER and QBT_PASS credentials, and verify qBittorrent container is running
```

## Startup Diagnostics

### Usage

Run diagnostics before starting the stack:

```bash
./scripts/stack-diagnostics.sh
```

**Options:**
- `--skip-api` - Skip API connectivity checks
- `--skip-docker` - Skip Docker daemon and container checks
- `--help` - Show help message

### What It Checks

1. **System Dependencies:**
   - bash, docker, curl, jq, openssl, git
   - Docker Compose (plugin or standalone)

2. **Configuration Variables:**
   - Port numbers (valid range, format)
   - Directory paths (existence, accessibility)
   - Critical variables (STACK, LAN_IP)

3. **Docker Environment:**
   - Docker daemon status
   - Container existence and health
   - Running container count

4. **API Connectivity:**
   - Gluetun API accessibility
   - qBittorrent API accessibility

### Example Output

```
Checking system dependencies...
✓ Command available: Bash shell
✓ Command available: Docker
✓ Command available: curl (HTTP client)
...

Checking configuration variables...
✓ Valid port: GLUETUN_CONTROL_PORT=8000
✓ Valid port: QBT_PORT=8082
⚠ Port not set: SONARR_INT_PORT
...

==========================================
Diagnostics Summary
==========================================
✓ Passed:   15
⚠ Warnings: 3
✗ Failed:   0
==========================================
```

## Health Check Script

### Usage

Monitor stack health:

```bash
./scripts/stack-healthcheck.sh
```

**Options:**
- `--format FORMAT` - Output format (text or json)
- `--containers-only` - Only check container status
- `--vpn-only` - Only check VPN connectivity
- `--api-only` - Only check API endpoints
- `--help` - Show help message

### JSON Output

Use JSON format for monitoring integrations:

```bash
./scripts/stack-healthcheck.sh --format json
```

**Example Output:**
```json
{
  "timestamp": "2024-11-21T23:23:10Z",
  "status": "healthy",
  "checks_total": 8,
  "checks_passed": 7,
  "checks_failed": 1,
  "details": [
    {
      "service": "arr-gluetun",
      "status": "pass",
      "message": "Container running and healthy"
    },
    {
      "service": "gluetun-vpn",
      "status": "pass",
      "message": "VPN tunnel status: running"
    },
    ...
  ]
}
```

### Integration with Monitoring

**Prometheus/Grafana:**
```bash
# Export metrics
./scripts/stack-healthcheck.sh --format json | \
  jq -r '.status' > /var/lib/node_exporter/textfile/arr_health.prom
```

**Docker Health Check:**
```yaml
healthcheck:
  test: ["CMD", "/scripts/stack-healthcheck.sh", "--api-only"]
  interval: 30s
  timeout: 10s
  retries: 3
```

## Input Validation

### Port Validation

```bash
# Source validation library
. scripts/stack-validation.sh

# Validate port
if arr_validate_port "8080" "MY_PORT"; then
  echo "Port is valid"
fi
```

**Validates:**
- Empty values
- Non-numeric values
- Out of range (< 1 or > 65535)
- Warns about privileged ports (< 1024)

### JSON Validation

```bash
# Validate JSON content
json='{"key": "value"}'
if arr_validate_json "$json" "configuration"; then
  echo "JSON is valid"
fi
```

### IP Address Validation

```bash
# Validate IP address (IPv4 and IPv6)
if arr_validate_ip "192.168.1.100" "LAN_IP"; then
  echo "IP is valid"
fi
```

### Other Validators

- `arr_validate_url` - URL format (http:// or https://)
- `arr_validate_directory` - Directory paths and existence
- `arr_validate_boolean` - Boolean values (0, 1, true, false, yes, no, on, off)
- `arr_validate_positive_integer` - Positive integers with optional min/max

## Graceful Shutdown

### Signal Handling

All scripts now handle signals gracefully:

**Handled Signals:**
- `INT` (Ctrl+C)
- `TERM` (docker stop, systemd)
- `HUP` (terminal closed)
- `QUIT` (Ctrl+\)

**Behavior:**
1. Catch signal
2. Log shutdown message
3. Clean up resources:
   - Temporary files
   - API sessions (qBittorrent cookies)
   - Lock files
4. Exit with appropriate code

### Example

```bash
# When you press Ctrl+C:
[INFO] Received INT signal, performing graceful shutdown...
[INFO] Cleaning up temporary resources...
# Script exits cleanly
```

## Configuration Consolidation

### Configuration Precedence

Clear precedence order is now enforced:

1. **CLI flags** (highest priority)
2. **Exported environment variables**
3. **userr.conf file**
4. **Default values** (lowest priority)

### Configuration Validation

```bash
# Source configuration consolidation
. scripts/stack-config-consolidate.sh

# Load and validate all configuration
if arr_load_and_validate_config; then
  echo "Configuration is valid"
else
  echo "Configuration has errors"
  exit 1
fi
```

### Configuration Summary

```bash
# Print configuration summary
arr_print_config_summary
```

**Output:**
```
=== Configuration Summary ===
Precedence: CLI flags > environment > userr.conf > defaults

Network Configuration:
  LAN_IP: 192.168.1.100
  SPLIT_VPN: 0

Gluetun Configuration:
  GLUETUN_CONTROL_URL: http://127.0.0.1:8000
  GLUETUN_CONTROL_PORT: 8000
  GLUETUN_API_RETRY_COUNT: 3
  GLUETUN_API_RETRY_DELAY: 2
...
```

## Best Practices

### 1. Run Diagnostics First

Always run diagnostics before deploying or troubleshooting:

```bash
./scripts/stack-diagnostics.sh
# Review output, fix any errors
./arr.sh --yes
```

### 2. Monitor Health Regularly

Set up periodic health checks:

```bash
# In crontab
*/5 * * * * /path/to/arrbash/scripts/stack-healthcheck.sh --format json > /var/log/arr-health.json
```

### 3. Configure Retry Appropriately

Adjust retry settings based on your network:

- **Fast local network:** Lower retry count, shorter delays
- **Slow/unreliable network:** Higher retry count, longer delays
- **Production:** 5+ retries with 3-5 second delays

### 4. Use Validation in Scripts

Always validate user input:

```bash
#!/usr/bin/env bash
. scripts/stack-validation.sh

port="$1"
if ! arr_validate_port "$port" "PORT"; then
  exit 1
fi
# Continue with validated port
```

### 5. Handle Errors Appropriately

Use the right severity level:

```bash
# Informational
arr_info "Starting service..."

# Warning - system continues
arr_warn "Using default configuration"

# Error - serious but may recover
arr_error "Failed to connect, retrying..."

# Fatal - unrecoverable
arr_fatal "Critical file missing"
exit 1
```

## Troubleshooting

### Retry Logic Not Working

1. Check retry configuration:
```bash
echo "GLUETUN_API_RETRY_COUNT: ${GLUETUN_API_RETRY_COUNT:-not set}"
echo "QBT_API_RETRY_COUNT: ${QBT_API_RETRY_COUNT:-not set}"
```

2. Enable trace logging:
```bash
ARR_TRACE=1 ./arr.sh
```

### Session Recovery Failing

Check authentication credentials:
```bash
echo "QBT_USER: ${QBT_USER:-not set}"
# Don't echo password in production!
```

### Health Check Always Failing

Run with verbose output:
```bash
bash -x ./scripts/stack-healthcheck.sh
```

### Diagnostics Show Warnings

Review each warning and fix configuration:
```bash
./scripts/stack-diagnostics.sh 2>&1 | grep "⚠"
```

## Future Enhancements

Planned improvements:

1. **Metrics Export** - Prometheus-compatible metrics endpoint
2. **Alert Integration** - Webhook notifications for failures
3. **Circuit Breaker** - Stop retries after repeated failures
4. **Adaptive Delays** - Exponential backoff for retries
5. **Health Check Dashboard** - Web UI for health status
6. **Configuration Templates** - Pre-configured profiles for common setups
