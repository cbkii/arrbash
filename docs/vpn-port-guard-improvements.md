# vpn-port-guard Improvements Summary

This document summarizes the reliability and usability improvements made to the `vpn-port-guard` controller.

## Overview

The vpn-port-guard controller manages the lifecycle of port forwarding between Gluetun (VPN) and qBittorrent. These improvements focus on making the controller more reliable, easier to debug, and more resilient to transient failures.

## Key Improvements

### 1. API Reliability & Retry Logic

**Problem**: Temporary network issues or API unavailability caused immediate failures without recovery attempts.

**Solution**:
- Added configurable retry logic for both Gluetun and qBittorrent APIs (default: 3 retries)
- Configurable retry delays (default: 2 seconds between attempts)
- Automatic re-authentication for qBittorrent when sessions expire
- All API operations now gracefully handle transient failures

**Configuration**:
```bash
GLUETUN_API_RETRY_COUNT=3      # Number of retry attempts for Gluetun
GLUETUN_API_RETRY_DELAY=2      # Seconds between Gluetun retries
QBT_API_RETRY_COUNT=3          # Number of retry attempts for qBittorrent
QBT_API_RETRY_DELAY=2          # Seconds between qBittorrent retries
```

### 2. Configuration Simplification

**Problem**: Multiple overlapping environment variables caused confusion about which one takes precedence.

**Solution**:
- Consolidated configuration with clear precedence: `CONTROLLER_REQUIRE_PF` is now canonical
- Legacy variables still supported for backward compatibility
- Added validation for all configuration values (e.g., poll interval minimum 5s)

**Precedence Order**:
1. `CONTROLLER_REQUIRE_PF` (recommended)
2. `CONTROLLER_REQUIRE_PORT_FORWARDING` (legacy)
3. `VPN_PORT_GUARD_REQUIRE_FORWARDING` (legacy)

### 3. Startup Diagnostics

**Problem**: Issues with missing dependencies or API connectivity weren't discovered until runtime failures.

**Solution**:
- Added comprehensive startup diagnostics that validate:
  - Required commands (curl, jq)
  - Configuration values (poll interval, port ranges)
  - Gluetun API connectivity (non-fatal, logged for awareness)
  - qBittorrent API connectivity (non-fatal, logged for awareness)
- Clear log output shows what's working and what needs attention

### 4. Enhanced Logging

**Problem**: Log messages didn't clearly indicate severity or provide actionable guidance.

**Solution**:
- Added severity prefixes: ✓ (success), ⚠ (warning), ERROR (critical)
- Contextual information in all error messages
- Consecutive failure tracking with escalating alerts
- Actionable guidance in error messages (e.g., "Check qBittorrent Web UI accessibility")

**Example**:
```
[vpn-port-guard] ERROR: Failed to set qBittorrent listen port to 12345
[vpn-port-guard]   → Check qBittorrent Web UI accessibility and credentials
```

### 5. Graceful Shutdown

**Problem**: Container restarts left torrents running or status files incomplete.

**Solution**:
- Proper signal handling for INT, TERM, and EXIT
- Cleanup sequence:
  1. Pause qBittorrent torrents
  2. Update status file to reflect shutdown
  3. Clean up temporary files (API cookies)
- Ensures clean state for container orchestration

### 6. Health Check Script

**Problem**: No automated way to verify controller health for monitoring systems.

**Solution**:
- New health check script: `scripts/vpn-port-guard-healthcheck.sh`
- Validates:
  - Status file exists and is readable
  - Status file contains valid JSON
  - Status updates within 60 seconds (4x poll interval)
- Returns standard exit codes (0=healthy, 1=unhealthy)
- Can be used with Docker, Kubernetes, or monitoring tools

**Docker Compose Example**:
```yaml
vpn-port-guard:
  healthcheck:
    test: ["/bin/bash", "/scripts/vpn-port-guard-healthcheck.sh"]
    interval: 30s
    timeout: 10s
    retries: 3
    start_period: 30s
```

### 7. Improved Input Validation

**Problem**: Invalid inputs could cause unexpected behavior or cryptic errors.

**Solution**:
- Port range validation (1024-65535)
- JSON validation before file writes
- Configuration value validation at startup
- Clear error messages for validation failures

### 8. Better Race Condition Handling

**Problem**: Trigger file operations had potential race conditions.

**Solution**:
- Improved trigger file handling with proper error checking
- Clarified that races are benign for trigger signaling
- Better directory creation with error handling
- Atomic status file writes using temp files + mv

## Performance Considerations

All improvements maintain or improve performance:
- Retry logic adds latency only on failures (normal case is unaffected)
- JSON validation uses here-string (<<<) instead of pipes for efficiency
- No new background processes or polling added
- Startup diagnostics run once, not on every loop

## Backward Compatibility

All changes maintain full backward compatibility:
- Legacy environment variables still work
- Existing behavior unchanged when defaults are used
- New features are opt-in via configuration
- No breaking changes to status file format

## Testing & Validation

All changes have been:
- ✅ Validated with shellcheck (no warnings or errors)
- ✅ Reviewed for code quality and best practices
- ✅ Documented with examples and troubleshooting guidance
- ✅ Designed for minimal change scope (surgical improvements)

## Future Enhancements

Potential areas for future improvement:
- Metrics endpoint for Prometheus/Grafana integration
- Configurable health check thresholds
- Support for multiple qBittorrent instances
- Integration tests with mock APIs

## References

- [vpn-port-guard documentation](./vpn-port-guard.md)
- [Troubleshooting guide](./vpn-port-guard.md#troubleshooting)
- [Configuration reference](./vpn-port-guard.md#configuration)
