# Gluetun/ProtonVPN/qBittorrent Improvements

This document summarizes the battle-tested improvements made to arrbash's Gluetun, ProtonVPN, and qBittorrent port forwarding implementation.

## Overview

The arrbash codebase already followed solid patterns for VPN and torrent client integration. These improvements enhance reliability, add validation, and align with official Gluetun best practices.

## Key Improvements

### 1. Enhanced Gluetun API Library (`scripts/gluetun-api.sh`)

**Exponential Backoff:**
- Implemented exponential backoff for failed API requests: 2s → 4s → 8s
- Reduces load during transient failures
- Prevents thundering herd when Gluetun is restarting

**Health Check Endpoint:**
- Added `gluetun_api_healthcheck()` using Gluetun's official `/healthcheck` endpoint
- Returns 0 (healthy), 1 (unhealthy), or 2 (unreachable)
- Enables proper health detection before attempting other operations

**Public IP Function:**
- Added `gluetun_api_public_ip()` for diagnostics
- Queries `/v1/publicip/ip` endpoint
- Useful for verifying VPN connection is active

**Port Validation:**
- Enhanced `gluetun_api_forwarded_port()` to validate port range (1024-65535)
- Prevents invalid ports from being applied to qBittorrent
- ProtonVPN typically assigns ports in the 40000-60000 range

**Improved Timeout:**
- Increased default timeout from 8s to 10s
- Accounts for Gluetun's initialization time after container start

### 2. Improved qBittorrent API Library (`scripts/qbt-api.sh`)

**Port Range Validation:**
- Added validation in `qbt_set_listen_port()` to ensure port is 1024-65535
- Prevents configuration errors from invalid port numbers

**Port Update Verification:**
- Added optional verification after setting listen port
- Reads back the port from qBittorrent to confirm it was accepted
- Detects silent failures where the API returns success but port wasn't changed

**Better Error Messages:**
- Enhanced error reporting when port updates fail
- Includes actual vs expected port numbers for debugging

### 3. Enhanced Port Guard Controller (`scripts/vpn-port-guard.sh`)

**Verified Port Updates:**
- Now uses `qbt_set_listen_port()` with verification enabled
- Confirms qBittorrent actually accepted the new port
- Better logging for successful port changes

**Improved Logging:**
- Added informational messages when ports change successfully
- Helps users confirm the system is working

### 4. Simplified Port Guard Hook (`scripts/vpn-port-guard-hook.sh`)

**Clarified Purpose:**
- Enhanced documentation that hook is audit-only
- Controller polls API independently
- Hook provides event trail for troubleshooting

**UTC Timestamps:**
- Uses ISO 8601 UTC format for consistency
- Easier correlation with Gluetun logs

**Clear Separation of Concerns:**
- Hook logs events
- Controller handles all qBittorrent updates

### 5. Documentation Enhancements (`docs/vpn-port-guard.md`, `docs/networking.md`)

**Architecture Explanation:**
- Documented why API polling is preferred over hook-based updates
- Explained resilience benefits of polling approach

**Reliability Features:**
- Documented port validation (1024-65535)
- Explained verification process
- Described exponential backoff behavior

**WireGuard Support Path:**
- Added notes about ProtonVPN WireGuard+NAT-PMP support
- Documented current OpenVPN focus
- Outlined path for future WireGuard integration

### 6. Code Comments (`scripts/stack-compose-runtime.sh`)

**Gluetun Configuration:**
- Added comments explaining port forwarding defaults
- Documented control API security requirements
- Clarified relationship between Gluetun and vpn-port-guard

## Battle-Tested Patterns

These improvements follow proven patterns from the Gluetun ecosystem:

### API Polling vs Hooks

**Why polling wins for reliability:**
1. **Resilience:** Continues working even if hook events are missed
2. **Recovery:** Can detect and fix drift from any cause
3. **Verification:** Can confirm changes were applied
4. **Simplicity:** Single control flow, easier to debug

**Hook role:**
- Audit trail for troubleshooting
- Quick notification of Gluetun events
- Does NOT trigger controller actions

### Exponential Backoff

**Pattern:**
```
Attempt 1: Wait 2s
Attempt 2: Wait 4s
Attempt 3: Wait 8s (capped)
```

**Benefits:**
- Reduces load when services are unavailable
- Allows time for services to stabilize
- Prevents resource exhaustion

### Port Validation

**Range check (1024-65535):**
- System ports (0-1023) are reserved
- ProtonVPN typically uses high ports (40000-60000)
- Prevents misconfigurations

**Verification:**
- Read back port after setting
- Confirm qBittorrent accepted the change
- Detect silent failures

## Backwards Compatibility

All improvements maintain full backwards compatibility:

- Existing configurations continue to work unchanged
- Default behavior preserved
- New features are opt-in (verification is enabled by default but non-breaking)
- No changes to environment variables or user-facing interfaces

## Testing Recommendations

### Unit Testing

1. **API Retry Logic:**
   ```bash
   # Simulate Gluetun down
   docker stop gluetun
   # Observe exponential backoff in vpn-port-guard logs
   docker logs -f vpn-port-guard
   # Start Gluetun
   docker start gluetun
   # Verify recovery
   ```

2. **Port Validation:**
   ```bash
   # Test invalid port (should fail gracefully)
   # Manually set FORWARDED_PORT_FILE to invalid value
   # Verify controller rejects it
   ```

3. **Verification:**
   ```bash
   # Verify port updates succeed
   docker logs vpn-port-guard | grep "Successfully updated"
   # Check qBittorrent has correct port
   curl -u admin:admin http://localhost:8082/api/v2/app/preferences | jq .listen_port
   ```

### Integration Testing

1. **Full Port Forwarding Flow:**
   - Enable `VPN_PORT_FORWARDING=on`
   - Configure hook commands
   - Monitor port changes
   - Verify qBittorrent updates

2. **Health Check:**
   ```bash
   # Test healthcheck endpoint
   curl -H "X-API-Key: ${GLUETUN_API_KEY}" \
     http://localhost:8000/healthcheck
   ```

3. **Public IP Verification:**
   ```bash
   # Verify VPN is working
   source .aliasarr
   arr.vpn.ip  # Should show VPN exit IP
   ```

## Future Enhancements

### WireGuard Support

ProtonVPN now offers WireGuard configs with NAT-PMP support. Potential additions:

1. **Auto-detection:** Detect WireGuard configs with NAT-PMP capability
2. **WireGuard API:** Add support for WireGuard-specific Gluetun endpoints
3. **Hybrid mode:** Support both OpenVPN and WireGuard simultaneously

### Enhanced Monitoring

1. **Metrics:** Expose Prometheus metrics for port forwarding status
2. **Alerts:** Notify when port forwarding fails for extended periods
3. **History:** Track port change frequency and patterns

### Advanced Features

1. **Port persistence:** Remember and request specific ports
2. **Port rotation:** Periodically rotate forwarded ports for privacy
3. **Multi-client:** Support multiple torrent clients behind same VPN

## References

- [Gluetun Wiki](https://github.com/qdm12/gluetun/wiki)
- [ProtonVPN Port Forwarding](https://protonvpn.com/support/port-forwarding/)
- [qBittorrent Web API](https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1))
- [Exponential Backoff](https://en.wikipedia.org/wiki/Exponential_backoff)

## Conclusion

These improvements enhance the already-solid arrbash implementation with:
- Better reliability through retry logic
- Validation to prevent misconfigurations  
- Verification to catch silent failures
- Clear documentation of design decisions

The changes follow battle-tested patterns from the Gluetun ecosystem while maintaining full backwards compatibility.
