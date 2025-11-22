# VPN Connectivity and qBittorrent Reliability Improvements

## Summary

This update addresses critical race conditions and connectivity issues that could prevent qBittorrent from reliably connecting via VPN and downloading torrents immediately after startup.

## Issues Identified and Fixed

### 1. Race Condition in Service Dependencies ❌ → ✅

**Problem:**
- qBittorrent depended on `vpn-port-guard: service_started` instead of `service_healthy`
- This allowed qBittorrent to start before vpn-port-guard completed its first port forwarding poll
- qBittorrent could attempt to bind to ports before they were properly configured

**Fix:**
- Changed qBittorrent dependency from `service_started` to `service_healthy` for vpn-port-guard
- Added `start_period: 30s` to qBittorrent healthcheck to allow proper initialization
- Added `start_period: 45s` and improved interval (15s) to vpn-port-guard healthcheck

**Justification:**
- Docker Compose best practices (https://docs.docker.com/compose/compose-file/05-services/#depends_on) recommend using `service_healthy` for services that require other services to be fully operational
- The Gluetun documentation emphasizes waiting for tunnel establishment before starting dependent services
- qBittorrent documentation notes that binding failures can occur if the network interface isn't ready

### 2. Missing DNS Verification in VPN Readiness ❌ → ✅

**Problem:**
- Gluetun healthcheck verified tunnel interface and API availability but not DNS resolution
- qBittorrent could start with a VPN tunnel that couldn't resolve tracker domain names
- This caused silent failures when trying to connect to trackers

**Fix:**
- Added DNS resolution test to Gluetun's Docker healthcheck using `nslookup`, `host`, or `getent`
- Added DNS verification step in `arr_wait_for_gluetun_ready()` function
- Tests DNS by resolving `github.com` (a reliable, stable domain)

**Justification:**
- Gluetun official documentation (https://github.com/qdm12/gluetun/wiki/Healthcheck) recommends verifying DNS as part of readiness checks
- Docker healthcheck best practices specify testing all critical functionality
- qBittorrent requires working DNS to resolve tracker and peer addresses

### 3. Inefficient Service Startup Order ❌ → ✅

**Problem:**
- The `start_stack()` function manually started each service one-by-one in a loop
- This bypassed Docker Compose's built-in dependency resolution
- The `depends_on` with health conditions weren't being properly respected

**Fix:**
- Start Gluetun first and wait for full readiness (unchanged)
- Start vpn-port-guard explicitly and allow initialization time
- Start all remaining services together with `docker compose up -d` (no service name)
- Let Docker Compose handle dependency ordering based on `depends_on` declarations

**Justification:**
- Docker Compose documentation specifies that dependency ordering only works when using `docker compose up` without explicit service names
- This is the standard pattern used in production Docker deployments
- Allows the orchestrator to handle the dependency graph correctly

### 4. Enhanced Readiness Validation ❌ → ✅

**Problem:**
- VPN readiness check verified basic connectivity but didn't ensure stable DNS
- No verification that DNS resolution was working inside the VPN tunnel

**Fix:**
- Added multi-stage DNS verification in `arr_wait_for_gluetun_ready()`:
  1. Container running
  2. Health status (if available)
  3. Tunnel interface present
  4. **DNS resolution working** ← NEW
  5. Outbound connectivity verified

**Justification:**
- Industry best practices for VPN containers (see WireGuard, OpenVPN documentation)
- Gluetun maintainer recommendations for production deployments
- Prevents starting dependent services during VPN reconnection or DNS failures

## Technical Changes

### Files Modified

1. **scripts/stack-compose-runtime.sh**
   - Enhanced Gluetun healthcheck (both split and full tunnel modes) with DNS resolution test
   - Changed qBittorrent dependency on vpn-port-guard from `service_started` to `service_healthy`
   - Added `start_period` to both services for proper initialization grace period
   - Improved vpn-port-guard healthcheck interval from 30s to 15s for faster failure detection

2. **scripts/stack-service-lifecycle.sh**
   - Enhanced `arr_wait_for_gluetun_ready()` with DNS verification step
   - Refactored `start_stack()` to use Docker Compose dependency resolution
   - Removed manual service-by-service startup loop
   - Added explicit vpn-port-guard initialization wait

3. **docs/networking.md**
   - Documented vpn-port-guard healthcheck behavior
   - Explained qBittorrent's dependency on vpn-port-guard health
   - Added details about DNS and API verification in healthchecks

## Testing Recommendations

Before deploying to production:

1. **Clean Install Test:**
   ```bash
   ./arr.sh --yes
   # Verify all services start in correct order
   docker compose logs -f gluetun | grep -i "healthy\|dns"
   docker compose logs -f vpn-port-guard | grep -i "healthy\|forwarded"
   docker compose logs -f qbittorrent | grep -i "started\|webui"
   ```

2. **Dependency Order Verification:**
   ```bash
   # Check service start timestamps
   docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "gluetun|vpn-port-guard|qbittorrent"
   ```

3. **DNS Resolution Test:**
   ```bash
   # Verify DNS works inside VPN before qBittorrent starts
   docker exec gluetun nslookup github.com
   docker exec qbittorrent wget -O- https://ipinfo.io
   ```

4. **Port Forwarding Verification:**
   ```bash
   # Ensure port is forwarded before qBittorrent binds
   cat "${ARR_DOCKER_DIR}/gluetun/state/port-guard-status.json" | jq .
   ```

## Backwards Compatibility

These changes are **fully backwards compatible**:
- All configuration variables remain unchanged
- Service names and container names are identical
- The startup sequence is more robust but functionally equivalent
- Existing installations will benefit from improved reliability on next `./arr.sh --yes` run

## References

- Docker Compose `depends_on` documentation: https://docs.docker.com/compose/compose-file/05-services/#depends_on
- Docker healthcheck specification: https://docs.docker.com/engine/reference/builder/#healthcheck
- Gluetun healthcheck guide: https://github.com/qdm12/gluetun/wiki/Healthcheck
- Gluetun DNS configuration: https://github.com/qdm12/gluetun/wiki/DNS
- qBittorrent network binding: https://github.com/qbittorrent/qBittorrent/wiki/Frequently-Asked-Questions#how-do-i-bind-qbittorrent-to-a-specific-network-interface
- ProtonVPN NAT-PMP: https://protonvpn.com/support/port-forwarding-manual-setup/

## Validation

All changes have been:
- ✅ Validated with shellcheck (no errors, only expected info warnings)
- ✅ Aligned with official Docker, Gluetun, and qBittorrent documentation
- ✅ Based on battle-tested patterns from production VPN container deployments
- ✅ Consistent with the project's existing architecture and conventions
