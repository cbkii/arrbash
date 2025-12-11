# API Endpoint Verification for .aliasarr

This document verifies that all API endpoints used in the standalone `.aliasarr` file are correct and up-to-date according to official documentation.

**Last Verified**: December 11, 2024

---

## 1. Radarr v3 API

**Official Documentation**: https://radarr.video/docs/api/  
**Current LinuxServer.io Image**: Uses Radarr v4/v5 (maintains v3 API compatibility)

### Endpoints Used

| Endpoint | Purpose | Status |
|----------|---------|--------|
| `/api/v3/system/status` | System status | ✅ Valid |
| `/api/v3/health` | Health check | ✅ Valid |
| `/api/v3/diskspace` | Disk space info | ✅ Valid |
| `/api/v3/movie` | List/get movies | ✅ Valid |
| `/api/v3/queue` | Download queue | ✅ Valid |
| `/api/v3/qualityprofile` | Quality profiles | ✅ Valid |

**Authentication**: X-API-Key header  
**Result**: 6/6 endpoints correct

---

## 2. Sonarr v3 API

**Official Documentation**: https://sonarr.tv/docs/api/  
**Current LinuxServer.io Image**: Uses Sonarr v4 (maintains v3 API compatibility)

### Endpoints Used

| Endpoint | Purpose | Status |
|----------|---------|--------|
| `/api/v3/system/status` | System status | ✅ Valid |
| `/api/v3/health` | Health check | ✅ Valid |
| `/api/v3/diskspace` | Disk space info | ✅ Valid |
| `/api/v3/series` | List/get series | ✅ Valid |
| `/api/v3/queue` | Download queue | ✅ Valid |
| `/api/v3/qualityprofile` | Quality profiles | ✅ Valid |

**Authentication**: X-API-Key header  
**Result**: 6/6 endpoints correct

---

## 3. Lidarr v1 API

**Official Documentation**: https://lidarr.audio/docs/api/  
**Current LinuxServer.io Image**: Uses Lidarr v1.x

### Endpoints Used

| Endpoint | Purpose | Status |
|----------|---------|--------|
| `/api/v1/system/status` | System status | ✅ Valid |
| `/api/v1/health` | Health check | ✅ Valid |

**Authentication**: X-API-Key header  
**Result**: 2/2 endpoints correct

---

## 4. Prowlarr v1 API

**Official Documentation**: https://prowlarr.com/docs/api/  
**Current LinuxServer.io Image**: Uses Prowlarr v1.x

### Endpoints Used

| Endpoint | Purpose | Status |
|----------|---------|--------|
| `/api/v1/system/status` | System status | ✅ Valid |
| `/api/v1/health` | Health check | ✅ Valid |
| `/api/v1/indexer` | Indexer list | ✅ Valid |

**Authentication**: X-API-Key header  
**Result**: 3/3 endpoints correct

---

## 5. Bazarr API

**Official Documentation**: https://wiki.bazarr.media/Additional-Configuration/API/  
**Current LinuxServer.io Image**: Uses Bazarr v1.x

### Endpoints Used

| Endpoint | Purpose | Status |
|----------|---------|--------|
| `/api/system/status?apikey=xxx` | System status | ✅ Valid |

**Authentication**: apikey query parameter  
**Result**: 1/1 endpoints correct

**Note**: Bazarr uses an unversioned API with the API key passed as a query parameter, not in headers.

---

## 6. qBittorrent Web API v2

**Official Documentation**: https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1)  
**Current LinuxServer.io Image**: Uses qBittorrent v4.5+

### Endpoints Used

| Endpoint | Purpose | Status |
|----------|---------|--------|
| `/api/v2/auth/login` | Authentication | ✅ Valid |
| `/api/v2/app/version` | App version | ✅ Valid |
| `/api/v2/app/preferences` | Get preferences | ✅ Valid |
| `/api/v2/app/setPreferences` | Set preferences | ✅ Valid |
| `/api/v2/transfer/info` | Transfer info | ✅ Valid |
| `/api/v2/torrents/info` | List torrents | ✅ Valid |
| `/api/v2/torrents/pause` | Pause torrents | ✅ Valid |
| `/api/v2/torrents/resume` | Resume torrents | ✅ Valid |

**Authentication**: Cookie-based (SID)  
**Result**: 8/8 endpoints correct

---

## 7. SABnzbd API

**Official Documentation**: https://sabnzbd.org/wiki/advanced/api  
**Current LinuxServer.io Image**: Uses SABnzbd v3.x/v4.x

### API Modes Used

| Mode | Purpose | Status |
|------|---------|--------|
| `server_stats` | Server statistics | ✅ Valid |
| `version` | Version info | ✅ Valid |
| `queue` | Queue info | ✅ Valid |
| `history` | History info | ✅ Valid |
| `pause` | Pause downloads | ✅ Valid |
| `resume` | Resume downloads | ✅ Valid |

**API Format**: `/api?mode=<mode>&apikey=<key>&output=json`  
**Authentication**: apikey query parameter  
**Result**: 6/6 modes correct

---

## 8. Gluetun Control API

**Official Documentation**: https://github.com/qdm12/gluetun-wiki/blob/main/setup/advanced/control-server.md  
**Current Image**: Uses Gluetun latest (control server enabled)

### Endpoints Used

| Endpoint | Purpose | Status |
|----------|---------|--------|
| `/v1/openvpn/status` | OpenVPN status | ✅ Valid |
| `/v1/wireguard/status` | WireGuard status | ✅ Valid |
| `/v1/publicip/ip` | Public IP | ✅ Valid |
| `/v1/openvpn/portforwarded` | Port forwarding (OpenVPN) | ✅ Valid |
| `/v1/wireguard/portforwarded` | Port forwarding (WireGuard) | ✅ Valid |
| `/v1/openvpn/actions/restart` | Restart tunnel (PUT) | ✅ Valid |

**Authentication**: X-API-Key header  
**Result**: 6/6 endpoints correct

---

## Overall Summary

✅ **ALL API ENDPOINTS ARE CORRECT AND VALID**

| Service | Endpoints | Status |
|---------|-----------|--------|
| Radarr v3 | 6/6 | ✅ All correct |
| Sonarr v3 | 6/6 | ✅ All correct |
| Lidarr v1 | 2/2 | ✅ All correct |
| Prowlarr v1 | 3/3 | ✅ All correct |
| Bazarr | 1/1 | ✅ All correct |
| qBittorrent v2 | 8/8 | ✅ All correct |
| SABnzbd | 6/6 | ✅ All correct |
| Gluetun | 6/6 | ✅ All correct |
| **TOTAL** | **38/38** | **✅ 100% correct** |

---

## Implementation Notes

### API Versioning Standards

All *arr services follow Servarr API standards:
- **Radarr/Sonarr**: Use v3 API (backward compatible with v4+ releases)
- **Lidarr/Prowlarr**: Use v1 API
- **Bazarr**: Uses unversioned API

### Quality Profile Endpoint

The endpoint `/api/v3/qualityprofile` (singular form) is correct for both Radarr and Sonarr v3 API. This is the standard Servarr endpoint name.

### Authentication Methods

Different services use different authentication approaches:

1. **X-API-Key Header** (Radarr, Sonarr, Lidarr, Prowlarr, Gluetun)
   ```bash
   curl -H "X-API-Key: <key>" <url>/api/v3/...
   ```

2. **Query Parameter** (Bazarr, SABnzbd)
   ```bash
   curl <url>/api/...?apikey=<key>
   ```

3. **Cookie-based** (qBittorrent)
   ```bash
   curl -c cookie.txt -b cookie.txt -d "username=x&password=y" <url>/api/v2/auth/login
   curl -b cookie.txt <url>/api/v2/...
   ```

### UrlBase Support

The implementation correctly prepends UrlBase (when present in `config.xml`) to all *arr service API calls:

```bash
# If config.xml has <UrlBase>/radarr</UrlBase>
# API calls become: http://host:port/radarr/api/v3/...
```

---

## Maintenance

This document should be reviewed and updated when:
- New API versions are released by any service
- LinuxServer.io updates container images with breaking API changes
- New endpoints are added to `.aliasarr`

**Next Review Date**: June 2025
