[← Back to README](../README.md)

# Glossary

Key terms referenced throughout the documentation.

| Term | Meaning |
| --- | --- |
| **DNS (Domain Name System)** | Service that maps a hostname (e.g. `qbittorrent.home.arpa`) to an IP address. |
| **DHCP (Dynamic Host Configuration Protocol)** | Router service that hands out IP addresses and DNS servers to clients. |
| **LAN (Local Area Network)** | Your home network (`192.168.x.x`, `10.x.x.x`, or `172.16-31.x.x`). |
| **LAN domain suffix** | Optional ending for hostnames (default `home.arpa`) that never resolves on the public Internet. |
| **CA (Certificate Authority)** | Trusted signer that lets browsers accept HTTPS certificates. Bring your own proxy if you need LAN HTTPS. |
| **Root certificate** | Public file you import so devices trust a custom CA. |
| **Gluetun** | VPN container that routes traffic through Proton VPN and exposes a control API. |
| **Docker compose** | Tool that launches the services defined in the generated `docker-compose.yml`. |
| **Port forwarding** | Proton VPN feature that assigns a TCP port so peers can reach qBittorrent through the VPN tunnel. |
| **Private DNS / DoT** | Android feature for DNS-over-TLS. Leave it Off/Automatic so lookups stay inside your LAN. |

If a term is unfamiliar, follow links in the other docs or search the Debian manual pages (for example, `man resolv.conf`).

## Related topics
- [Networking](networking.md)
- [Operations](operations.md)
- [FAQ](faq.md)
