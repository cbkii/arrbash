[← Back to README](../README.md)

# Glossary

Key terms referenced throughout the documentation.

| Term | Meaning |
| --- | --- |
| **DNS (Domain Name System)** | Service that maps a hostname (e.g. `qbittorrent.home.arpa`) to an IP address. |
| **DHCP (Dynamic Host Configuration Protocol)** | Router service that hands out IP addresses and DNS servers to clients. |
| **LAN (Local Area Network)** | Your home network (`192.168.x.x`, `10.x.x.x`, or `172.16-31.x.x`). |
| **LAN domain suffix** | Optional ending for hostnames (default `home.arpa`) that never resolves on the public Internet. |
| **CA (Certificate Authority)** | Trusted signer that lets browsers accept HTTPS certificates. Caddy runs its own CA for LAN sites. |
| **Root certificate** | Public file (`root.crt`) you import so devices trust the local CA. |
| **Gluetun** | VPN container that routes traffic through Proton VPN and exposes a control API. |
| **Caddy** | Reverse proxy that terminates HTTPS on ports 80/443 and enforces basic auth. |
| **dnsmasq** | Lightweight DNS server used by the optional `local_dns` container. |
| **Docker compose** | Tool that launches the services defined in the generated `docker-compose.yml`. |
| **Port forwarding** | Proton VPN feature that assigns a TCP port so peers can reach qBittorrent through the VPN tunnel. |
| **Private DNS / DoT** | Android feature for DNS-over-TLS. Leave it Off/Automatic so lookups stay inside your LAN. |

If a term is unfamiliar, follow links in the other docs or run `man <term>` on Debian (for example, `man resolv.conf`).

## See also
- [Networking](networking.md)
- [Operations](operations.md)
- [FAQ](faq.md)
