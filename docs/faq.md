[← Back to README](../README.md)

# Frequently asked questions

Quick answers to common beginner questions about arrbash.

## Do I need a Raspberry Pi 5?
Any 64-bit Debian Bookworm host with roughly 4 CPU cores and 4 GB RAM works. Raspberry Pi 5 is a popular option but not required.

## Which Proton plan should I buy?
Use Proton VPN Plus or Unlimited. Those plans support port forwarding, which qBittorrent needs for good performance.

## Can I skip the DNS helper?
Yes, but you must add host entries manually or set DNS per device. Following [Networking](networking.md) keeps the experience consistent.

## Where do I put my Proton credentials?
Copy `arrconf/proton.auth.example` to `arrconf/proton.auth` and fill in `PROTON_USER` and `PROTON_PASS`. The installer enforces safe permissions automatically.

## Which group should `PGID` use with the collaborative profile?
Set `PGID` to the group that owns your shared downloads or media storage (for example the `media` group). Without a matching group the installer keeps the stricter defaults to avoid exposing data to every root user.

## How do I update container versions?
Read [Version management](version-management.md). Adjust tags in `${ARR_BASE}/userr.conf`, rerun the installer, and confirm containers start cleanly.

## Can I rerun the installer safely?
Yes. `./arrstack.sh` is idempotent—rerun it anytime after editing `${ARR_BASE}/userr.conf`. Review the printed summary before containers restart.

## Can I expose services to the Internet?
Use Caddy with strong basic auth if you need remote access. Avoid forwarding raw service ports; keep the stack behind Proton VPN whenever possible. Review [Security](security.md) first.

## Is `home.arpa` required?
It is the recommended LAN suffix because it never leaks to the public Internet. Change it only if another system already uses it.

## Related topics
- [Configuration](configuration.md)
- [Networking](networking.md)
- [Operations](operations.md)
- [Troubleshooting](troubleshooting.md)
