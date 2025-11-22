# Frequently asked questions

[← Back to README](../README.md)

Quick answers to common beginner questions about the stack.

## Do I need a Raspberry Pi 5?
Any 64-bit Debian Bookworm host with roughly 4 CPU cores and 4 GB RAM works. Raspberry Pi 5 is a popular option but not required.

## Which Proton plan should I buy?
Use Proton VPN Plus or Unlimited. Those plans support port forwarding, which qBittorrent needs for good performance.

## Can I skip the DNS helper?
arrbash does not ship a DNS helper. Manage hostnames through your router or per-device configuration instead. See [Networking](networking.md) for current exposure guidance.

## How do I monitor Proton VPN port forwarding?
`vpn-port-guard` publishes Proton VPN status through `/gluetun_state/port-guard-status.json` and the `arr.pf.*` aliases. Use those surfaces inside hooks or automation so they do not fail on missing files.

## Where do I put my Proton credentials?
Copy `arrconf/proton.auth.example` to `arrconf/proton.auth` and fill in `PROTON_USER` and `PROTON_PASS`. The installer enforces safe permissions automatically.

## Which group should `PGID` use with the collaborative profile?
Set `PGID` to the group that owns your shared downloads or media storage (for example the `media` group). Without a matching group the installer keeps the stricter defaults to avoid exposing data to every root user.

## How do I update container versions?
Read [Version management](version-management.md). Adjust tags in `${ARRCONF_DIR}/userr.conf`, rerun the installer, and confirm containers start cleanly.

## Can I rerun the installer safely?
Yes. `./arr.sh` is idempotent—rerun it anytime after editing `${ARRCONF_DIR}/userr.conf`. Review the printed summary before containers restart.

## Can I expose services to the Internet?
Direct WAN exposure is not recommended. Keep qBittorrent behind Gluetun and access the *arr services via LAN IPs only. Review [Security](security.md) before attempting any port forwards.


## Related topics
- [Configuration](configuration.md)
- [Networking](networking.md)
- [Operations](operations.md)
- [Troubleshooting](troubleshooting.md)
