# shellcheck shell=bash

configure_local_dns_entries() {
  msg "🧭 Local DNS helper has been removed. Manage host entries with your preferred tooling."
  return 0
}

run_host_dns_setup() {
  msg "🧭 Host DNS setup helper removed; --setup-host-dns no longer performs any action."
  msg "Configure resolver settings directly on your router or host as needed."
  return 0
}

notify_dns_dependents() {
  return 0
}
