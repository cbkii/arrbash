# Changelog

## Unreleased

- Non-functional refactor: split legacy helpers into grouped modules (`compose-*`, `service-*`, `vpn-auto-*`) to improve maintainability without altering behaviour.
- Remove transitional shim scripts now that callers source the grouped modules directly.
