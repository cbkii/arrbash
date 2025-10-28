# AGENTS.md

## Purpose / Role of Agent

You are an AI coding agent for the `cbkii/arrbash` project. Your responsibilities include:

* Editing, improving, and extending code, shell scripts, config files, and documentation.
* Ensuring consistency between docs, examples, and code behaviour.
* Providing diffs or patches when making changes.
* Suggesting PR messages, structural improvements, and diagnostics.
* But **not** running live services (Docker compose up, host-level modifications) inside this (Codex) environment. Those tasks are for a host machine.

---

## Repository Overview

* **Entry script:** `arr.sh` — orchestrates setup on Debian hosts, handles flags like `--yes`, `--rotate-api-key`, `--split`, etc.
* **Config directory:** `arrconf/` — user and defaults config; **this is the canonical source of config variables**.
* **Env generation (NEW):**

  * `scripts/gen-env.sh` — single, authoritative generator for `.env` using **Bash/Zsh logic + envsubst**.
  * `.env.template` — repository-tracked template with `${VAR}` placeholders and optional blocks guarded by `# @if VAR` … `# @endif`.
  * Runtime layering is `CLI flags > exported environment > ${ARRCONF_DIR}/userr.conf > arrconf/userr.conf.defaults.sh`. Mirror that order in all docs.
* **Scripts directory:** `scripts/` — helper scripts (DNS, versions, networking, qbt helpers, etc.).

  * **ENV EMISSION MOVED HERE** (via `gen-env.sh` only).
  * Compose YAML helpers remain (YAML emit/escape).
* **Docs:** `README.md`, `docs/` (guides, troubleshooting, operations).

> **Consolidate, don’t duplicate**: update and centralise existing code paths. If a helper overlaps with an existing function, **merge** them and remove the old one. Avoid “wrapper-of-a-wrapper” patterns; keep a single authoritative implementation per concern.

---

## Naming Conventions (arrbash-specific)

* **User config (canonical):** `arrconf/userr.conf.defaults.sh` → `${ARRCONF_DIR}/userr.conf` (**double r**).
* **Scripts / helpers:** file names kebab-case; shared helpers prefixed `arr_` when appropriate.
* **Variables:** uppercase `SNAKE_CASE` with service/area prefixes (`ARR_`, `GLUETUN_`, `QBT_`, `PROWLARR_`, etc.).
* **Compose/env artefacts:**

  * `.env.template` (**tracked; hand-edited**)
  * `.env` (**generated; do not hand-edit**) by `scripts/gen-env.sh`
* **Examples/placeholders:** `*.example` suffix only (never committed with real secrets).

---

## New Env Generation Workflow (authoritative)

1. **Inputs**

   * `arrconf/userr.conf.defaults.sh` (defaults)
   * `${ARRCONF_DIR}/userr.conf` (user overrides; optional)
   * `.env.template` (placeholders, optional `# @if VAR` guards)
   * CLI flags and exported environment variables layered ahead of `${ARRCONF_DIR}/userr.conf`

2. **Generator**

   * `scripts/gen-env.sh`:

    * Sources defaults then user overrides (arr.sh applies CLI/environment overrides before invoking the generator).
   * Applies **derived logic** (internal→external port fallbacks, ProtonVPN port-forward defaults, boolean normalisation).
     * Processes conditional blocks: keeps content between `# @if VAR` … `# @endif` only when `VAR` is “truthy” (`1/true/yes/on`, case-insensitive).
     * Runs `envsubst` **scoped** to placeholders actually used in the filtered template.
     * Writes to `${ARR_ENV_FILE}` (default `${ARR_STACK_DIR}/.env`) with mode `0600`.
     * Emits `KEY=value` with no wrapping quotes; Compose consumes the file literally.

3. **Outcomes**

   * No change to effective values seen by Compose or runtime.
   * Post-install scripts may still **surgically update** keys in `${ARR_ENV_FILE}` (e.g., image pinning, temporary passwords).

---

## What Was Removed / Must Not Be Reintroduced

* **Remove** legacy env emission and placeholder-tracking in `scripts/files.sh`:

  * `ARR_COMPOSE_VARS`, `ARR_COMPOSE_MISSING`, `ARR_COMPOSE_REQUIRED_BY`
  * `arr_compose_reset_tracking`, `arr_compose_set_context`
  * `arr_compose_inline_escape`, `arr_compose_stream_line`, `arr_compose_stream_block`
  * `arr_emit_compose_env_file`
* **Trim** `scripts/gen-yaml-emit.sh` to YAML-only helpers actually used elsewhere; it must **not** write `.env`.
* **Do not** add migration wrappers/shims around `gen-env.sh`.

---

## Coding Style & Conventions

* Use **Bash** with strict safety: `#!/usr/bin/env bash`, `set -Eeuo pipefail`. When authoring shell code, ensure constructs remain
  **zsh-compatible** (e.g., avoid Bash-only arrays where unnecessary, prefer POSIX-compatible parameter expansion, and test critical
  scripts with `zsh` when feasible) so contributors using Z shell can run the tooling seamlessly.
* Scripts must check dependencies (`curl`, `jq`, `openssl`, etc.) and fail with clear messages.
* Permissions: secrets/auth files default to `600`; never commit real credentials.
* Standalone helpers bootstrap with:

  * `SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"`,
  * derive `REPO_ROOT`,
  * source `scripts/stack-common.sh`,
  * call `arr_escalate_privileges "$@"` before enabling strict mode when root access is required.
* Reuse shared helpers in `scripts/stack-common.sh` — **do not** reimplement `msg`, `warn`, `die`, permission logic, or env quoting/escaping already available.
* Consistent indenting and quoting; always quote variables in paths.
* Example/template files (`*.example`) reflect defaults or placeholders only.

---

## Robust Variable Escaping & Emission

* **Authority for `.env`:** `scripts/gen-env.sh` (only).

  * Format: `NAME=VALUE` (no `export`), one per line.
  * Values are produced via `envsubst`; source variables must be set before substitution. Do not add quotes around values in `userr.conf`—Compose reads `.env` values literally, so quotes become part of the value. Spaces and `#` are allowed in values; just ensure there’s no trailing comment after the value in the template.
  * Optional blocks rely on `# @if VAR` guards so feature-scoped variables disappear entirely when falsey.
* **YAML emission:** keep YAML-escape logic (double-quoted scalars; escape `\` → `\\`, `"` → `\"`, newlines → `\n`). Prefer list-form commands/healthchecks.
  * Feature-gated sections (SABnzbd, Configarr, VPN helpers, etc.) must drop their services and dependent variables whenever the controlling flag is disabled.
* **Double-expansion guard:** after writing YAML, ensure unresolved placeholders are only those intended for Compose interpolation (allow-list common runtime names).

---

## Variables Surface (must be covered in `.env.template`)

Include placeholders for **all** user-settable variables found in `arrconf/userr.conf.example`, notably:

* **Core/paths & identity:** `STACK`, `ARR_STACK_DIR`, `ARRCONF_DIR`, `ARR_DATA_ROOT`, `PUID`, `PGID`, `TIMEZONE`
* **Media & downloads:** `MEDIA_DIR`, `TV_DIR`, `MOVIES_DIR`, `SUBS_DIR`, `DOWNLOADS_DIR`, `COMPLETED_DIR`
* **LAN & loopback:** `LAN_IP`, `LOCALHOST_IP`
* **VPN/Proton/Gluetun & controller tuning:** `SERVER_COUNTRIES`, `PVPN_ROTATE_COUNTRIES`, `GLUETUN_API_KEY`, `GLUETUN_CONTROL_PORT`, `VPN_PORT_GUARD_POLL_SECONDS`, `VPN_*`, `SPLIT_VPN`
* **Images:** `CONFIGARR_IMAGE`, `FLARR_IMAGE`, `GLUETUN_IMAGE`, `PROWLARR_IMAGE`, `QBITTORRENT_IMAGE`, `RADARR_IMAGE`, `SONARR_IMAGE`
* **Service ports:**

  * Internal: `QBT_INT_PORT`, `SONARR_INT_PORT`, `RADARR_INT_PORT`, `PROWLARR_INT_PORT`, `BAZARR_INT_PORT`, `FLARR_INT_PORT`
  * LAN exposed (guard with `# @if EXPOSE_DIRECT_PORTS`): `EXPOSE_DIRECT_PORTS`, `QBT_PORT`, `SONARR_PORT`, `RADARR_PORT`, `PROWLARR_PORT`, `BAZARR_PORT`, `FLARR_PORT`
* **qBittorrent:** `QBT_USER`, `QBT_PASS`, `QBT_BIND_ADDR`, `QBT_ENFORCE_WEBUI`, `QBT_AUTH_WHITELIST`
* **SABnzbd (guard with `# @if SABNZBD_ENABLED`):** `SABNZBD_ENABLED`, `SABNZBD_USE_VPN`, `SABNZBD_HOST`, `SABNZBD_INT_PORT`, `SABNZBD_PORT`, `SABNZBD_API_KEY`, `SABNZBD_CATEGORY`, `SABNZBD_TIMEOUT`
* **Scoring/tuning:** all `ARR_*` from the example file, incl.:
  `ARRBASH_USENET_CLIENT`, `ARR_COLOR_OUTPUT`, `ARR_DISCOURAGE_MULTI`, `ARR_ENGLISH_ONLY`, `ARR_ENGLISH_POSITIVE_SCORE`, `ARR_EP_MAX_GB`, `ARR_EP_MIN_MB`, `ARR_JUNK_NEGATIVE_SCORE`, `ARR_LANG_PRIMARY`, `ARR_MBMIN_DECIMALS`, `ARR_MULTI_NEGATIVE_SCORE`, `ARR_PENALIZE_HD_X265`, `ARR_PERMISSION_PROFILE`, `ARR_PORT_CHECK_MODE`, `ARR_SEASON_MAX_GB`, `ARR_STRICT_JUNK_BLOCK`, `ARR_TV_RUNTIME_MIN`, `ARR_VIDEO_MAX_RES`, `ARR_VIDEO_MIN_RES`, `ARR_X265_HD_NEGATIVE_SCORE`

> **Derived-only values** need **no** placeholder unless they are persisted into `.env`. If persisted today, add `${VAR}` and compute it in `gen-env.sh` to keep behaviour identical.

---

## Tasks You Will Commonly Perform

1. **Env system edits**

   * Update `.env.template` when adding/removing config surface.
   * Extend `scripts/gen-env.sh` for new derived logic or flags (add defaulting/normalisation; add/consume `# @if VAR` guards).
   * Ensure the generator is the **only** writer for `.env`.

2. **Remove duplication**

   * When you find env-emission logic elsewhere, migrate callers to the generator, delete the duplicate, and update docs.

3. **Compose/YAML**

   * Keep YAML emitters minimal and focused on YAML formatting & escaping.
   * Do **not** generate `.env` from YAML or vice-versa.

4. **Docs sync**

   * Keep README and docs aligned with the env workflow (how to set `userr.conf`, how to regenerate `.env`).

---

## Testing & Validation (within Codex)

* **Static:** `shellcheck` for all changed shell scripts.
* **Generator parity:**

  * Remove `.env`, run `scripts/gen-env.sh`, ensure a new `.env` appears with `0600`.
  * Toggle guards in `arrconf/userr.conf` and re-generate; verify guarded blocks appear/disappear as expected.
  * Confirm internal→external port fallbacks (e.g., empty `QBT_PORT` with `QBT_INT_PORT` set yields populated `QBT_PORT`).
* **Compose parity (syntax-level):** `docker compose config` against the working tree (if Compose is available in the environment you’re testing) — no unresolved placeholders beyond intended runtime envs.
* **Docs:** `./arr.sh --help` must reflect changes when flags/config surface shift.

**Quick commands (illustrative):**

```bash
rm -f "${ARR_STACK_DIR}/.env"
scripts/gen-env.sh .env.template "${ARR_STACK_DIR}/.env"
test -f "${ARR_STACK_DIR}/.env" && ls -l "${ARR_STACK_DIR}/.env"

# Derived fallback
sed -i 's/^QBT_PORT=.*/QBT_PORT=/' arrconf/userr.conf; scripts/gen-env.sh
grep -q '^QBT_PORT=' "${ARR_STACK_DIR}/.env"
```

---

## What Agent MAY Do vs MAY NOT Do (in this environment)

| May Do                                                                                  | May NOT Do / Should Avoid                                     |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Modify code, scripts, config, docs.                                                     | Launch the full stack via Docker Compose.                     |
| Generate patches, suggestions, tests.                                                   | Make host OS changes (DNS, services).                         |
| Update example/template permissions.                                                    | Use secrets/private credentials.                              |
| Validate static correctness, pins, env alignment.                                       | Assume unrestricted network or host privileges.               |
| **Consolidate duplicates into one authoritative function/module** and refactor callers. | **Add parallel or near-identical logic** to existing helpers. |

---

## Pull Request / Commit Guidelines

* Commit messages: `<type>(<area>): short description` (e.g., `feat(env): add ENABLE_FOO guard to template`).
* PR body:

  1. Summary of change.
  2. Impact / user-visible differences.
  3. Host actions (e.g., “re-run `scripts/gen-env.sh`”).
  4. Static check results (shellcheck; generator parity notes).
* Include a “Testing Done” block with the exact commands run.

---

## Security & Secrets

* Never commit real credentials. Use placeholders (`*.example`) only.
* Files containing secrets (including generated `.env`) default to mode `600`.
* If adding control APIs (e.g., Gluetun), keep API keys out of repo and ensure loopback bindings by default.

---

## Agent Priorities

1. **Correctness** — behaviour matches docs and remains stable.
2. **Clarity** — errors/help/docs are clear and concise.
3. **Safety** — no secret leaks; cautious file modes.
4. **Maintainability** — remove duplication; keep code small and cohesive.
5. **Minimal assumptions** — operate within Codex constraints.
