# AGENTS.md

## Purpose / Role of Agent

You are an AI coding agent for the `cbkii/arrbash` project. Your responsibilities include:

- Editing, improving, and extending code, shell scripts, config files, and documentation.
- Ensuring consistency between docs, examples, and code behavior.
- Providing diffs or patches when making changes.
- Suggesting PR messages, structural improvements, and diagnostics.
- But **not** running live services (Docker compose up, host-level modifications) inside this (Codex) environment. Those tasks are for a host machine.

---

## Repository Overview

- Entry script: `arr.sh` — orchestrates setup on Debian hosts, handles flags like `--yes`, `--rotate-caddy-auth`, `--setup-host-dns`, etc.
- Config directory: `arrconf/` — user and defaults config; **this is the canonical source of config variables**.
- Scripts directory: `scripts/` — helper scripts (DNS, versions, networking, qbt helpers, etc.); **compose writers and emission helpers live here**.
- Docs: `README.md`, `docs/` (guides, troubleshooting, operations).

> **Consolidate, don’t duplicate**: update and centralise existing code paths. If a helper overlaps with an existing function, **merge** them and deprecate the old one in-place. Avoid “wrapper-of-a-wrapper” patterns; keep a single authoritative implementation per concern. This applies equally when adding *“new files”*—only create them if no suitable entry point exists, then remove/replace overlapping logic.

---

## Coding Style & Conventions

- Use **Bash** with strict safety: `#!/usr/bin/env bash`, `set -Eeuo pipefail`.
- Scripts must check dependencies (`curl`, `jq`, `openssl`, etc.) and fail with clear messages.
- Permissions: secrets/auth files default to `600`; never commit real credentials.
- Standalone helpers bootstrap with:
  - `SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"`,
  - derive `REPO_ROOT`,
  - source `scripts/common.sh`,
  - call `arr_escalate_privileges "$@"` before enabling strict mode when root access is required.
- Reuse shared helpers in `scripts/common.sh` — **do not** reimplement `msg`, `warn`, `die`, or permission logic.
- Consistent indenting and quoting; always quote variables in paths.
- Example/template files (`*.example`) reflect defaults or placeholders only.


### Robust Variable Escaping & Emission (Docker/Compose-safe)

**Intent:** The guidance in this section uses **illustrative examples**. **Do not hardcode function or variable names** from examples; instead, locate the current helpers in `scripts/` (e.g., YAML/ENV emitters) and extend them.

- **Source of truth for variables:** parse from `arrconf/userr.conf.defaults.sh` and `arrconf/userr.conf` (and any `scripts/defaults.sh`-style files if present).
- **Where to hook in:** the compose writer(s) and file generators in `scripts/` (e.g., files that render `docker-compose.yml`, `.env`, hook scripts).

#### Emission rules (format-specific)
- **docker-compose YAML**
  - Emit scalars as **double-quoted** YAML strings; escape `\` → `\\`, `"` → `\"`, newlines → `\n`.
  - Avoid unquoted values when they contain YAML-sensitive tokens (`: # , * ? { } [ ]`, leading `~/on/off/yes/no`, spaces).
  - Use list-form for commands/healthchecks to avoid shell re-parsing.
  - Generate YAML with **single-quoted heredocs** (`<<'YAML'`) so Bash does not expand `${…}`; let Compose resolve at runtime.

- **`.env` (Compose dotenv)**
  - Format: `NAME=VALUE` (no `export`), one per line.
  - **Always double-quote** values; escape `\` and `"`; collapse newlines to spaces.
  - Names must match `^[A-Za-z_][A-Za-z0-9_]*$`.

- **Shell scripts / s6 hooks**
  - Use `printf '%q'` for paths/args when constructing commands.
  - Normalise CRLF (`dos2unix`/`sed -i 's/\r$//'`).
  - Include `set -euo pipefail`.

> **Example helpers (illustrative only):**
> - YAML scalar escaper (Bash) that returns a double-quoted string.
> - Dotenv kv writer that validates names and quotes values.
> Extend/merge with the **existing** repo helpers rather than introducing parallel ones.

#### Double-expansion guard (pattern-based)
- After writing YAML, fail if unresolved placeholders remain that are **not** intended for Compose substitution.
- **Pattern:** allow only known runtime placeholders discovered from the config surface. Build this allow-list dynamically by scanning `arrconf/*.sh` for var names.
  - Generic allow-regex example (adjust based on discovery):  
    `\${(LAN_IP|LOCALHOST_IP|[A-Z][A-Z0-9_]+_PORT|[A-Z][A-Z0-9_]*_DIR)}`

---

## Path & Directory Variables — Single Source of Truth

**Intent:** This section defines the **policy**. Any explicit path examples are **illustrative**. Do **not** assume exact variable names are stable; instead:

- **Discover variables** from:
  - `arrconf/userr.conf.defaults.sh` (defaults),
  - `arrconf/userr.conf` (user overrides),
  - and any `scripts/*defaults*.sh` files referenced by the installer.
- **Identify canonical path variables** by regex and precedence, e.g.:
  - **Top-level roots:** `^(ARR_)?(DATA_ROOT|STACK_DIR|DOCKER_DIR|CONF(DIR)?|LOG_DIR)$`
  - **Service roots:** `^[A-Z0-9_]+_DIR$`
  - **Media/downloads:** `^(DOWNLOADS_DIR|COMPLETED_DIR|MEDIA_DIR|TV_DIR|MOVIES_DIR|SUBS_DIR)$`
- **Replacement principle:** where a literal path equals a composition of known variables, replace the literal with the **most granular** variable available.

### Hardcoded-path detector (regex strategy)
- Treat strings matching these **literal patterns** as suspicious (illustrative list; extend per repo state):
  - `\b/home/[^/\s]+/Downloads(?:/completed)?\b`
  - `\b/media/[^/\s]+/(Shows|Movies|subs)\b`
  - `\b(?:docker-data|dockarr)\b` when used as a directory segment
  - `\b\.env\b` when paired with a hardcoded stack dir
- For each match, attempt to map to a variable by checking compositions discovered from the config graph. Prefer the **most specific** variable (e.g., `${COMPLETED_DIR}` over `${DOWNLOADS_DIR}/completed`).

### Emission policy
- Generators must compose volumes, hooks, healthchecks and log paths from **discovered** canonical variables, not literals.
- If an existing emitter already builds these paths, **extend it**; do **not** add new parallel emitters.

---

## Workflow & Task Guidance

1. **Understand scope**: read relevant scripts/config/docs; inspect current helpers and writers.
2. **Make changes locally**: produce diffs/patches.
3. **Run static checks**:
   - `shellcheck` on all `.sh`.
   - Lint example/template files for placeholders and var names.
4. **Docs sync**: when features/flags/services change, update README and relevant docs. Prefer editing existing content over adding new pages.
5. **Help output**: ensure `./arr.sh --help` reflects current state.

---

## Testing & Validation Commands

Within Codex (no live stack):

- `shellcheck` over all shell scripts.
- Any version/YAML/env consistency checks provided by repo.
- `./arr.sh --help` must succeed without side effects.
- Optional: detectors that flag hardcoded path fragments and unexpected/unresolved placeholders in generated files.
- `docker compose config` (syntax-only) on generated compose files if available locally.

---

## What Agent MAY Do vs MAY NOT Do (in this environment)

| May Do | May NOT Do / Should Avoid |
|---|---|
| Modify code, scripts, config, docs. | Launch the full stack via Docker Compose. |
| Generate patches, suggestions, tests. | Make host OS changes (DNS, services). |
| Update example/template permissions. | Use secrets/private credentials. |
| Validate static correctness, pins, env alignment. | Assume unrestricted network or host privileges. |
| **Consolidate duplicates into one authoritative function/module** and refactor callers to use it (improves maintainability and consistency). | **Add parallel or near-identical functions/files** (copy-paste variants, forks of the same logic). |
| **Extend existing functions/modules** when scope grows slightly (add flags/params, small cohesive changes). | **Create new files/functions for minor, related behaviour**; only add new entry points if none exist—if you must, migrate callers and remove the old path. |

---

## Pull Request / Commit Guidelines

- Commit messages: `<type>(<area>): short description` (e.g., `feat(installer): add PORT_SYNC_IMAGE override`).
- PR body:
  1. Summary of change.
  2. Impact / user-visible differences.
  3. Actions required by host-user (copy example, set env var, run helper).
  4. Static check results (shellcheck/help-output/version script).
- Include “Testing Done” describing validations performed within Codex limits.

---

## Security & Secrets Handling

- Never commit real credentials. Use `.example` placeholders.
- Local secrets (e.g., `arrconf/proton.auth`) are not committed.
- Secrets default to mode `600`.
- If features touch control APIs (e.g., Gluetun), enforce API key handling and localhost binding per docs.

---

## Agent’s Priorities

1. **Correctness** — behaviour matches docs; consistent across repo.
2. **Clarity** — clear errors, help text, README, examples.
3. **Safety** — no secret leaks; no destructive ops without flags.
4. **Maintainability** — small, scoped changes; avoid duplication.
5. **Minimal assumptions** — operate within Codex constraints.

---

## Scope of this AGENTS.md

- Applies to all files in this repository unless overridden by a deeper `AGENTS.md`.
- For tasks touching documentation, examples, code, config, scripts — follow this guide.
- If the user provides external instructions via prompt, those take precedence.
