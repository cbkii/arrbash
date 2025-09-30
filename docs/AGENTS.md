# AGENTS.md

## Purpose / Role of Agent

You are an AI coding agent for the `cbkii/arrstackmini` project. Your responsibilities include:

- Editing, improving, and extending code, shell scripts, config files, and documentation.
- Ensuring consistency between docs, examples, and code behavior.
- Providing diffs or patches when making changes.
- Suggesting PR messages, structural improvements, and diagnostics.
- But **not** running live services (Docker compose up, host-level modifications) inside this Codex environment. Those tasks are for a host machine.

---

## Repository Overview

- Entry script: `arrstack.sh` — orchestrates setup on Debian hosts, handles flags like `--yes`, `--rotate-caddy-auth`, `--setup-host-dns`, etc.
- Config directory: `arrconf/` — contains `proton.auth.example`, `userr.conf.example`, and the defaults used to render it.
- Scripts directory: `scripts/` — contains helper scripts like DNS-setup/rollback, version-fixing, others.
- Example env file: `.env.example`
- Docs: `README.md`, `docs/TROUBLESHOOTING.md`, etc.

---

## Coding Style & Conventions

- Use **Bash** scripts with strict safety: `#!/usr/bin/env bash`, `set -Eeuo pipefail`.
- Shell scripts should check for missing dependencies (e.g. `curl`, `jq`, `openssl`) and fail gracefully with informative messages.
- Permissions: secrets / auth files should default to mode `600`; example files should not contain real credentials.
- Standalone helpers must bootstrap with `SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"`, derive `REPO_ROOT`, source `scripts/common.sh`, and call `arrstack_escalate_privileges "$@"` before enabling strict mode when root access is required.
- Reuse the shared helpers in `scripts/common.sh` (`ensure_dir_mode`, `ensure_secret_file_mode`, `check_dependencies`, etc.) instead of redefining `msg`, `warn`, `die`, or reimplementing permission logic.
- Use consistent indenting, quoting, and avoid unsafe expansions (e.g. always quote variables when used in paths).
- Example / template files (with `.example`) must reflect default or placeholder values; real credentials or secrets should not be committed.

---

## Workflow & Task Guidance

When assigned a task, follow:

1. **Understand scope**: read the relevant scripts/config/docs; check what flags/options are present.
2. **Make changes locally**: propose changes via diffs / patch output.
3. **Run static checks**:
   - `shellcheck` on all `.sh` files (core + `scripts/`).
   - Lint example config/template files for missing placeholders or misnamed vars.
   - If any `.env.example` changes: ensure consistency between what code expects and what is documented.
4. **Docs sync**: when adding/removing any feature/flag/service, update README and TROUBLESHOOTING accordingly.
5. **Test help-interfaces**: ensure `./arrstack.sh --help` reflects current flags/options.

---

## Testing & Validation Commands

Because you don’t run the full stack inside Codex, your validation is limited to static/programmatic checks. You are expected to invoke:

- `shellcheck` over all shell scripts.
- Any version checking or YAML/Env variable consistency scripts (e.g. `scripts/fix-versions.sh`) to confirm no missing fallbacks.
- Help output tests (i.e. `./arrstack.sh --help`) to succeed without side-effects.

If these checks exist in scripts, run them; if not, propose creating them.

---

## What Agent MAY Do vs MAY NOT Do **in This Environment**

| May Do | May NOT Do / Should Avoid |
|---|---|
| Modify code, scripts, config, docs. | Launching the full stack via Docker Compose inside Codex environment. |
| Generate patches, suggestions, tests. | Making host OS changes (e.g. DNS, system services). |
| Update example/template / permissions. | Using secrets or private credentials. |
| Validate static correctness, version pins, env var alignment. | Relying on unlimited network in agent run; assume host privileges. |

---

## Pull Request / Commit Guidelines

- Commit messages should follow form: `<type>(<area>): short description` e.g. `feat(installer): add PORT_SYNC_IMAGE override`.
- PR body should include:
  1. Summary of the change.
  2. Impact / user visible difference.
  3. Any actions needed by host-user (e.g. copy example file, set env var, run a helper).
  4. Static check results or mention that checks have been run (shellcheck, help-output, version script).  
- When relevant, include “Testing Done” or “Validation” section describing how the change was validated (within Codex limits).

---

## Security & Secrets Handling

- Never commit real credentials. Use `.example` files for placeholders.
- Files like `arrconf/proton.auth` (or similar) are local secrets; templates only in `.example`.
- Keep secrets permissions to `600`.
- If adding features dealing with control APIs (e.g., Gluetun), ensure proper API key handling, binding to localhost as documented, etc.

---

## Additional Notes

- Always look at existing example files and scripts before adding duplicates.
- For new features, ensure clear default behaviour and documentation of overrides (env vars, userr.conf).
- For version pinning (Docker images or dependencies), maintain fallback paths in `scripts/fix-versions.sh` or similar.
- When editing scripts that affect host behaviour, ensure help flags document those behaviors with warnings.
- `address_conflicts()` now lives solely in `scripts/common.sh`; reuse it instead of redefining per-script variants.
- Prefer the shared `get_env_kv` helper when reading values from `.env` so escaping stays consistent.

---

## Agent’s Priorities

1. **Correctness** — code should behave as described in docs and be consistent.
2. **Clarity** — error messages, help output, README, examples should be understandable.
3. **Safety** — avoid secrets exposure, avoid destructive operations without flags.
4. **Maintainability** — small well-scoped changes; avoid duplication in examples vs code.
5. **Minimal assumptions** about environment when working inside Codex.

---

## Scope of this AGENTS.md

- Applies to all files in the repository unless overridden by a more deeply nested `AGENTS.md`.
- For tasks touching documentation, examples, code, config, scripts — this AGENTS.md must be respected.
- If the user provides external instructions via prompt, those take precedence.

---

