# Tests

Use these scripts to verify the offline helpers that arrbash ships with this repository.

## Smoke tests
Run the smoke tests directly from the repository root:

```bash
./test/smoke/pm-watch.dryrun.sh
./test/smoke/pf-openvpn-wireguard.sh
```

Both scripts exit non-zero if their assertions fail.

## Shell linting
You can lint the shell scripts locally with [ShellCheck](https://www.shellcheck.net/):

```bash
shellcheck scripts/**/*.sh test/smoke/*.sh
```

## Compose sanity checks
arrbash cannot run Docker in this environment, but on a real host you can validate the generated stack with:

```bash
./scripts/gen-env.sh
./scripts/compose-runtime.sh
docker compose config
# or bring the stack up once you have reviewed the output
# docker compose up -d
```

These commands confirm that the `.env` and Compose output render correctly with your configuration before launching containers.
