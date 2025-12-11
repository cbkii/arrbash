# POSIX Compliance Guide

## Overview

The `.aliasarr` file (generated from `scripts/gen-aliasarr.template.sh`) uses POSIX-compliant syntax for maximum shell compatibility while preserving the project's API design with dotted function names.

## Shell Compatibility Strategy

### Target Shells
- **Primary:** bash, zsh (documented in usage.md)
- **Core Syntax:** POSIX-compliant (works in sh, dash, bash, zsh, ksh)
- **Function Names:** Use dots (e.g., `arr.vpn.status`) - supported by bash/zsh/ksh but NOT strict POSIX sh/dash

### Rationale
The project maintains 195+ functions with dotted names as a core API design. This naming convention:
- Works perfectly in bash and zsh (the project's target shells)
- Provides clear namespacing (e.g., `arr.vpn.*`, `arr.qbt.*`)
- Is consistent across the entire codebase

The core syntax is POSIX-compliant to maximize portability and avoid Bash-specific constructs that could cause issues.

## POSIX Compliance Patterns

### 1. Array Replacement

**Bash (before):**
```bash
arr=()
arr+=("item1")
arr+=("item2")
for item in "${arr[@]}"; do
    echo "$item"
done
```

**POSIX (after):**
```sh
arr=""
_arr_append() {
    if [ -z "$arr" ]; then
        arr="$1"
    else
        arr="$arr
$1"
    fi
}
_arr_append "item1"
_arr_append "item2"
printf '%s\n' "$arr" | while IFS= read -r item; do
    [ -n "$item" ] || continue
    echo "$item"
done
```

### 2. Arithmetic Evaluation

**Bash (before):**
```bash
if ((_arr_services_cached)); then
    return 0
fi

if ((${#arr[@]} > 0)); then
    echo "Array has elements"
fi
```

**POSIX (after):**
```sh
if [ "$_arr_services_cached" -eq 1 ]; then
    return 0
fi

if [ -n "$arr" ]; then
    echo "String has content"
fi
```

**Note:** `$((expr))` for arithmetic expansion is POSIX-compliant and should be kept:
```sh
waited=$((waited + interval))  # ✅ POSIX-compliant
```

### 3. Test Constructs

**Bash (before):**
```bash
[[ -f "$file" ]] && echo "exists"
[[ $var =~ ^[0-9]+$ ]] && echo "numeric"
```

**POSIX (after):**
```sh
[ -f "$file" ] && echo "exists"
expr "$var" : '^[0-9][0-9]*$' >/dev/null && echo "numeric"
# or
case "$var" in
    *[!0-9]*) echo "not numeric" ;;
    *) echo "numeric" ;;
esac
```

### 4. String Operations

**Bash (before):**
```bash
value="${value//$'\r'/ }"
value="${value//,/ }"
```

**POSIX (after):**
```sh
value="$(printf '%s' "$value" | tr '\r' ' ')"
value="$(printf '%s' "$value" | tr ',' ' ')"
```

**Keep POSIX-compliant patterns:**
```sh
${var#pattern}   # ✅ Remove shortest prefix
${var##pattern}  # ✅ Remove longest prefix
${var%pattern}   # ✅ Remove shortest suffix
${var%%pattern}  # ✅ Remove longest suffix
```

### 5. Function Checks

**Bash (before):**
```bash
if declare -f function_name >/dev/null 2>&1; then
    function_name
fi
```

**POSIX (after):**
```sh
if command -v function_name >/dev/null 2>&1; then
    function_name
fi
```

### 6. Variable Assignment by Name

**Bash (before):**
```bash
printf -v "$var_name" '%s' "$value"
```

**POSIX (after):**
```sh
eval "$var_name='$value'"  # Safe when var_name is from internal source
```

## Testing for POSIX Compliance

### Shellcheck Validation
```bash
shellcheck --shell=sh --severity=error scripts/gen-aliasarr.template.sh
```

### Bash Syntax Check
```bash
bash -n scripts/gen-aliasarr.template.sh
```

### Source Test
```bash
# Generate test file
TEST_DIR="/tmp/test_$$"
mkdir -p "$TEST_DIR"
sed -e "s|__ARR_STACK_DIR__|${TEST_DIR}|g" \
    -e "s|__ARR_ENV_FILE__|${TEST_DIR}/.env|g" \
    -e "s|__ARR_DOCKER_DIR__|${TEST_DIR}/dockarr|g" \
    -e "s|__ARRCONF_DIR__|${TEST_DIR}/arrconf|g" \
    scripts/gen-aliasarr.template.sh > "${TEST_DIR}/.aliasarr"

# Test sourcing
bash -c "source ${TEST_DIR}/.aliasarr && echo 'Success'"
```

## Common Pitfalls

### 1. Don't Use Process Substitution
```bash
# ❌ Not POSIX
while read -r line; do
    echo "$line"
done < <(command)

# ✅ POSIX alternative - Use heredoc or pipe
command | while read -r line; do
    echo "$line"
done
```

### 2. Don't Use Here-Strings
```bash
# ❌ Not POSIX
grep pattern <<< "$variable"

# ✅ POSIX alternative
printf '%s\n' "$variable" | grep pattern
```

### 3. Don't Use ANSI-C Quoting
```bash
# ❌ Not POSIX
value=$'line1\nline2'

# ✅ POSIX alternative
value="line1
line2"
```

### 4. Be Careful with Local Variables
```bash
# ⚠️  'local' is not POSIX but is universally supported
# We use it throughout the codebase for consistency
local var="value"  # Acceptable in this project
```

## Security Considerations

### Safe eval Usage
The codebase uses `eval` in specific contexts where it's safe:

1. **Variable assignment by name (internal):**
   ```sh
   error_var="my_error"
   eval "$error_var='Error message'"  # Safe - variable name from internal source
   ```

2. **Command execution with validated arguments:**
   ```sh
   curl_args="-fsS -X GET"  # Constructed from validated internal variables
   eval "curl $curl_args \"$url\""  # Safe - no user input in curl_args
   ```

**Always avoid:** `eval` with user-controlled input.

## Maintenance Guidelines

When modifying `scripts/gen-aliasarr.template.sh`:

1. **Run shellcheck** after every change:
   ```bash
   shellcheck --shell=sh scripts/gen-aliasarr.template.sh
   ```

2. **Test the generated file:**
   ```bash
   ./arr.sh --alias
   source ~/srv/arr/.aliasarr
   ```

3. **Preserve POSIX compliance:**
   - Use `[ ]` not `[[ ]]`
   - Use strings not arrays
   - Use `command -v` not `declare -f`
   - Use `tr`/`sed` not `${var//pattern/replace}`

4. **Keep function names with dots:**
   - This is the project's API convention
   - 195+ functions use this pattern
   - Works in bash/zsh (target shells)

## References

- [POSIX Shell Command Language](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)
- [ShellCheck Wiki](https://github.com/koalaman/shellcheck/wiki)
- [Rich's sh (POSIX shell) tricks](http://www.etalabs.net/sh_tricks.html)
