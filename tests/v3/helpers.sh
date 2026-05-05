#!/usr/bin/env bash
# Test helper functions for C-ITS PKI test suite.

# Colour codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Global counters
PASS=0
FAIL=0
SKIP=0
TEST_NAME=""

# ── PKI project root ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
PKI_CMD="$PYTHON $PKI_ROOT/cli.py"
PKI_PY="$PYTHON -c"

# ── Assertion helpers ─────────────────────────────────────────────────────────

pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    FAIL=$((FAIL + 1))
}

skip() {
    echo -e "  ${YELLOW}[SKIP]${NC} $1"
    SKIP=$((SKIP + 1))
}

assert_exit_0() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        pass "$desc"
    else
        fail "$desc (command: $*)"
    fi
}

assert_exit_nonzero() {
    local desc="$1"; shift
    if ! "$@" >/dev/null 2>&1; then
        pass "$desc"
    else
        fail "$desc (expected non-zero exit)"
    fi
}

assert_file_exists() {
    local desc="$1"
    local path="$2"
    if [[ -f "$path" ]]; then
        pass "$desc"
    else
        fail "$desc (file not found: $path)"
    fi
}

assert_file_size_gt() {
    local desc="$1"
    local path="$2"
    local min_size="$3"
    local actual
    actual=$(wc -c < "$path" 2>/dev/null || echo 0)
    if [[ "$actual" -gt "$min_size" ]]; then
        pass "$desc (size=$actual bytes)"
    else
        fail "$desc (expected > $min_size bytes, got $actual)"
    fi
}

assert_equal() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        pass "$desc"
    else
        fail "$desc (expected='$expected', actual='$actual')"
    fi
}

assert_contains() {
    local desc="$1"
    local haystack="$2"
    local needle="$3"
    if echo "$haystack" | grep -q "$needle"; then
        pass "$desc"
    else
        fail "$desc (expected to contain '$needle')"
    fi
}

assert_python_ok() {
    local desc="$1"
    local script="$2"
    local output
    output=$(cd "$PKI_ROOT" && $PYTHON -c "$script" 2>&1)
    if [[ $? -eq 0 ]]; then
        pass "$desc"
    else
        fail "$desc: $output"
    fi
}

# ── Section header ────────────────────────────────────────────────────────────

section() {
    echo -e "\n${BOLD}${CYAN}$1${NC}"
    echo "$(printf '─%.0s' {1..60})"
}

# ── Summary ───────────────────────────────────────────────────────────────────

print_summary() {
    local total=$((PASS + FAIL + SKIP))
    echo ""
    echo "$(printf '═%.0s' {1..60})"
    echo -e "${BOLD}Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC} / $total total"
    echo "$(printf '═%.0s' {1..60})"
    [[ $FAIL -eq 0 ]]
}

# ── Temp directory management ────────────────────────────────────────────────

make_tmpdir() {
    mktemp -d /tmp/cits_pki_test_XXXXXX
}

cleanup_tmpdir() {
    local dir="$1"
    [[ -n "$dir" && -d "$dir" ]] && rm -rf "$dir"
}
