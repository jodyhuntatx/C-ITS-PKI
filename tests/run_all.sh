#!/usr/bin/env bash
# run_all.sh — C-ITS PKI Test Suite Runner
# Runs all test scripts and reports overall pass/fail.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKI_ROOT="$(dirname "$SCRIPT_DIR")"

# Colour codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     C-ITS PKI Test Suite — ETSI TS 103 097 V2.2.1       ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Pre-flight checks ─────────────────────────────────────────────────────────

echo -e "${BOLD}Pre-flight checks${NC}"

# Python version
PYTHON_VERSION=$(python3.10 --version 2>&1)
echo "  Python   : $PYTHON_VERSION"

# Check required packages
if python3.10 -c "import cryptography" 2>/dev/null; then
    CRYPTO_VERSION=$(python3.10 -c "import cryptography; print(cryptography.__version__)")
    echo -e "  cryptography : ${GREEN}$CRYPTO_VERSION${NC}"
else
    echo -e "  cryptography : ${RED}NOT INSTALLED${NC}"
    echo ""
    echo "  Install with: pip install -r requirements.txt"
    exit 1
fi

# Check src package is importable
if python3.10 -c "import sys; sys.path.insert(0,'$PKI_ROOT'); import src" 2>/dev/null; then
    echo -e "  src package  : ${GREEN}OK${NC}"
else
    echo -e "  src package  : ${RED}NOT FOUND${NC} (run from $PKI_ROOT)"
    exit 1
fi

echo ""

# ── Test Scripts ──────────────────────────────────────────────────────────────

TESTS=(
    test_01_keygen.sh
    test_02_root_ca.sh
    test_03_ea_aa_certs.sh
    test_04_tlm_ec_at.sh
    test_05_signing.sh
    test_06_encryption.sh
    test_07_pki_init.sh
    test_08_coer_encoding.sh
    test_09_verification.sh
)

TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0

for test_script in "${TESTS[@]}"; do
    test_path="$SCRIPT_DIR/$test_script"
    if [[ ! -f "$test_path" ]]; then
        echo -e "${YELLOW}[SKIP]${NC} $test_script (not found)"
        continue
    fi

    chmod +x "$test_path"
    TOTAL_SUITES=$((TOTAL_SUITES + 1))

    echo -e "${BOLD}Running: $test_script${NC}"

    # Run test from PKI root so imports work
    if (cd "$PKI_ROOT" && bash "$test_path"); then
        PASSED_SUITES=$((PASSED_SUITES + 1))
        echo -e "${GREEN}[SUITE PASSED]${NC} $test_script"
    else
        FAILED_SUITES=$((FAILED_SUITES + 1))
        echo -e "${RED}[SUITE FAILED]${NC} $test_script"
    fi
    echo ""
done

# ── Summary ───────────────────────────────────────────────────────────────────

echo "$(printf '═%.0s' {1..60})"
echo -e "${BOLD}Test Suite Summary${NC}"
echo "$(printf '─%.0s' {1..60})"
echo -e "  Suites run    : $TOTAL_SUITES"
echo -e "  ${GREEN}Suites passed${NC} : $PASSED_SUITES"
echo -e "  ${RED}Suites failed${NC} : $FAILED_SUITES"
echo "$(printf '═%.0s' {1..60})"

if [[ $FAILED_SUITES -eq 0 ]]; then
    echo -e "\n${GREEN}${BOLD}ALL TESTS PASSED${NC}\n"
    exit 0
else
    echo -e "\n${RED}${BOLD}$FAILED_SUITES SUITE(S) FAILED${NC}\n"
    exit 1
fi
