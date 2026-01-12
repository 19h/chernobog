#!/bin/bash
#
# Individual Function Tests
# =========================
# Tests specific functions in the fake_hikari binary
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IDUMP="${IDUMP:-/home/null/local/bin/idump}"
TEST_BINARY="$PROJECT_DIR/fake_hikari"
RESULTS_DIR="$SCRIPT_DIR/results/individual"

mkdir -p "$RESULTS_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Function addresses from fake_hikari
# Based on the test.c source mapping:
declare -A FUNCTIONS=(
    # MBA functions (small, should simplify)
    ["mba_add"]="0x12E9"
    ["mba_sub"]="0x1307"
    ["mba_mul2"]="0x1329"
    ["mba_eq"]="0x1337"
    ["mba_zero"]="0x1352"
    ["mba_one"]="0x13C2"

    # Wrapper functions (indirect calls)
    ["wrapper_001"]="0x143C"
    ["wrapper_002"]="0x148F"
    ["wrapper_003"]="0x150E"
    ["wrapper_004"]="0x1576"
    ["wrapper_005"]="0x162E"
    ["wrapper_006"]="0x16A5"

    # String operations
    ["decrypt_array"]="0x16FD"
    ["build_string_1"]="0x188B"
    ["build_string_2"]="0x18E2"
    ["build_string_3"]="0x1A40"

    # CFF functions (flattened control flow)
    ["processData"]="0x1C1A"
    ["loadConfig"]="0x1CC9"
    ["checkNetwork"]="0x1DB1"
    ["cleanupSystem"]="0x207C"

    # Utility functions
    ["checksum"]="0x2458"
    ["memcmp"]="0x2731"

    # Main
    ["main"]="0x27E9"
)

run_test() {
    local name="$1"
    local addr="$2"
    local mode="$3"  # pseudo, mc, asm

    echo -e "\n${CYAN}Testing $name @ $addr${NC}"

    local output_file="$RESULTS_DIR/${name}_${mode}.txt"

    CHERNOBOG_RESET=1 CHERNOBOG_DEBUG=1 CHERNOBOG_AUTO=1 \
        timeout 120 "$IDUMP" --${mode} -a "$addr" "$TEST_BINARY" > "$output_file" 2>&1

    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}[OK]${NC} $name decompiled successfully"

        # Show summary
        if [[ "$mode" == "pseudo" ]]; then
            local lines=$(grep -c "^" "$output_file" || true)
            local returns=$(grep -c "return" "$output_file" || true)
            echo "  Lines: $lines, Returns: $returns"
        elif [[ "$mode" == "mc" ]]; then
            local insns=$(grep -c "^[0-9]" "$output_file" || true)
            echo "  Microcode instructions: $insns"
        fi
    else
        echo -e "${RED}[FAIL]${NC} $name failed (exit code $exit_code)"
    fi

    return $exit_code
}

test_all_pseudo() {
    echo -e "${BLUE}=== Testing All Functions (Pseudocode) ===${NC}"

    local passed=0
    local failed=0

    for name in "${!FUNCTIONS[@]}"; do
        if run_test "$name" "${FUNCTIONS[$name]}" "pseudo"; then
            ((passed++))
        else
            ((failed++))
        fi
    done

    echo -e "\n${BLUE}Summary:${NC} $passed passed, $failed failed"
}

test_all_microcode() {
    echo -e "${BLUE}=== Testing All Functions (Microcode) ===${NC}"

    local passed=0
    local failed=0

    for name in "${!FUNCTIONS[@]}"; do
        if run_test "$name" "${FUNCTIONS[$name]}" "mc"; then
            ((passed++))
        else
            ((failed++))
        fi
    done

    echo -e "\n${BLUE}Summary:${NC} $passed passed, $failed failed"
}

test_mba_functions() {
    echo -e "${BLUE}=== Testing MBA Functions ===${NC}"

    for name in mba_add mba_sub mba_mul2 mba_eq mba_zero mba_one; do
        run_test "$name" "${FUNCTIONS[$name]}" "pseudo"
        echo "  --- Microcode ---"
        run_test "$name" "${FUNCTIONS[$name]}" "mc"
    done
}

test_cff_functions() {
    echo -e "${BLUE}=== Testing CFF Functions ===${NC}"

    for name in processData loadConfig checkNetwork cleanupSystem; do
        run_test "$name" "${FUNCTIONS[$name]}" "pseudo"
    done
}

test_wrapper_functions() {
    echo -e "${BLUE}=== Testing Wrapper Functions ===${NC}"

    for name in wrapper_001 wrapper_002 wrapper_003 wrapper_004 wrapper_005 wrapper_006; do
        run_test "$name" "${FUNCTIONS[$name]}" "pseudo"
    done
}

compare_before_after() {
    echo -e "${BLUE}=== Comparing Before/After Deobfuscation ===${NC}"

    local addr="$1"
    local name="$2"

    echo "Testing $name @ $addr"

    # Without chernobog (just hex-rays)
    echo "Without chernobog:"
    CHERNOBOG_DISABLE=1 timeout 60 "$IDUMP" -q --pseudo -a "$addr" "$TEST_BINARY" 2>&1 | head -30

    echo ""
    echo "With chernobog:"
    CHERNOBOG_RESET=1 CHERNOBOG_AUTO=1 timeout 120 "$IDUMP" -q --pseudo -a "$addr" "$TEST_BINARY" 2>&1 | head -30
}

case "${1:-all}" in
    all)
        test_all_pseudo
        ;;
    mc)
        test_all_microcode
        ;;
    mba)
        test_mba_functions
        ;;
    cff)
        test_cff_functions
        ;;
    wrapper)
        test_wrapper_functions
        ;;
    compare)
        compare_before_after "${2:-0x207C}" "${3:-cleanupSystem}"
        ;;
    single)
        run_test "$2" "$3" "${4:-pseudo}"
        ;;
    *)
        echo "Usage: $0 [all|mc|mba|cff|wrapper|compare|single]"
        echo "  all     - Test all functions (pseudocode)"
        echo "  mc      - Test all functions (microcode)"
        echo "  mba     - Test MBA simplification functions"
        echo "  cff     - Test control flow flattened functions"
        echo "  wrapper - Test wrapper/indirect call functions"
        echo "  compare - Compare before/after deobfuscation"
        echo "  single <name> <addr> [mode] - Test single function"
        exit 1
        ;;
esac
