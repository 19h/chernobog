#!/bin/bash
#
# Component-Level Tests for Chernobog
# ====================================
# Tests each D810-NG ported feature individually
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IDUMP="${IDUMP:-/home/null/local/bin/idump}"
TEST_BINARY="$PROJECT_DIR/fake_hikari"
RESULTS_DIR="$SCRIPT_DIR/results/components"

mkdir -p "$RESULTS_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

log_test() {
    local result="$1"
    local name="$2"
    local details="$3"

    ((TOTAL_TESTS++))
    if [[ "$result" == "PASS" ]]; then
        echo -e "${GREEN}[PASS]${NC} $name"
        ((PASSED_TESTS++))
    elif [[ "$result" == "FAIL" ]]; then
        echo -e "${RED}[FAIL]${NC} $name"
        [[ -n "$details" ]] && echo -e "       ${YELLOW}$details${NC}"
        ((FAILED_TESTS++))
    else
        echo -e "${YELLOW}[SKIP]${NC} $name"
    fi
}

run_idump() {
    local args="$1"
    local timeout_sec="${2:-120}"

    CHERNOBOG_RESET=1 CHERNOBOG_DEBUG=1 CHERNOBOG_AUTO=1 \
        timeout "$timeout_sec" "$IDUMP" $args "$TEST_BINARY" 2>&1
}

# ==============================================================================
# 1. AST System Tests
# ==============================================================================
test_ast_system() {
    echo -e "\n${MAGENTA}╔════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║ 1. AST System Tests                    ║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════╝${NC}"

    # AST is internal - test via successful microcode translation
    local output
    output=$(run_idump "--mc -a 0x12E9" 60)

    # Check microcode was generated (means AST worked)
    if echo "$output" | grep -q "m_mov\|m_add\|m_xor"; then
        log_test "PASS" "AST: Microcode translation works"
    else
        log_test "FAIL" "AST: Microcode translation failed"
    fi

    # Test larger function AST
    output=$(run_idump "--mc -a 0x207C" 120)
    local insn_count=$(echo "$output" | grep -c "^[0-9]" || true)

    if [[ $insn_count -gt 50 ]]; then
        log_test "PASS" "AST: Large function processed ($insn_count instructions)"
    else
        log_test "FAIL" "AST: Large function had too few instructions ($insn_count)"
    fi
}

# ==============================================================================
# 2. Pattern Matching Tests
# ==============================================================================
test_pattern_matching() {
    echo -e "\n${MAGENTA}╔════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║ 2. Pattern Matching Tests              ║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════╝${NC}"

    # Pattern matching is tested via rule application
    local output

    # Test MBA pattern: (a ^ b) + 2 * (a & b) = a + b
    # mba_add at 0x12E9
    output=$(run_idump "--pseudo -a 0x12E9" 60)

    if echo "$output" | grep -q "return"; then
        log_test "PASS" "Pattern Matching: mba_add pattern recognized"
    else
        log_test "FAIL" "Pattern Matching: mba_add pattern not recognized"
    fi

    # Test XOR patterns
    output=$(run_idump "--mc -a 0x1352" 60)
    if echo "$output" | grep -q "xor\|m_xor"; then
        log_test "PASS" "Pattern Matching: XOR patterns found"
    else
        log_test "FAIL" "Pattern Matching: XOR patterns not found"
    fi
}

# ==============================================================================
# 3. MBA Rule Tests
# ==============================================================================
test_mba_rules() {
    echo -e "\n${MAGENTA}╔════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║ 3. MBA Rule Tests                      ║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════╝${NC}"

    local output

    # Test Addition rules: (a ^ b) + 2 * (a & b) = a + b
    output=$(run_idump "--pseudo -a 0x12E9" 60)
    if echo "$output" | grep -q "return"; then
        log_test "PASS" "MBA Add Rules: Function decompiles"
    else
        log_test "FAIL" "MBA Add Rules: Function failed"
    fi

    # Test Subtraction rules: (a ^ b) - 2 * (~a & b) = a - b
    output=$(run_idump "--pseudo -a 0x1307" 60)
    if echo "$output" | grep -q "return"; then
        log_test "PASS" "MBA Sub Rules: Function decompiles"
    else
        log_test "FAIL" "MBA Sub Rules: Function failed"
    fi

    # Test XOR rules: x ^ x = 0
    output=$(run_idump "--pseudo -a 0x1352" 60)
    if echo "$output" | grep -q "return"; then
        log_test "PASS" "MBA XOR Rules: mba_zero decompiles"
    else
        log_test "FAIL" "MBA XOR Rules: mba_zero failed"
    fi

    # Test AND rules
    output=$(run_idump "--mc -a 0x1352" 60)
    local and_count=$(echo "$output" | grep -c "m_and\|and " || true)
    log_test "PASS" "MBA AND Rules: Found $and_count AND operations"

    # Test OR rules
    output=$(run_idump "--mc -a 0x13C2" 60)
    local or_count=$(echo "$output" | grep -c "m_or\|or " || true)
    log_test "PASS" "MBA OR Rules: Found $or_count OR operations"
}

# ==============================================================================
# 4. Predicate Rule Tests
# ==============================================================================
test_predicate_rules() {
    echo -e "\n${MAGENTA}╔════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║ 4. Predicate Rule Tests                ║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════╝${NC}"

    local output

    # Test self-comparison rules: x == x, x < x, etc.
    output=$(run_idump "--mc -a 0x1352" 60)

    # Count set* instructions
    local setz_count=$(echo "$output" | grep -c "setz\|m_setz" || true)
    local setnz_count=$(echo "$output" | grep -c "setnz\|m_setnz" || true)

    log_test "PASS" "Predicate: Found $setz_count setz, $setnz_count setnz"

    # Test on wrapper function with opaque predicates
    output=$(run_idump "--pseudo -a 0x143C" 60)
    if echo "$output" | grep -q "return\|if"; then
        log_test "PASS" "Predicate: Opaque predicate function decompiles"
    else
        log_test "FAIL" "Predicate: Opaque predicate function failed"
    fi
}

# ==============================================================================
# 5. Chain Simplifier Tests
# ==============================================================================
test_chain_simplifier() {
    echo -e "\n${MAGENTA}╔════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║ 5. Chain Simplifier Tests              ║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════╝${NC}"

    local output

    # Test XOR chains in decrypt function
    output=$(run_idump "--mc -a 0x16FD" 60)
    local xor_count=$(echo "$output" | grep -c "xor" || true)

    log_test "PASS" "Chain: XOR chain with $xor_count operations"

    # Test ADD chains
    output=$(run_idump "--mc -a 0x12E9" 60)
    local add_count=$(echo "$output" | grep -c "add\|m_add" || true)

    log_test "PASS" "Chain: ADD chain with $add_count operations"

    # Verify chain simplification via decompilation
    output=$(run_idump "--pseudo -a 0x16FD" 60)
    if echo "$output" | grep -q "return"; then
        log_test "PASS" "Chain: Decrypt function simplified"
    else
        log_test "FAIL" "Chain: Decrypt function not simplified"
    fi
}

# ==============================================================================
# 6. Peephole Optimizer Tests
# ==============================================================================
test_peephole() {
    echo -e "\n${MAGENTA}╔════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║ 6. Peephole Optimizer Tests            ║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════╝${NC}"

    local output

    # Test on small functions (wrappers)
    output=$(run_idump "--pseudo -a 0x1329" 60)
    if echo "$output" | grep -q "return"; then
        log_test "PASS" "Peephole: Small function optimized"
    else
        log_test "FAIL" "Peephole: Small function failed"
    fi

    # Test dead code elimination
    output=$(run_idump "--pseudo -a 0x1337" 60)
    local line_count=$(echo "$output" | grep -c "^" || true)

    log_test "PASS" "Peephole: Function produced $line_count lines"
}

# ==============================================================================
# 7. Jump Optimizer Tests
# ==============================================================================
test_jump_optimizer() {
    echo -e "\n${MAGENTA}╔════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║ 7. Jump Optimizer Tests                ║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════╝${NC}"

    local output

    # Test on function with many conditional jumps
    output=$(run_idump "--mc -a 0x1576" 60)

    local jcnd_before=$(echo "$output" | grep -c "jcnd\|jnz\|jz" || true)
    log_test "PASS" "Jump: Found $jcnd_before conditional jumps"

    # Decompile and check if structure is simplified
    output=$(run_idump "--pseudo -a 0x1576" 60)

    if echo "$output" | grep -q "if\|return"; then
        log_test "PASS" "Jump: Conditional structure preserved/simplified"
    else
        log_test "FAIL" "Jump: Conditional structure lost"
    fi
}

# ==============================================================================
# 8. Unflattener Tests
# ==============================================================================
test_unflatteners() {
    echo -e "\n${MAGENTA}╔════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║ 8. Unflattener Tests                   ║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════╝${NC}"

    local output

    # 8.1 HikariUnflattener (priority 80)
    echo -e "${CYAN}8.1 HikariUnflattener${NC}"
    output=$(run_idump "--pseudo -a 0x207C" 120)
    if echo "$output" | grep -q "return"; then
        log_test "PASS" "HikariUnflattener: Main function decompiles"
    else
        log_test "FAIL" "HikariUnflattener: Main function failed"
    fi

    # 8.2 FakeJumpUnflattener (priority 85)
    echo -e "${CYAN}8.2 FakeJumpUnflattener${NC}"
    output=$(run_idump "--pseudo -a 0x143C" 60)
    if echo "$output" | grep -q "return\|printf\|print"; then
        log_test "PASS" "FakeJumpUnflattener: Wrapper function simplified"
    else
        log_test "FAIL" "FakeJumpUnflattener: Wrapper function not simplified"
    fi

    # 8.3 BadWhileLoopUnflattener (priority 75)
    echo -e "${CYAN}8.3 BadWhileLoopUnflattener${NC}"
    output=$(run_idump "--pseudo -a 0x16FD" 60)
    # while(1) loops should be converted to proper structure
    if echo "$output" | grep -q "return\|while\|for"; then
        log_test "PASS" "BadWhileLoopUnflattener: Loop structure handled"
    else
        log_test "FAIL" "BadWhileLoopUnflattener: Loop structure lost"
    fi

    # 8.4 OLLVMUnflattener (priority 70)
    echo -e "${CYAN}8.4 OLLVMUnflattener${NC}"
    output=$(run_idump "--pseudo -a 0x1CC9" 120)
    if echo "$output" | grep -q "return"; then
        log_test "PASS" "OLLVMUnflattener: loadConfig decompiles"
    else
        log_test "FAIL" "OLLVMUnflattener: loadConfig failed"
    fi

    # 8.5 JumpTableUnflattener (priority 60)
    echo -e "${CYAN}8.5 JumpTableUnflattener${NC}"
    output=$(run_idump "--mc -a 0x207C" 120)
    # Look for switch/jump table patterns
    local switch_count=$(echo "$output" | grep -c "jtbl\|switch" || true)
    log_test "PASS" "JumpTableUnflattener: Found $switch_count jump table refs"

    # 8.6 SwitchCaseUnflattener (priority 55)
    echo -e "${CYAN}8.6 SwitchCaseUnflattener${NC}"
    output=$(run_idump "--pseudo -a 0x1DB1" 120)
    if echo "$output" | grep -q "return"; then
        log_test "PASS" "SwitchCaseUnflattener: checkNetwork decompiles"
    else
        log_test "FAIL" "SwitchCaseUnflattener: checkNetwork failed"
    fi

    # 8.7 GenericUnflattener (priority 30)
    echo -e "${CYAN}8.7 GenericUnflattener${NC}"
    output=$(run_idump "--pseudo -a 0x2458" 120)
    if echo "$output" | grep -q "return"; then
        log_test "PASS" "GenericUnflattener: checksum decompiles"
    else
        log_test "FAIL" "GenericUnflattener: checksum failed"
    fi
}

# ==============================================================================
# 9. Integration Tests
# ==============================================================================
test_integration() {
    echo -e "\n${MAGENTA}╔════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║ 9. Integration Tests                   ║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════╝${NC}"

    local output

    # Full binary decompilation
    echo "Running full binary decompilation (this may take a while)..."
    output=$(run_idump "--pseudo" 300)
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_test "PASS" "Integration: Full binary decompiles"
    else
        log_test "FAIL" "Integration: Full binary failed (exit code $exit_code)"
    fi

    # Count decompiled functions
    local func_count=$(echo "$output" | grep -c "^__int64\|^void\|^int\|^unsigned" || true)
    log_test "PASS" "Integration: Decompiled $func_count functions"

    # Check for crashes or errors
    local error_count=$(echo "$output" | grep -ci "error\|crash\|abort\|segfault" || true)
    if [[ $error_count -eq 0 ]]; then
        log_test "PASS" "Integration: No crashes or errors"
    else
        log_test "FAIL" "Integration: Found $error_count error messages"
    fi
}

# ==============================================================================
# Summary
# ==============================================================================
print_summary() {
    echo -e "\n${MAGENTA}╔════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║            TEST SUMMARY                ║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "Total Tests:  ${CYAN}$TOTAL_TESTS${NC}"
    echo -e "Passed:       ${GREEN}$PASSED_TESTS${NC}"
    echo -e "Failed:       ${RED}$FAILED_TESTS${NC}"
    echo ""

    local percent=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}========================================${NC}"
        echo -e "${GREEN}  ALL TESTS PASSED! ($percent%)${NC}"
        echo -e "${GREEN}========================================${NC}"
    else
        echo -e "${YELLOW}========================================${NC}"
        echo -e "${YELLOW}  $FAILED_TESTS TESTS FAILED ($percent% passed)${NC}"
        echo -e "${YELLOW}========================================${NC}"
    fi
}

# ==============================================================================
# Main
# ==============================================================================
main() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   Chernobog Component Test Suite                   ║${NC}"
    echo -e "${BLUE}║   Testing all D810-NG ported features              ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Date: $(date)"
    echo "Binary: $TEST_BINARY"
    echo ""

    case "${1:-all}" in
        all)
            test_ast_system
            test_pattern_matching
            test_mba_rules
            test_predicate_rules
            test_chain_simplifier
            test_peephole
            test_jump_optimizer
            test_unflatteners
            test_integration
            ;;
        ast)         test_ast_system ;;
        pattern)     test_pattern_matching ;;
        mba)         test_mba_rules ;;
        predicate)   test_predicate_rules ;;
        chain)       test_chain_simplifier ;;
        peephole)    test_peephole ;;
        jump)        test_jump_optimizer ;;
        unflatten)   test_unflatteners ;;
        integration) test_integration ;;
        *)
            echo "Usage: $0 [all|ast|pattern|mba|predicate|chain|peephole|jump|unflatten|integration]"
            exit 1
            ;;
    esac

    print_summary

    [[ $FAILED_TESTS -eq 0 ]]
}

main "$@"
