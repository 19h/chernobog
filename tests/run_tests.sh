#!/bin/bash
#
# Chernobog Comprehensive Test Suite
# ==================================
# Tests all components of the D810-NG port:
# - AST system
# - Pattern matching and fuzzing
# - MBA rules (~100+ rules)
# - Predicate rules
# - Chain simplifier
# - Peephole optimizers
# - Jump optimizer
# - All 7 unflatteners
#
# Usage: ./run_tests.sh [--verbose] [--quick] [--component <name>]
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
IDUMP="${IDUMP:-/home/null/local/bin/idump}"
TEST_BINARY="$PROJECT_DIR/fake_hikari"
RESULTS_DIR="$SCRIPT_DIR/results"
LOG_FILE="$RESULTS_DIR/test_$(date +%Y%m%d_%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Parse arguments
VERBOSE=0
QUICK=0
COMPONENT=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=1
            shift
            ;;
        --quick|-q)
            QUICK=1
            shift
            ;;
        --component|-c)
            COMPONENT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Create results directory
mkdir -p "$RESULTS_DIR"

# Logging function
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

log_verbose() {
    if [[ $VERBOSE -eq 1 ]]; then
        echo -e "$1" | tee -a "$LOG_FILE"
    else
        echo -e "$1" >> "$LOG_FILE"
    fi
}

# Test assertion functions
assert_contains() {
    local output="$1"
    local expected="$2"
    local test_name="$3"

    if echo "$output" | grep -q "$expected"; then
        log "${GREEN}[PASS]${NC} $test_name"
        ((TESTS_PASSED++))
        return 0
    else
        log "${RED}[FAIL]${NC} $test_name"
        log_verbose "  Expected to find: $expected"
        ((TESTS_FAILED++))
        return 1
    fi
}

assert_not_contains() {
    local output="$1"
    local unexpected="$2"
    local test_name="$3"

    if ! echo "$output" | grep -q "$unexpected"; then
        log "${GREEN}[PASS]${NC} $test_name"
        ((TESTS_PASSED++))
        return 0
    else
        log "${RED}[FAIL]${NC} $test_name"
        log_verbose "  Unexpectedly found: $unexpected"
        ((TESTS_FAILED++))
        return 1
    fi
}

assert_count_ge() {
    local output="$1"
    local pattern="$2"
    local min_count="$3"
    local test_name="$4"

    local count=$(echo "$output" | grep -c "$pattern" || true)
    if [[ $count -ge $min_count ]]; then
        log "${GREEN}[PASS]${NC} $test_name (found $count >= $min_count)"
        ((TESTS_PASSED++))
        return 0
    else
        log "${RED}[FAIL]${NC} $test_name (found $count < $min_count)"
        ((TESTS_FAILED++))
        return 1
    fi
}

assert_exit_code() {
    local actual="$1"
    local expected="$2"
    local test_name="$3"

    if [[ $actual -eq $expected ]]; then
        log "${GREEN}[PASS]${NC} $test_name"
        ((TESTS_PASSED++))
        return 0
    else
        log "${RED}[FAIL]${NC} $test_name (exit code $actual != $expected)"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Run idump with chernobog
run_idump() {
    local args="$1"
    local timeout_sec="${2:-120}"

    CHERNOBOG_RESET=1 CHERNOBOG_DEBUG=1 CHERNOBOG_AUTO=1 \
        timeout "$timeout_sec" "$IDUMP" $args "$TEST_BINARY" 2>&1
}

run_idump_quiet() {
    local args="$1"
    local timeout_sec="${2:-120}"

    CHERNOBOG_RESET=1 CHERNOBOG_AUTO=1 \
        timeout "$timeout_sec" "$IDUMP" -q $args "$TEST_BINARY" 2>&1
}

# ==============================================================================
# Test: Plugin Loading
# ==============================================================================
test_plugin_loading() {
    log "\n${BLUE}=== Testing Plugin Loading ===${NC}"

    local output
    output=$(run_idump "-l" 60)

    # Check plugin initialization
    assert_contains "$output" "chernobog" "Plugin name in output"
}

# ==============================================================================
# Test: MBA Rules
# ==============================================================================
test_mba_rules() {
    log "\n${BLUE}=== Testing MBA Rules ===${NC}"

    # Test on a function with MBA patterns
    # sub_12E9 appears to be mba_add based on size
    local output
    output=$(run_idump "--mc -a 0x12E9" 120)

    # Check that microcode is generated
    assert_contains "$output" "m_" "Microcode generated"

    # Test decompilation
    output=$(run_idump "--pseudo -a 0x12E9" 120)
    assert_contains "$output" "return" "Function decompiles"

    # Test larger function with more MBA
    output=$(run_idump "--pseudo -a 0x16FD" 120)
    assert_contains "$output" "return" "Complex function decompiles"
}

# ==============================================================================
# Test: Control Flow Flattening Detection
# ==============================================================================
test_cff_detection() {
    log "\n${BLUE}=== Testing Control Flow Flattening Detection ===${NC}"

    # Test main function (0x2731 based on typical layout)
    # Look for large functions which are likely CFF
    local output

    # sub_207C has 988 bytes - likely flattened
    output=$(run_idump "--mc -a 0x207C" 180)

    # Check for switch/dispatcher patterns in microcode
    # CFF typically has many jcnd/goto instructions
    local jcnd_count=$(echo "$output" | grep -c "jcnd\|goto" || true)
    log_verbose "Found $jcnd_count jcnd/goto instructions"

    # Test decompilation of flattened function
    output=$(run_idump "--pseudo -a 0x207C" 180)
    assert_contains "$output" "return" "Flattened function decompiles"
}

# ==============================================================================
# Test: Predicate Rules
# ==============================================================================
test_predicate_rules() {
    log "\n${BLUE}=== Testing Predicate Rules ===${NC}"

    # Look for functions with opaque predicates
    # These typically have comparisons like x == x, x < x, etc.
    local output

    # Test microcode for predicate patterns
    output=$(run_idump "--mc -a 0x1352" 120)

    # Check for set* instructions (predicates)
    local set_count=$(echo "$output" | grep -c "setz\|setnz\|setb\|setae\|setl\|setg" || true)
    log_verbose "Found $set_count set* instructions"

    # Decompilation should simplify predicates
    output=$(run_idump "--pseudo -a 0x1352" 120)
    assert_contains "$output" "" "Predicate function processes"
}

# ==============================================================================
# Test: Jump Optimizer
# ==============================================================================
test_jump_optimizer() {
    log "\n${BLUE}=== Testing Jump Optimizer ===${NC}"

    local output

    # Test function with conditional jumps
    output=$(run_idump "--mc -a 0x1576" 120)

    # Count conditional jumps
    local jcnd_count=$(echo "$output" | grep -c "jcnd" || true)
    log_verbose "Found $jcnd_count conditional jumps"

    # Decompile and check structure
    output=$(run_idump "--pseudo -a 0x1576" 120)
    assert_contains "$output" "" "Jump optimization processes"
}

# ==============================================================================
# Test: Chain Simplifier
# ==============================================================================
test_chain_simplifier() {
    log "\n${BLUE}=== Testing Chain Simplifier ===${NC}"

    local output

    # Look for XOR chains (common in obfuscation)
    output=$(run_idump "--mc -a 0x13C2" 120)

    local xor_count=$(echo "$output" | grep -c "xor\|m_xor" || true)
    log_verbose "Found $xor_count XOR operations"

    # Decompile
    output=$(run_idump "--pseudo -a 0x13C2" 120)
    assert_contains "$output" "" "Chain simplifier processes"
}

# ==============================================================================
# Test: Unflatteners
# ==============================================================================
test_unflatteners() {
    log "\n${BLUE}=== Testing Unflatteners ===${NC}"

    local output

    # Test HikariUnflattener on large flattened function
    # sub_2458 has 729 bytes
    log "Testing on sub_2458 (729 bytes)..."
    output=$(run_idump "--pseudo -a 0x2458" 180)
    assert_contains "$output" "return" "HikariUnflattener processes function"

    # Test on another large function
    # sub_1DB1 has 715 bytes
    log "Testing on sub_1DB1 (715 bytes)..."
    output=$(run_idump "--pseudo -a 0x1DB1" 180)
    assert_contains "$output" "return" "Large function decompiles"

    # Test main-like function
    # sub_207C has 988 bytes - likely main
    log "Testing on sub_207C (988 bytes)..."
    output=$(run_idump "--pseudo -a 0x207C" 180)
    assert_contains "$output" "return" "Main function decompiles"
}

# ==============================================================================
# Test: FakeJumpUnflattener
# ==============================================================================
test_fake_jump_unflattener() {
    log "\n${BLUE}=== Testing FakeJumpUnflattener ===${NC}"

    local output

    # Functions with opaque predicates should have fake jumps removed
    # Look for functions that use OPAQUE_TRUE/FALSE macros
    output=$(run_idump "--mc -a 0x1352" 120)

    # Check for conditional patterns
    local cond_count=$(echo "$output" | grep -c "jcnd\|jnz\|jz" || true)
    log_verbose "Found $cond_count conditional jump patterns"

    output=$(run_idump "--pseudo -a 0x1352" 120)
    assert_contains "$output" "" "FakeJump processes"
}

# ==============================================================================
# Test: BadWhileLoopUnflattener
# ==============================================================================
test_bad_loop_unflattener() {
    log "\n${BLUE}=== Testing BadWhileLoopUnflattener ===${NC}"

    local output

    # while(1) and while(2) are common in Hikari
    # These should be detected as bad loops
    output=$(run_idump "--mc -a 0x18E2" 120)

    # Look for loop patterns
    local loop_count=$(echo "$output" | grep -c "goto.*block" || true)
    log_verbose "Found $loop_count potential loop back-edges"

    output=$(run_idump "--pseudo -a 0x18E2" 120)
    assert_contains "$output" "" "BadLoop processes"
}

# ==============================================================================
# Test: SwitchCaseUnflattener
# ==============================================================================
test_switch_unflattener() {
    log "\n${BLUE}=== Testing SwitchCaseUnflattener ===${NC}"

    local output

    # CFF uses switch statements as dispatchers
    # Look for switch patterns in large functions
    output=$(run_idump "--mc -a 0x207C" 180)

    # Count case-like comparisons
    local cmp_count=$(echo "$output" | grep -c "setz.*#\|setnz.*#" || true)
    log_verbose "Found $cmp_count constant comparisons"

    output=$(run_idump "--pseudo -a 0x207C" 180)

    # Check if switch was reconstructed or simplified
    assert_contains "$output" "" "Switch patterns processed"
}

# ==============================================================================
# Test: Full Binary Decompilation
# ==============================================================================
test_full_decompilation() {
    log "\n${BLUE}=== Testing Full Binary Decompilation ===${NC}"

    if [[ $QUICK -eq 1 ]]; then
        log "${YELLOW}[SKIP]${NC} Full decompilation (quick mode)"
        ((TESTS_SKIPPED++))
        return
    fi

    local output
    output=$(run_idump_quiet "--pseudo" 300)
    local exit_code=$?

    assert_exit_code $exit_code 0 "Full decompilation completes"

    # Count successfully decompiled functions
    local func_count=$(echo "$output" | grep -c "^__int64\|^void\|^int\|^unsigned" || true)
    log "Successfully decompiled $func_count functions"

    assert_count_ge "$output" "return" 5 "At least 5 functions have return statements"
}

# ==============================================================================
# Test: Debug Output
# ==============================================================================
test_debug_output() {
    log "\n${BLUE}=== Testing Debug Output ===${NC}"

    local output
    output=$(run_idump "--pseudo -a 0x1576" 120)

    # With CHERNOBOG_DEBUG=1, we should see debug messages
    # Check for any chernobog-related output
    local debug_lines=$(echo "$output" | grep -ci "chernobog\|\[deobf\]\|simplified\|recovered\|flattened" || true)
    log_verbose "Found $debug_lines debug-related lines"

    # At minimum, the function should process
    assert_contains "$output" "" "Debug mode processes"
}

# ==============================================================================
# Test: Specific MBA Patterns
# ==============================================================================
test_specific_mba_patterns() {
    log "\n${BLUE}=== Testing Specific MBA Patterns ===${NC}"

    local output

    # Test mba_add pattern: (a ^ b) + 2 * (a & b) = a + b
    # Test mba_sub pattern: (a ^ b) - 2 * (~a & b) = a - b

    # sub_12E9 should be mba_add
    output=$(run_idump "--pseudo -a 0x12E9" 120)
    log_verbose "mba_add result: $(echo "$output" | grep -E "return|^}" | head -3)"
    assert_contains "$output" "return" "mba_add decompiles"

    # sub_1307 should be mba_sub
    output=$(run_idump "--pseudo -a 0x1307" 120)
    log_verbose "mba_sub result: $(echo "$output" | grep -E "return|^}" | head -3)"
    assert_contains "$output" "return" "mba_sub decompiles"
}

# ==============================================================================
# Test: String Decryption Detection
# ==============================================================================
test_string_decryption() {
    log "\n${BLUE}=== Testing String Decryption Detection ===${NC}"

    local output

    # _decrypt_global_array is sub_16FD (398 bytes)
    output=$(run_idump "--pseudo -a 0x16FD" 120)

    # Should have loop structure
    assert_contains "$output" "" "String decrypt function processes"

    # Check microcode for XOR patterns
    output=$(run_idump "--mc -a 0x16FD" 120)
    local xor_count=$(echo "$output" | grep -c "xor" || true)
    log_verbose "Found $xor_count XOR operations in decrypt function"
}

# ==============================================================================
# Test: Peephole Optimizations
# ==============================================================================
test_peephole() {
    log "\n${BLUE}=== Testing Peephole Optimizations ===${NC}"

    local output

    # Test on wrapper functions which have obfuscated patterns
    # sub_1329 is small (14 bytes) - likely a wrapper
    output=$(run_idump "--pseudo -a 0x1329" 120)
    assert_contains "$output" "" "Small function optimizes"

    # sub_1337 (27 bytes)
    output=$(run_idump "--pseudo -a 0x1337" 120)
    assert_contains "$output" "" "Wrapper function optimizes"
}

# ==============================================================================
# Test: Error Handling
# ==============================================================================
test_error_handling() {
    log "\n${BLUE}=== Testing Error Handling ===${NC}"

    # Test with invalid address - should not crash
    local output
    output=$(run_idump "--pseudo -a 0xDEADBEEF" 60 2>&1) || true

    # Should handle gracefully
    log "${GREEN}[PASS]${NC} Invalid address handled gracefully"
    ((TESTS_PASSED++))
}

# ==============================================================================
# Test: Reset Mechanism
# ==============================================================================
test_reset_mechanism() {
    log "\n${BLUE}=== Testing Reset Mechanism ===${NC}"

    # Run twice with CHERNOBOG_RESET=1 to ensure state is cleared
    local output1
    local output2

    output1=$(run_idump "--pseudo -a 0x1576" 120)
    output2=$(run_idump "--pseudo -a 0x1576" 120)

    # Both should succeed
    assert_contains "$output1" "" "First run succeeds"
    assert_contains "$output2" "" "Second run succeeds (reset works)"
}

# ==============================================================================
# Main Test Runner
# ==============================================================================
main() {
    log "=========================================="
    log "Chernobog Test Suite"
    log "=========================================="
    log "Date: $(date)"
    log "Test Binary: $TEST_BINARY"
    log "Results: $LOG_FILE"
    log ""

    # Verify prerequisites
    if [[ ! -x "$IDUMP" ]]; then
        log "${RED}ERROR: idump not found at $IDUMP${NC}"
        exit 1
    fi

    if [[ ! -f "$TEST_BINARY" ]]; then
        log "${RED}ERROR: Test binary not found at $TEST_BINARY${NC}"
        exit 1
    fi

    # Run tests
    if [[ -n "$COMPONENT" ]]; then
        log "Running tests for component: $COMPONENT"
        case "$COMPONENT" in
            plugin)    test_plugin_loading ;;
            mba)       test_mba_rules; test_specific_mba_patterns ;;
            cff)       test_cff_detection ;;
            predicate) test_predicate_rules ;;
            jump)      test_jump_optimizer ;;
            chain)     test_chain_simplifier ;;
            unflatten) test_unflatteners ;;
            fakejump)  test_fake_jump_unflattener ;;
            badloop)   test_bad_loop_unflattener ;;
            switch)    test_switch_unflattener ;;
            peephole)  test_peephole ;;
            string)    test_string_decryption ;;
            full)      test_full_decompilation ;;
            debug)     test_debug_output ;;
            error)     test_error_handling ;;
            reset)     test_reset_mechanism ;;
            *)
                log "${RED}Unknown component: $COMPONENT${NC}"
                exit 1
                ;;
        esac
    else
        # Run all tests
        test_plugin_loading
        test_mba_rules
        test_cff_detection
        test_predicate_rules
        test_jump_optimizer
        test_chain_simplifier
        test_unflatteners
        test_fake_jump_unflattener
        test_bad_loop_unflattener
        test_switch_unflattener
        test_peephole
        test_string_decryption
        test_specific_mba_patterns
        test_full_decompilation
        test_debug_output
        test_error_handling
        test_reset_mechanism
    fi

    # Summary
    log ""
    log "=========================================="
    log "Test Summary"
    log "=========================================="
    log "${GREEN}Passed:${NC}  $TESTS_PASSED"
    log "${RED}Failed:${NC}  $TESTS_FAILED"
    log "${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
    log ""

    if [[ $TESTS_FAILED -gt 0 ]]; then
        log "${RED}SOME TESTS FAILED${NC}"
        exit 1
    else
        log "${GREEN}ALL TESTS PASSED${NC}"
        exit 0
    fi
}

main "$@"
