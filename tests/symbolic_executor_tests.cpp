#include "deobf/analysis/z3_solver.h"
#include "deobf/analysis/opaque_eval.h"

#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <iostream>

namespace {

int failures = 0;

void check(bool condition, const char *description)
{
    if ( !condition )
    {
        std::cerr << "FAIL: " << description << '\n';
        ++failures;
    }
}

[[noreturn]] void unsupported(const char *description)
{
    std::cerr << "unsupported executor fixture operation: "
              << description << '\n';
    std::abort();
}

} // namespace

extern "C" void *chernobog_executor_hexdsp(int code, ...)
{
    // These tests construct only allocation-free register/global operands.
    // No instruction walk, decoder, memory read, or other SDK behavior is
    // supplied by this shim; an unexpected dependency aborts the test.
    if ( code != hx_mop_t_erase )
        unsupported("SDK opcode other than operand erase");
    va_list arguments;
    va_start(arguments, code);
    mop_t *operand = va_arg(arguments, mop_t *);
    va_end(arguments);
    if ( operand == nullptr
      || (operand->t != mop_z && operand->t != mop_r && operand->t != mop_v) )
        unsupported("operand with owned storage");
    operand->zero();
    return nullptr;
}

namespace deobf {
void log(const char *, ...) {}
void log_verbose(const char *, ...) {}
bool is_jcc(mcode_t) { unsupported("unrelated state-machine analysis"); }
} // namespace deobf

// These production fallbacks are unrelated to the state/query API exercised
// here. They must remain unreachable, rather than silently supplying facts.
std::optional<uint64_t> opaque_eval_t::evaluate_operand(const mop_t &)
{
    unsupported("database constant evaluation");
}

bool opaque_eval_t::evaluate_condition(minsn_t *, bool *)
{
    unsupported("database condition evaluation");
}

int main(int argc, char **argv)
{
    const bool memory_only_control = argc == 2
        && std::strcmp(argv[1], "--memory-only-control") == 0;
    if ( argc != 1 && !memory_only_control )
        return 2;

    using executor_t = z3_solver::symbolic_executor_t;
    using feasibility_t = executor_t::feasibility_t;
    z3_solver::z3_context_t context;
    context.set_timeout(1000);
    executor_t executor(context);
    mop_t recurrent_register;
    recurrent_register.make_reg(0x100, 8);
    mop_t invariant_register;
    invariant_register.make_reg(0x200, 8);
    mop_t global;
    global.t = mop_v;
    global.g = 0x10000;
    global.size = 8;

    const z3::expr entry_value = executor.evaluate_operand(recurrent_register);
    check(executor.assume(entry_value == 7), "entry constraint is accepted");
    executor.set_value(recurrent_register, context.ctx().bv_val(17, 64));
    executor.set_value(global, context.ctx().bv_val(23, 64));
    check(executor.get_value(recurrent_register).has_value()
          && executor.get_value(global).has_value(),
          "register and memory bindings exist before the recurrence boundary");

    if ( memory_only_control )
        executor.invalidate_memory_values();
    else
        executor.invalidate_all_values();
    check(!executor.get_value(recurrent_register).has_value(),
          "a recurrence boundary removes the prior register binding");
    check(!executor.get_value(global).has_value(),
          "a recurrence boundary removes the prior memory binding");

    const z3::expr current_value = executor.evaluate_operand(recurrent_register);
    const z3::expr current_memory = executor.evaluate_operand(global);
    check(executor.check_feasibility_with(entry_value != 7)
              == feasibility_t::infeasible,
          "entry assumptions survive havoc");
    check(executor.check_feasibility_with(current_value == 8)
              == feasibility_t::feasible,
          "fresh recurrence register can differ from its entry value");
    check(executor.check_feasibility_with(current_value == 9)
              == feasibility_t::feasible,
          "a temporary feasible query does not constrain the next query");
    check(executor.check_feasibility_with(current_memory == 24)
              == feasibility_t::feasible,
          "fresh recurrence memory can differ from its prior binding");
    check(executor.check_feasibility_with(current_memory != 24)
              == feasibility_t::feasible,
          "memory query conditions are not retained");
    check(executor.check_feasibility_with(z3::ugt(current_value, 7))
              == feasibility_t::feasible,
          "an unconstrained returning state can take the rejected guard edge");
    check(executor.check_feasibility_with(!z3::ugt(current_value, 7))
              == feasibility_t::feasible,
          "the guard continuation is also feasible before a uniqueness proof");

    executor.set_value(invariant_register, entry_value, true);
    check(executor.check_feasibility_with(
              executor.evaluate_operand(invariant_register) != 7)
              == feasibility_t::infeasible,
          "a separately supplied invariant can be restored after havoc");
    check(executor.check_feasibility_with(context.ctx().bool_val(false))
              == feasibility_t::infeasible,
          "a contradictory temporary condition is infeasible");
    check(executor.check_feasibility() == feasibility_t::feasible,
          "a rejected temporary condition does not poison persistent assumptions");

    check(executor.check_feasibility_with(current_value) == feasibility_t::unknown,
          "a non-Boolean query fails closed");
    z3::context foreign_context;
    check(executor.check_feasibility_with(foreign_context.bool_val(true))
              == feasibility_t::unknown,
          "a foreign-context query fails closed");
    check(executor.check_feasibility_with(z3::expr(context.ctx()))
              == feasibility_t::unknown,
          "an empty query fails closed");
    check(executor.check_feasibility() == feasibility_t::feasible,
          "invalid queries do not alter persistent feasibility");

    executor.set_value(recurrent_register, context.ctx().bv_val(3, 64));
    check(executor.check_feasibility_with(
              z3::ugt(executor.evaluate_operand(recurrent_register), 7))
              == feasibility_t::infeasible,
          "a proved in-range value excludes the rejected edge");
    check(executor.assume(entry_value != 7), "contradictory path can be represented");
    executor.invalidate_all_values();
    check(executor.check_feasibility() == feasibility_t::infeasible,
          "havoc does not turn an impossible path into a feasible one");
    check(executor.check_feasibility_with(context.ctx().bool_val(true))
              == feasibility_t::infeasible,
          "extra-condition queries respect persistent path infeasibility");

    if ( failures == 0 )
        std::cout << "symbolic executor tests: PASS (freshness and isolated queries)\n";
    return failures == 0 ? 0 : 1;
}
