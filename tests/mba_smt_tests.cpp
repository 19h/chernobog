#include "deobf/analysis/mba_smt.hpp"
#include <cstdio>
#include <stdexcept>

using namespace chernobog::mba_smt;

namespace
{
int failures = 0;

void check(bool ok, const char *description)
{
    if (!ok)
    {
        std::fprintf(stderr, "FAIL: %s\n", description);
        ++failures;
    }
}

Term read_register(size_t index, unsigned bits = 8)
{
    return variable(index, bits);
}

Term number(uint64_t value, unsigned bits = 8)
{
    return constant(value, bits);
}

Term add(Term a, Term b)
{
    return expression(Op::Add, a, b);
}

Term multiply(Term a, Term b)
{
    return expression(Op::Mul, a, b);
}

Program make_program(unsigned bits = 8)
{
    Program program;
    program.address_bits = 32;
    program.widths = {bits, bits, bits, bits};
    program.blocks.resize(1);
    return program;
}

void test_scalar_identity_synthesis()
{
    for (unsigned bits = 8; bits <= 64; bits += 8)
    {
        auto program = make_program(bits);
        auto x = read_register(0, bits), y = read_register(1, bits);
        program.blocks[0].statements.push_back(
            Statement::assign(2, add(expression(Op::Xor, x, y),
                                     multiply(number(2, bits), expression(Op::And, x, y)))));
        Analysis engine(program, Options::deep());
        auto proposals = engine.run();
        check(!proposals.empty(), "discover carry identity at each scalar byte width");
        if (!proposals.empty())
        {
            check(engine.verify(0, 0, proposals.front().replacement) == Verdict::Verified,
                  "emitted candidate is verified again");
            check(engine.verify(0, 0, number(0, bits)) == Verdict::Disproved,
                  "incorrect constant has a counterexample");
        }
    }
}

void test_joins_and_memory()
{
    auto program = make_program();
    program.blocks.resize(4);
    program.blocks[0].edges = {{1, read_register(3), false}, {2, read_register(3), true}};
    program.blocks[1].statements = {Statement::assign(2, add(read_register(0), read_register(1)))};
    program.blocks[2].statements = {Statement::assign(2, add(read_register(1), read_register(0)))};
    program.blocks[1].edges = {{3, {}, false}};
    program.blocks[2].edges = {{3, {}, false}};
    program.blocks[3].statements = {
        Statement::assign(3, expression(Op::Sub, read_register(2), read_register(0)))};

    Analysis joins(program, Options::deep());
    joins.run();

    check(joins.verify(3, 0, read_register(1)) == Verdict::Verified,
          "join includes both incoming assignments");
    program.blocks[2].statements[0] = Statement::assign(2, add(read_register(0), number(7)));

    Analysis unequal(program, Options::deep());
    unequal.run();

    check(unequal.verify(3, 0, read_register(1)) != Verdict::Verified,
          "one favorable incoming path cannot authorize a rewrite");

    auto memory = make_program();
    memory.blocks[0].statements = {
        Statement::store(number(4096, 32), number(0x1234, 16)),
        Statement::store(number(4097, 32), number(0xAB)),
        Statement::assign(0, expression(Op::Low, load(number(4096, 32), 16), {}, 8))};

    Analysis bytes(memory, Options::deep());
    bytes.run();

    check(bytes.verify(0, 2, number(0x34)) == Verdict::Verified,
          "partial stores preserve low byte");
    memory.blocks[0].statements.push_back(Statement::store(read_register(3, 8), number(0)));
    check(!validate(memory), "invalid pointer width is rejected");
}

void test_polynomial_loop()
{
    auto program = make_program();
    program.blocks.resize(3);
    program.blocks[0].statements = {
        Statement::assign(1, multiply(read_register(0), read_register(0)))};
    program.blocks[0].edges = {{1, {}, false}};
    program.blocks[1].statements = {Statement::assign(
        2, expression(Op::Sub, read_register(1), multiply(read_register(0), read_register(0))))};
    program.blocks[1].edges = {{2, read_register(3), false}};
    program.blocks[2].statements = {
        Statement::assign(
            1, add(read_register(1), add(multiply(number(2), read_register(0)), number(1)))),
        Statement::assign(0, add(read_register(0), number(1)))};
    program.blocks[2].edges = {{1, {}, false}};

    Analysis induction(program, Options::deep());
    induction.run();

    check(induction.verify(1, 0, number(0)) == Verdict::Verified,
          "quadratic invariant holds for arbitrary iterations and overflow");
    program.blocks[2].statements[0] = Statement::assign(1, add(read_register(1), number(1)));

    Analysis broken(program, Options::deep());
    broken.run();

    check(broken.verify(1, 0, number(0)) != Verdict::Verified,
          "invalid induction step is rejected");
    program.blocks[0].statements.clear();

    Analysis missing_base(program, Options::deep());
    missing_base.run();

    check(missing_base.verify(1, 0, number(0)) != Verdict::Verified,
          "missing initiation is rejected");
}

void test_known_bits_loop()
{
    auto program = make_program();
    program.blocks.resize(3);
    program.blocks[0].statements = {
        Statement::assign(0, expression(Op::And, read_register(0), number(0xF0)))};
    program.blocks[0].edges = {{1, {}, false}};

    program.blocks[1].statements = {
        Statement::assign(1, expression(Op::And, read_register(0), number(0x0F)))};
    program.blocks[1].edges = {{2, read_register(3), false}};
    program.blocks[2].statements = {
        Statement::assign(0, expression(Op::And, add(read_register(0), number(16)), number(0xF0)))};
    program.blocks[2].edges = {{1, {}, false}};

    Analysis analysis(program, Options::deep());
    analysis.run();

    check(analysis.verify(1, 0, number(0)) == Verdict::Verified,
          "known-bit invariants survive modular loop updates");
}

void test_memory_polynomial_loop()
{
    auto program = make_program();
    program.blocks.resize(3);
    const Term x_address = number(4096, 32);
    const Term square_address = number(4104, 32);
    const Term x = load(x_address, 8);
    const Term square = load(square_address, 8);

    program.blocks[0].statements = {
        Statement::store(x_address, read_register(0)),
        Statement::store(square_address, multiply(read_register(0), read_register(0)))};
    program.blocks[0].edges = {{1, {}, false}};
    program.blocks[1].statements = {
        Statement::assign(2, expression(Op::Sub, square, multiply(x, x)))};
    program.blocks[1].edges = {{2, read_register(3), false}};
    program.blocks[2].statements = {
        Statement::store(square_address, add(square, add(multiply(number(2), x), number(1)))),
        Statement::store(x_address, add(x, number(1)))};
    program.blocks[2].edges = {{1, {}, false}};

    Analysis analysis(program, Options::deep());
    analysis.run();

    check(analysis.verify(1, 0, number(0)) == Verdict::Verified,
          "polynomial invariants relate loop-carried byte memory");

    program.blocks.resize(4);
    program.blocks[1].edges.push_back({3, read_register(3), false});
    program.blocks[3].statements = {Statement::store(x_address, add(x, number(2)))};
    program.blocks[3].edges = {{1, {}, false}};

    Analysis invalid_backedge(program, Options::deep());
    invalid_backedge.run();

    check(invalid_backedge.verify(1, 0, number(0)) != Verdict::Verified,
          "every backedge must preserve a memory invariant");
}

void test_intervening_register_write()
{
    auto program = make_program();
    program.blocks[0].statements = {
        Statement::assign(2, read_register(0)),
        Statement::assign(0, add(read_register(0), number(1))),
        Statement::assign(3, expression(Op::Sub, read_register(0), read_register(2)))};

    Analysis analysis(program, Options::deep());
    analysis.run();

    check(analysis.verify(0, 2, number(1)) == Verdict::Verified,
          "register snapshots retain values across an intervening write");
    check(analysis.verify(0, 2, number(0)) == Verdict::Disproved,
          "an overwritten register cannot be equated with its earlier snapshot");
}

void test_linear_reconstruction_and_false_fit()
{
    auto program = make_program();
    const Term x = read_register(0);
    const Term y = read_register(1);
    const Term encoded_sum = add(multiply(number(37), expression(Op::Xor, x, y)),
                                 multiply(number(74), expression(Op::And, x, y)));
    const Term expression_value = expression(Op::Sub, encoded_sum, multiply(number(36), add(x, y)));
    program.blocks[0].statements = {Statement::assign(2, expression_value)};

    Analysis linear(program, Options::deep());
    const auto proposals = linear.run();
    check(!proposals.empty(), "linear MBA reconstruction removes unrelated modular coefficients");
    check(linear.verify(0, 0, add(x, y)) == Verdict::Verified,
          "reconstructed addition holds outside Boolean samples");

    program.blocks[0].statements = {Statement::assign(2, multiply(x, x))};
    Analysis nonlinear(program, Options::deep());
    nonlinear.run();

    check(nonlinear.verify(0, 0, expression(Op::Neg, x)) == Verdict::Disproved,
          "a nonlinear Boolean-table collision is not accepted as an identity");
}

void test_guards_and_aliasing()
{
    auto program = make_program();
    program.blocks.resize(2);
    program.blocks[0].edges = {{1, expression(Op::Equal, read_register(0), number(7)), false}};
    program.blocks[1].statements = {Statement::assign(2, add(read_register(0), number(1)))};

    Analysis guarded(program, Options::deep());
    guarded.run();

    check(guarded.verify(1, 0, number(8)) == Verdict::Verified,
          "branch facts specialize only dominated sites");
    auto memory = make_program();
    memory.widths = {8, 32, 32, 8};
    memory.blocks[0].statements = {Statement::store(read_register(1, 32), number(7)),
                                   Statement::store(read_register(2, 32), number(9)),
                                   Statement::assign(0, load(read_register(1, 32), 8))};

    Analysis alias(memory, Options::deep());
    alias.run();

    check(alias.verify(0, 2, number(7)) == Verdict::Disproved,
          "symbolic aliases prevent stale load forwarding");
    memory.blocks.resize(2);
    memory.blocks[0].statements.clear();
    memory.blocks[0].edges = {
        {1, expression(Op::NotEqual, read_register(1, 32), read_register(2, 32)), false}};
    memory.blocks[1].statements = {Statement::store(read_register(1, 32), number(7)),
                                   Statement::store(read_register(2, 32), number(9)),
                                   Statement::assign(0, load(read_register(1, 32), 8))};

    Analysis disjoint(memory, Options::deep());
    disjoint.run();

    check(disjoint.verify(1, 2, number(7)) == Verdict::Verified,
          "proved byte disjointness permits memory reasoning");
    auto clobber = make_program();
    clobber.blocks[0].statements = {Statement::store(number(4096, 32), number(7)),
                                    Statement::havoc(),
                                    Statement::assign(0, load(number(4096, 32), 8))};

    Analysis spoiled(clobber, Options::deep());
    spoiled.run();

    check(spoiled.verify(0, 2, number(7)) == Verdict::Disproved,
          "unknown call clobbers memory contents");
}

void test_partial_registers_and_endianness()
{
    Program program;
    program.widths = {32, 8};
    program.blocks.resize(1);
    auto write = Statement::assign(0, number(0xAB));
    write.offset = 8;
    program.blocks[0].statements = {
        write,
        Statement::assign(
            1, expression(Op::Low, expression(Op::High, read_register(0, 32), {}, 24), {}, 8))};

    Analysis partial(program, Options::deep());
    partial.run();

    check(partial.verify(0, 1, number(0xAB)) == Verdict::Verified,
          "byte writes update the overlapping register view");
    auto memory = make_program();
    memory.big_endian = true;
    memory.blocks[0].statements = {Statement::store(number(4096, 32), number(0x1234, 16)),
                                   Statement::assign(0, load(number(4096, 32), 8))};

    Analysis big(memory, Options::deep());
    big.run();

    check(big.verify(0, 1, number(0x12)) == Verdict::Verified,
          "big-endian memory preserves target byte order");
    auto unknown = Options::deep();
    unknown.resource_limit = 1;
    auto difficult = make_program(64);
    difficult.blocks[0].statements = {
        Statement::assign(2, multiply(read_register(0, 64), read_register(1, 64)))};

    Analysis limited(difficult, unknown);
    limited.run();

    check(limited.verify(0, 0, number(0, 64)) != Verdict::Verified,
          "resource UNKNOWN never admits equality");
}

void test_failures_and_profiles()
{
    check(Options{}.budget_ms == 1000 && Options::deep().budget_ms == 30000,
          "normal and deep budgets are one and thirty seconds");
    auto program = make_program();
    program.blocks[0].statements = {
        Statement::assign(2, expression(Op::Xor, read_register(0), read_register(0)))};
    auto options = Options{};
    options.budget_ms = 0;

    Analysis exhausted(program, options);
    check(exhausted.run().empty(), "zero budget cannot authorize a proposal");
    check(exhausted.verify(0, 0, number(0)) != Verdict::Verified,
          "verification cannot escape exhausted shared budget");
    options = Options{};
    options.cancelled = [] { return true; };

    Analysis cancelled(program, options);
    check(cancelled.run().empty(), "cancellation retains the original");
    program.blocks[0].statements[0].value = add(read_register(0), number(1, 16));
    check(!validate(program), "implicit width conversion rejects malformed input");
}
} // namespace

int main()
{
    test_scalar_identity_synthesis();
    test_joins_and_memory();
    test_polynomial_loop();
    test_known_bits_loop();
    test_memory_polynomial_loop();
    test_intervening_register_write();
    test_linear_reconstruction_and_false_fit();
    test_guards_and_aliasing();
    test_partial_registers_and_endianness();
    test_failures_and_profiles();
    std::printf("MBA SMT failures: %d\n", failures);
    return failures != 0;
}
