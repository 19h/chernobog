#include "deobf/analysis/mba_smt.hpp"
#include "deobf/analysis/mba_cobra.hpp"
#include "deobf/analysis/mba_smt_internal.hpp"
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

Term read_register(size_t index, unsigned bits = 8) { return variable(index, bits); }

Term number(uint64_t value, unsigned bits = 8) { return constant(value, bits); }

Term add(Term a, Term b) { return expression(Op::Add, a, b); }

Term multiply(Term a, Term b) { return expression(Op::Mul, a, b); }

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

void test_cobra_boolean_selector()
{
    if (!cobra_backend::available())
    {
        check(selected_backend() == Backend::Legacy,
              "an unavailable CoBRA build selects the legacy backend");
        return;
    }
    auto program = make_program();
    const Term x = read_register(0);
    const Term selector = expression(
        Op::Not, expression(Op::And, expression(Op::Or, expression(Op::Not, x), number(86)),
                            expression(Op::Or, x, number(169))));
    program.blocks[0].statements = {Statement::assign(2, selector)};
    Options options;
    options.backend = Backend::Cobra;
    options.max_invariants = 0;
    Analysis analysis(program, options);
    const auto proposals = analysis.run();
    check(!proposals.empty() && cost(proposals.front().replacement) < cost(selector),
          "CoBRA simplifies constant-masked Boolean selectors without arithmetic nodes");
    check(analysis.verify(0, 0, expression(Op::Xor, x, number(86))) == Verdict::Verified,
          "Boolean selector retains all byte values");
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

    program.targets = {{1, 0}};
    Options cobra_options = Options::deep();
    cobra_options.backend = Backend::Cobra;
    Analysis cobra_induction(program, cobra_options);
    const auto cobra_proposals = cobra_induction.run();
    check(!cobra_proposals.empty() && cobra_proposals.front().replacement->op == Op::Constant &&
              cobra_proposals.front().replacement->value == 0,
          "CoBRA retains invariant-backed scalar constant discovery");

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

    program.targets = {{1, 0}};
    Options cobra_options = Options::deep();
    cobra_options.backend = Backend::Cobra;
    Analysis cobra_known_bits(program, cobra_options);
    const auto cobra_proposals = cobra_known_bits.run();
    check(!cobra_proposals.empty() && cobra_proposals.front().replacement->op == Op::Constant &&
              cobra_proposals.front().replacement->value == 0,
          "CoBRA retains known-bit invariant constant discovery");

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

    program.targets = {{1, 0}};
    Options cobra_options = Options::deep();
    cobra_options.backend = Backend::Cobra;
    Analysis cobra_memory(program, cobra_options);
    const auto cobra_proposals = cobra_memory.run();
    check(!cobra_proposals.empty() && cobra_proposals.front().replacement->op == Op::Constant &&
              cobra_proposals.front().replacement->value == 0,
          "CoBRA retains invariant-backed memory constant discovery");

    for (Backend backend : {Backend::Legacy, Backend::Cobra})
    {
        Options constants = Options::deep();
        constants.backend = backend;
        constants.contextual_constants_only = true;
        Analysis sequential(program, constants);
        const auto proposals = sequential.run();
        check(proposals.size() == 1 && proposals.front().replacement->op == Op::Constant &&
                  proposals.front().replacement->value == 0 &&
                  sequential.statistics().cobra.calls == 0,
              "sequential contextual mode proves the loop without algebraic generation");
    }

    Analysis analysis(program, Options::deep());
    analysis.run();

    check(analysis.verify(1, 0, number(0)) == Verdict::Verified,
          "polynomial invariants relate loop-carried byte memory");

    program.blocks.resize(4);
    program.blocks[1].edges.push_back({3, read_register(3), false});
    program.blocks[3].statements = {Statement::store(x_address, add(x, number(2)))};
    program.blocks[3].edges = {{1, {}, false}};

    Analysis cobra_invalid(program, cobra_options);
    const auto invalid_proposals = cobra_invalid.run();
    check(invalid_proposals.empty() || invalid_proposals.front().replacement->op != Op::Constant ||
              invalid_proposals.front().replacement->value != 0,
          "CoBRA rejects a constant invalidated by a second memory backedge");

    Options constants = Options::deep();
    constants.contextual_constants_only = true;
    Analysis sequential_invalid(program, constants);
    check(sequential_invalid.run().empty(),
          "sequential contextual mode rejects an invalid memory backedge");

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

void test_nested_linear_reconstruction()
{
    for (unsigned bits : {8u, 16u, 32u, 64u})
    {
        const Term x = variable(0, bits);
        const Term y = variable(1, bits);
        const Term z = variable(2, bits);
        const Term one = constant(1, bits);
        const Term two = constant(2, bits);
        const Term inverted_x = expression(Op::Not, x);
        const Term union_z = expression(Op::Or, z, inverted_x);
        const Term intersection_z = expression(Op::And, z, inverted_x);
        const Term sum = add(x, y);
        const Term carry_sum =
            add(expression(Op::Xor, x, sum), multiply(two, expression(Op::And, sum, x)));
        const Term mask = add(add(union_z, x), one);
        const Term disjoint_y =
            expression(Op::And, expression(Op::Or, y, z), expression(Op::Not, z));
        const Term nested_z = expression(Op::And, z, expression(Op::Not, mask));
        const Term combined = expression(
            Op::Sub, add(add(add(disjoint_y, carry_sum), add(add(mask, z), nested_z)), y),
            expression(Op::Or, y, z));
        Term chained = disjoint_y;
        for (const Term &term : {expression(Op::Xor, x, sum), union_z, z, x, one, nested_z, y,
                                 multiply(two, expression(Op::And, sum, x))})
        {
            chained = add(chained, term);
        }
        chained = expression(Op::Sub, chained, expression(Op::Or, y, z));

        const std::vector<std::pair<Term, Term>> cases = {
            {add(add(add(union_z, z), one), intersection_z),
             expression(Op::Sub, multiply(two, z), x)},
            {add(sum, x), add(multiply(two, x), y)},
            {expression(Op::Sub, add(add(expression(Op::And, y, expression(Op::Not, z)), y), x),
                        expression(Op::Or, y, z)),
             expression(Op::Sub, sum, z)},
            {combined, add(multiply(two, sum), z)},
            {chained, add(multiply(two, sum), z)},
            {multiply(two, combined), multiply(two, add(multiply(two, sum), z))},
        };

        for (const auto &[original, expected] : cases)
        {
            Program program = make_program(bits);
            program.blocks[0].statements = {Statement::assign(3, original)};
            Options options;
            options.max_invariants = 0;
            Analysis analysis(program, options);
            const auto proposals = analysis.run();
            check(!proposals.empty(), "nested arithmetic reconstruction produces a replacement");
            if (proposals.empty())
            {
                const auto &statistics = analysis.statistics();
                std::fprintf(stderr,
                             "Empty nested case: bits=%u original=%zu unknown=%zu "
                             "exhausted=%zu elapsed_ns=%llu stage=%u\n",
                             bits, cost(original), statistics.unknown, statistics.exhausted,
                             static_cast<unsigned long long>(statistics.elapsed_ns),
                             unsigned(statistics.cancel_stage));
            }
            if (!proposals.empty())
            {
                if (cost(proposals.front().replacement) > cost(expected))
                {
                    const auto &statistics = analysis.statistics();
                    std::fprintf(stderr,
                                 "Nested case: bits=%u original=%zu result=%zu expected=%zu "
                                 "unknown=%zu exhausted=%zu elapsed_ns=%llu\n",
                                 bits, cost(original), cost(proposals.front().replacement),
                                 cost(expected), statistics.unknown, statistics.exhausted,
                                 static_cast<unsigned long long>(statistics.elapsed_ns));
                }
                check(cost(proposals.front().replacement) <= cost(expected),
                      "nested reconstruction reaches the compact arithmetic expression");
                check(analysis.verify(0, 0, expected) == Verdict::Verified,
                      "nested reconstruction proves the expected result at the full word width");
            }
        }
    }

    // The Boolean samples of x*x and -x agree, but their word semantics do not.
    // Placing the false fit inside a larger expression exercises local admission.
    Program nonlinear = make_program(32);
    const Term x = variable(0, 32);
    const Term y = variable(1, 32);
    nonlinear.blocks[0].statements = {Statement::assign(3, add(multiply(x, x), add(y, y)))};
    // Synthesis and verification share one budget. Nonlinear search can consume
    // the normal profile before these counterexample checks on slower runners.
    Analysis analysis(nonlinear, Options::deep());
    analysis.run();
    check(analysis.verify(0, 0, add(expression(Op::Neg, x), multiply(constant(2, 32), y))) ==
              Verdict::Disproved,
          "a nested nonlinear table collision cannot enter the verified rewrite cache");

    const Term square = multiply(x, x);
    nonlinear.blocks[0].statements = {
        Statement::assign(3, add(expression(Op::Xor, x, square),
                                 multiply(constant(2, 32), expression(Op::And, x, square))))};
    Analysis nonlinear_word(nonlinear, Options::deep());
    nonlinear_word.run();
    check(nonlinear_word.verify(0, 0, constant(0, 32)) == Verdict::Disproved,
          "proof-only Boolean expansion does not treat a nonlinear word as an independent input");
}

void test_masked_flag_updates()
{
    for (unsigned bits = 8; bits <= 64; bits += 8)
    {
        const Term flags = variable(0, bits);
        const Term input = variable(1, bits);
        const Term low_flag = expression(Op::And, input, constant(1, bits));
        Term high_flag = expression(Op::Equal, expression(Op::And, input, constant(0x11, bits)),
                                    constant(0x11, bits));
        if (bits > 8)
        {
            high_flag = expression(Op::ZeroExtend, high_flag, {}, bits);
        }
        const uint64_t mask = bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1;
        const Term inserted = multiply(constant(8, bits), low_flag);
        const Term cleared = expression(Op::And, flags, constant(mask ^ 8, bits));
        const Term high_bit = expression(Op::Shl, high_flag, constant(6, 8));
        const Term original = expression(Op::Or, high_bit,
                                         expression(Op::And, expression(Op::Xor, cleared, inserted),
                                                    constant(mask ^ 0x40, bits)));
        const Term expected =
            expression(Op::Or, expression(Op::And, flags, constant(mask ^ 0x48, bits)),
                       expression(Op::Or, inserted, high_bit));
        Program program = make_program(bits);
        program.blocks[0].statements = {Statement::assign(3, original)};
        Options options;
        options.max_invariants = 0;
        Analysis analysis(program, options);
        const auto proposals = analysis.run();
        check(!proposals.empty(), "masked flag update produces a compact replacement");
        if (!proposals.empty())
        {
            check(cost(proposals.front().replacement) <= cost(expected),
                  "disjoint flag insertion merges the clearing masks");
            check(analysis.verify(0, 0, expected) == Verdict::Verified,
                  "flag update preserves all untouched bits at every scalar byte width");
        }

        // Bit 4 of this insertion overlaps a retained bit of flags. Changing
        // the XOR to OR would silently lose the toggle when both bits are set.
        const Term overlapping =
            multiply(constant(8, bits), expression(Op::And, input, constant(3, bits)));
        program.blocks[0].statements = {
            Statement::assign(3, expression(Op::Xor, cleared, overlapping))};
        Analysis overlap(program, Options::deep());
        check(overlap.verify(0, 0, expression(Op::Or, cleared, overlapping)) == Verdict::Disproved,
              "overlapping insertion bits prevent XOR-to-OR conversion");
    }
}

void verify_known_bit_certificate(const Term &value)
{
    const unsigned bits = value->bits;
    const auto known = chernobog::mba_smt::detail::known_bits(value);
    check((known.zero & known.one) == 0, "known zero and one masks are disjoint");
    Program program = make_program(bits);
    program.blocks[0].statements = {
        Statement::assign(1, expression(Op::And, value, constant(known.zero, bits))),
        Statement::assign(2, expression(Op::And, value, constant(known.one, bits)))};
    Options options;
    options.max_invariants = 0;
    Analysis certificate(program, options);
    check(certificate.verify(0, 0, constant(0, bits)) == Verdict::Verified,
          "SMT proves every inferred zero bit");
    check(certificate.verify(0, 1, constant(known.one, bits)) == Verdict::Verified,
          "SMT proves every inferred one bit");
}

void test_known_bit_certificates()
{
    for (unsigned bits : {8u, 16u, 32u, 64u})
    {
        const uint64_t sign = uint64_t{1} << (bits - 1);
        const Term low_bits = expression(Op::And, variable(0, bits), constant(0x71, bits));
        for (uint64_t forced : {uint64_t{0x80}, uint64_t{0x80} | sign})
        {
            const Term input = expression(Op::Or, low_bits, constant(forced, bits));
            for (unsigned amount : {0u, 1u, bits - 1, bits, bits + 1, 255u})
            {
                for (Op operation : {Op::Shl, Op::Shr, Op::Sar})
                {
                    const Term shifted = expression(operation, input, constant(amount, 8));
                    const auto known = chernobog::mba_smt::detail::known_bits(shifted);
                    check((known.zero | known.one) != 0,
                          "fixed shifts retain useful bits at boundaries and beyond word width");
                    verify_known_bit_certificate(shifted);
                }
            }
            for (uint64_t factor : {uint64_t{0}, uint64_t{1}, uint64_t{8}, sign})
            {
                verify_known_bit_certificate(multiply(constant(factor, bits), input));
            }
        }
        const Term unknown_sign = expression(Op::Sar, variable(0, bits), constant(255, 8));
        const auto unknown = chernobog::mba_smt::detail::known_bits(unknown_sign);
        check(unknown.zero == 0 && unknown.one == 0,
              "an unknown sign cannot become a known fill bit on oversized arithmetic shifts");
        verify_known_bit_certificate(unknown_sign);
    }
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

void check_symbolic_reduction(Program program, size_t destination, Term original, Term expected,
                              const char *description)
{
    program.blocks[0].statements = {Statement::assign(destination, original)};
    Analysis analysis(program);
    const auto proposals = analysis.run();
    check(!proposals.empty(), description);
    if (proposals.empty())
    {
        const auto &statistics = analysis.statistics();
        std::fprintf(
            stderr,
            "  width=%u cost=%zu candidates=%zu unknown=%zu exhausted=%zu elapsed_ns=%llu\n",
            original->bits, cost(original), statistics.candidates, statistics.unknown,
            statistics.exhausted, static_cast<unsigned long long>(statistics.elapsed_ns));
    }
    if (!proposals.empty())
    {
        check(cost(proposals.front().replacement) < cost(original),
              "symbolic reduction lowers the expression cost");
        check(analysis.verify(0, 0, expected) == Verdict::Verified,
              "symbolic reduction preserves the expected value for every input");
        check(analysis.verify(0, 0, constant(0, original->bits)) == Verdict::Disproved,
              "composed equality proofs do not authorize an unrelated constant");
    }
}

void test_boolean_words_and_variable_views()
{
    for (unsigned bits : {8u, 16u, 32u, 64u})
    {
        const auto x = variable(0, bits);
        const auto y = variable(1, bits);
        const auto z = variable(2, bits);
        const auto carry = multiply(constant(2, bits), expression(Op::And, x, y));
        const auto xor_mba = add(expression(Op::Sub, x, carry), y);
        check_symbolic_reduction(make_program(bits), 3, xor_mba, expression(Op::Xor, x, y),
                                 "arithmetic Boolean words reduce to XOR");

        const auto inverted = expression(Op::Or, expression(Op::Not, x), z);
        const auto direct = expression(Op::Or, x, y);
        const auto selector = expression(Op::Not, expression(Op::And, inverted, direct));
        const auto expected = expression(
            Op::Not, expression(Op::Xor, y, expression(Op::And, x, expression(Op::Xor, y, z))));
        check_symbolic_reduction(make_program(bits), 3, selector, expected,
                                 "three symbolic Boolean words admit a smaller selector");
    }

    auto program = make_program(8);
    const auto x = expression(Op::SignExtend, variable(0, 8), {}, 32);
    const auto y = expression(Op::SignExtend, variable(1, 8), {}, 32);
    const auto promoted =
        add(expression(Op::Sub, x, multiply(constant(2, 32), expression(Op::And, x, y))), y);
    check_symbolic_reduction(program, 3, expression(Op::Low, promoted, {}, 8),
                             expression(Op::Xor, variable(0, 8), variable(1, 8)),
                             "signed byte promotions retain their symbolic identities");
}

Term masked_opaque_value()
{
    const auto x = variable(0, 32);
    const auto y = variable(1, 32);
    const auto first = expression(Op::Xor, x, constant(0x393F5533, 32));
    const auto second = expression(Op::Xor, y, constant(0x5E909F27, 32));
    const auto complement = expression(Op::Xor, x, constant(0xC6C0AACC, 32));
    const auto sum = add(expression(Op::Or, first, second), complement);
    const auto product = add(multiply(constant(0x5A75D737, 32), sum), constant(0x5A75D737, 32));
    return expression(Op::Or, product, constant(0x55588C79, 32));
}

void test_symbolic_opaque_expressions()
{
    const auto value = masked_opaque_value();
    const auto complement = expression(Op::Xor, variable(0, 32), constant(0xC6C0AACC, 32));
    const auto second = expression(Op::Xor, variable(1, 32), constant(0x5E909F27, 32));
    const auto expected = expression(
        Op::Or, multiply(constant(0x5A75D737, 32), expression(Op::And, complement, second)),
        constant(0x55588C79, 32));
    check_symbolic_reduction(make_program(32), 3, value, expected,
                             "complemented symbolic words reduce inside masked arithmetic");
    auto cobra_program = make_program(32);
    cobra_program.blocks[0].statements = {Statement::assign(3, value)};
    Options cobra_options = Options::deep();
    cobra_options.backend = Backend::Cobra;
    cobra_options.max_invariants = 0;
    Analysis cobra_masked(cobra_program, cobra_options);
    const auto cobra_proposals = cobra_masked.run();
    if (cobra_proposals.empty())
        std::fprintf(
            stderr,
            "CoBRA masked diagnostics: calls=%zu proved=%zu verified=%zu unknown=%zu exhausted=%zu\n",
            cobra_masked.statistics().cobra.calls, cobra_masked.statistics().cobra.proved,
            cobra_masked.statistics().verified, cobra_masked.statistics().unknown,
            cobra_masked.statistics().exhausted);
    check(!cobra_proposals.empty() && cost(cobra_proposals.front().replacement) <= cost(expected),
          "CoBRA complemented words remain smaller under the emitted operation model");
    check(cobra_masked.verify(0, 0, expected) == Verdict::Verified,
          "CoBRA masked arithmetic retains every 32-bit valuation");

    auto predicate = make_program(32);
    predicate.widths[3] = 8;
    check_symbolic_reduction(predicate, 3, expression(Op::NotEqual, value, constant(0, 32)),
                             constant(1, 8), "masked opaque expression is provably nonzero");

    auto program = make_program(32);
    program.widths[3] = 64;
    const auto x = expression(Op::Xor, variable(0, 32), constant(0x29D81B96, 32));
    const auto y = expression(Op::Xor, variable(1, 32), constant(0x3FA3EB91, 32));
    const auto difference = expression(Op::Sub, expression(Op::Or, x, y), constant(0x1F206DED, 32));
    const auto masked = expression(Op::Or, difference, constant(0xAB597BD5, 32));
    const auto numerator = expression(Op::ZeroExtend, masked, {}, 64);
    const auto quotient = expression(Op::UnsignedDivide, numerator, constant(0x52AC7B5E, 64));
    const auto selected = expression(Op::And, difference, constant(0x50000000, 32));
    const auto upper = expression(Op::Equal, selected, constant(0x50000000, 32), 8);
    const auto result = add(constant(2, 64), expression(Op::ZeroExtend, upper, {}, 64));
    check_symbolic_reduction(program, 3, quotient, result,
                             "two-valued unsigned division becomes a two-bit test");

    program.blocks[0].statements = {Statement::assign(3, quotient)};
    Analysis reduced(program);
    const auto proposals = reduced.run();
    check(!proposals.empty() && cost(proposals.front().replacement) <= cost(result),
          "the emitted quotient drops the forced mask bits and wide comparison");

    program.blocks[0].statements = {Statement::assign(3, quotient)};
    Analysis varying(program, Options::deep());
    check(varying.verify(0, 0, constant(2, 64)) == Verdict::Disproved,
          "the quotient is not incorrectly replaced by its minimum");
    check(varying.verify(0, 0, constant(3, 64)) == Verdict::Disproved,
          "the quotient is not incorrectly replaced by its maximum");

    const auto signed_numerator = expression(Op::SignExtend, masked, {}, 64);
    program.blocks[0].statements[0].value =
        expression(Op::UnsignedDivide, signed_numerator, constant(0x52AC7B5E, 64));
    Analysis signed_input(program, Options::deep());
    check(signed_input.verify(0, 0, result) == Verdict::Disproved,
          "signed extension cannot inherit unsigned numerator bounds");

    program.blocks[0].statements[0].value =
        expression(Op::UnsignedDivide, numerator, constant(0, 64));
    check(!validate(program), "division by zero is not modeled as a total SMT operation");
    program.blocks[0].statements[0].value =
        expression(Op::UnsignedDivide, numerator, variable(3, 64));
    check(!validate(program), "unconstrained divisors retain their native fault behavior");

    auto narrow = make_program(8);
    narrow.blocks[0].statements = {
        Statement::assign(3, expression(Op::UnsignedDivide, variable(0, 8), constant(256, 8)))};
    check(!validate(narrow), "a divisor that truncates to zero is rejected");
}

void test_known_bit_thresholds()
{
    struct ThresholdCase
    {
        Op operation;
        uint64_t mask;
        uint64_t threshold;
        bool greater;
        Op comparison;
        uint64_t selected;
        uint64_t expected;
    };

    // Exercise both comparison directions and both outcomes at the first
    // differing fixed bit, including an exact threshold and bit 63.
    const ThresholdCase cases[] = {
        {Op::Or, 0xAB, 0xF8, true, Op::Equal, 0x50, 0x50},
        {Op::Or, 0xAB, 0xF8, false, Op::NotEqual, 0x50, 0x50},
        {Op::And, 0xD4, 0x20, true, Op::NotEqual, 0xC0, 0},
        {Op::And, 0xD4, 0x20, false, Op::Equal, 0xC0, 0},
        {Op::Or, 0xAB, 0xAB, true, Op::NotEqual, 0x54, 0},
        {Op::And, 0xD4, 0xD4, false, Op::NotEqual, 0xD4, 0xD4},
    };
    for (unsigned bits : {8u, 16u, 32u, 64u})
    {
        const unsigned shift = bits - 8;
        for (const ThresholdCase &test : cases)
        {
            auto program = make_program(bits);
            program.widths[3] = 8;
            const auto input = variable(0, bits);
            const auto masked =
                expression(test.operation, input, constant(test.mask << shift, bits));
            const auto threshold = constant(test.threshold << shift, bits);
            const auto original = test.greater ? expression(Op::UnsignedLess, threshold, masked, 8)
                                               : expression(Op::UnsignedLess, masked, threshold, 8);
            uint64_t selected_mask = test.selected << shift;
            if (test.operation == Op::Or && test.mask == test.threshold)
            {
                selected_mask |= (uint64_t{1} << shift) - 1;
            }
            const auto selected = expression(Op::And, input, constant(selected_mask, bits));
            const auto expected =
                expression(test.comparison, selected, constant(test.expected << shift, bits), 8);

            program.blocks[0].statements = {Statement::assign(3, original)};
            Analysis analysis(program);
            check(analysis.verify(0, 0, expected) == Verdict::Verified,
                  "known-bit threshold identity holds across scalar widths");

            if (bits < 64)
            {
                const auto widened = expression(Op::ZeroExtend, masked, {}, 64);
                const auto wide_threshold = constant(test.threshold << shift, 64);
                const auto comparison =
                    test.greater ? expression(Op::UnsignedLess, wide_threshold, widened, 8)
                                 : expression(Op::UnsignedLess, widened, wide_threshold, 8);
                check_symbolic_reduction(
                    program, 3, comparison, expected,
                    "threshold synthesis handles both directions and suffixes");
            }
        }
    }
}

void test_constant_queries()
{
    auto program = make_program(32);
    const auto input = variable(0, 32);
    program.blocks[0].statements = {Statement::assign(3, expression(Op::Xor, input, input))};
    Analysis invariant(program);
    const Term zero = invariant.constant_value(0, 0);
    check(zero && zero->op == Op::Constant && zero->value == 0,
          "constant-only query proves a value for arbitrary inputs");

    program.blocks[0].statements[0].value = input;
    Analysis varying(program);
    check(!varying.constant_value(0, 0),
          "a model's observed value cannot become a universal constant");
    check(!varying.constant_value(1, 0), "constant queries reject invalid block indices");
    check(!varying.constant_value(0, 1), "constant queries reject invalid statement indices");

    Options exhausted;
    exhausted.budget_ms = 0;
    Analysis unavailable(program, exhausted);
    check(!unavailable.constant_value(0, 0), "exhausted constant queries fail closed");
}

void test_unlowerable_proposal_continuation()
{
    auto program = make_program(32);
    const auto x = variable(0, 32), y = variable(1, 32);
    program.blocks[0].statements = {
        Statement::assign(2, add(expression(Op::Xor, x, y),
                                 multiply(constant(2, 32), expression(Op::And, x, y)))),
        Statement::assign(3, expression(Op::Xor, x, x))};
    for (Backend backend : {Backend::Legacy, Backend::Cobra})
    {
        if (backend == Backend::Cobra && !cobra_backend::available())
            continue;
        Options options = Options::deep();
        options.backend = backend;
        Analysis analysis(program, options);
        unsigned rejected = 0;
        const auto proposals = analysis.run(
            [&](const Proposal &proposal)
            {
                if (proposal.statement == 0)
                {
                    ++rejected;
                    return false;
                }
                return true;
            });
        check(rejected == 1 && proposals.size() == 1 && proposals[0].statement == 1 &&
                  proposals[0].replacement->op == Op::Constant &&
                  proposals[0].replacement->value == 0,
              "unlowerable first proposal does not hide another proved site");
        check(analysis.verify(0, 1, constant(0, 32)) == Verdict::Verified,
              "continued proposal retains its independent value proof");
    }
}
void test_post_proof_eligibility()
{
    using Clock = std::chrono::steady_clock;
    detail::SessionTestHooks hooks;
    auto time = Clock::time_point{};
    bool cancelled = false;
    hooks.now = [&] { return time; };
    struct Restore
    {
        detail::SessionTestHooks *old;
        ~Restore() { detail::session_test_hooks = old; }
    } restore{detail::session_test_hooks};
    detail::session_test_hooks = &hooks;
    Options options;
    options.budget_ms = 100;
    options.cancelled = [&] { return cancelled; };
    Statistics statistics;
    detail::SolverSession session(options, statistics);
    check(session.remaining_budget(time) == std::chrono::milliseconds(100),
          "session exposes exact remaining budget");
    check(session.remaining_budget(session.deadline()) == std::chrono::nanoseconds(0),
          "expiry is inclusive");
    check(session.remaining_budget(session.deadline() + std::chrono::seconds(1)).count() == 0,
          "remaining budget clamps to zero");
    z3::solver solver(session.context);
    solver.add(session.context.bool_val(false));
    hooks.after_query = [&](const char *, const z3::check_result &) { cancelled = true; };
    Statistics cancellation_statistics;
    detail::SolverSession cancellation_session(options, cancellation_statistics);
    z3::solver cancellation_solver(cancellation_session.context);
    cancellation_solver.add(cancellation_session.context.bool_val(false));
    check(cancellation_session.check(cancellation_solver, "post-poll cancellation") == z3::unknown,
          "late cancellation rejects observed UNSAT");
    check(cancellation_statistics.cancel_stage == RejectReason::PostProofExpiry,
          "post-proof rejection records its stage");
    cancelled = false;
    hooks.after_query = [&](const char *, const z3::check_result &)
    { time += std::chrono::milliseconds(150); };
    check(session.check(solver, "post-poll scheduling pause") == z3::unknown,
          "150 ms pause exhausts 100 ms allowance");
    check(statistics.deadline_overshoot_ns == 50000000, "overshoot is recorded in nanoseconds");
    check(!session.eligible_for_commit(), "strict commit rejects deadline expiry");
    check(session.eligible_for_commit(true),
          "tagged preverified legacy fallback waives only deadline");
    cancelled = true;
    check(!session.eligible_for_commit(true), "legacy fallback never waives cancellation");
    cancelled = false;
    Statistics snapshot_statistics;
    detail::SolverSession snapshot_session(options, snapshot_statistics);
    check(!snapshot_session.eligible_for_commit(true, [] { return false; }),
          "legacy fallback never waives snapshot mismatch");

    time = Clock::time_point{};
    hooks.after_query = {};
    options.cancelled = [&]
    {
        time += std::chrono::milliseconds(150);
        return false;
    };
    Statistics callback_statistics;
    detail::SolverSession callback_session(options, callback_statistics);
    check(!callback_session.has_budget(), "callback time is charged before clock eligibility");
    options.cancelled = []() -> bool { throw std::runtime_error("callback"); };
    Statistics failure_statistics;
    detail::SolverSession failure_session(options, failure_statistics);
    check(!failure_session.has_budget() &&
              failure_statistics.cancel_stage == RejectReason::CallbackFailure,
          "callback failure retains the original");
}

void test_cancellation_latch()
{
    unsigned polls = 0;
    bool cancelled = false;
    Options options;
    options.cancelled = [&]
    {
        ++polls;
        return cancelled;
    };
    Statistics statistics;
    detail::SolverSession session(options, statistics);
    check(session.has_budget() && polls == 1, "session polls host cancellation at entry");
    cancelled = true;
    check(!session.has_budget() && polls == 2, "session immediately observes cancellation");
    cancelled = false;
    check(session.is_cancelled() && !session.has_budget() && polls == 2,
          "observed cancellation cannot be lost when a host callback resets");
    check(!session.eligible_for_commit(true), "legacy expiry exemption cannot resume cancellation");
}

void test_cobra_word_proof_cancellation()
{
    if (!cobra_backend::available())
        return;
    auto program = make_program(32);
    const auto x = variable(0, 32), y = variable(1, 32);
    program.blocks[0].statements = {Statement::assign(
        2, add(expression(Op::Xor, x, y), multiply(constant(2, 32), expression(Op::And, x, y))))};
    bool cancelled = false, observed_word_proof = false;
    detail::SessionTestHooks hooks;
    hooks.after_query = [&](const char *purpose, const z3::check_result &observed)
    {
        if (std::string(purpose) == "MBA Boolean word identity" && observed == z3::unsat)
            cancelled = observed_word_proof = true;
    };
    struct Restore
    {
        detail::SessionTestHooks *old;
        ~Restore() { detail::session_test_hooks = old; }
    } restore{detail::session_test_hooks};
    detail::session_test_hooks = &hooks;
    Options options;
    options.backend = Backend::Cobra;
    options.max_invariants = 0;
    options.cancelled = [&] { return cancelled; };
    Analysis analysis(program, options);
    check(analysis.run().empty() && observed_word_proof && analysis.statistics().cobra.calls == 0,
          "late word-theorem cancellation cannot authorize generation or a replacement");
    check(analysis.statistics().last_solver_observed == 2 &&
              !analysis.statistics().last_solver_usable,
          "word-theorem observation and eligibility remain distinct");
}

} // namespace

int main()
{
    test_scalar_identity_synthesis();
    test_cobra_boolean_selector();
    test_joins_and_memory();
    test_polynomial_loop();
    test_known_bits_loop();
    test_memory_polynomial_loop();
    test_intervening_register_write();
    test_linear_reconstruction_and_false_fit();
    test_nested_linear_reconstruction();
    test_masked_flag_updates();
    test_known_bit_certificates();
    test_guards_and_aliasing();
    test_partial_registers_and_endianness();
    test_failures_and_profiles();
    test_boolean_words_and_variable_views();
    test_symbolic_opaque_expressions();
    test_known_bit_thresholds();
    test_constant_queries();
    test_unlowerable_proposal_continuation();
    test_post_proof_eligibility();
    test_cancellation_latch();
    test_cobra_word_proof_cancellation();
    std::printf("MBA SMT failures: %d\n", failures);
    return failures != 0;
}
