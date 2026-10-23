#include "mba_backend_selection.hpp"
#include "deobf/analysis/mba_smt.hpp"
#include "deobf/analysis/mba_cobra.hpp"
#include "deobf/analysis/mba_smt_internal.hpp"
#include "deobf/analysis/mba_smt_word_view.hpp"
#include <cstdio>
#include <cstring>
#include <stdexcept>

using namespace chernobog::mba_smt;

namespace
{
int failures = 0;
unsigned compound_width = 0;

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

void test_masked_difference_sum()
{
    for (Backend backend : {Backend::Legacy, Backend::Cobra})
    {
        if (backend == Backend::Cobra && !cobra_backend::available())
            continue;
        for (unsigned bits : {8u, 16u, 32u, 64u})
        {
            for (bool reassociate : {false, true})
            {
                for (uint64_t allowed : {UINT64_MAX, UINT64_MAX - 3, uint64_t{0x5A}})
                {
                    auto program = make_program(bits);
                    const Term x = read_register(0, bits);
                    const uint64_t c = 0x4CEA06F4;
                    const uint64_t d = ~c & allowed;
                    const Term disjunction = expression(Op::Or, x, number(c, bits));
                    const Term conjunction = expression(Op::And, x, number(d, bits));
                    const Term original =
                        reassociate ? expression(Op::Sub, add(disjunction, conjunction), x)
                                    : add(expression(Op::Sub, disjunction, x), conjunction);
                    program.blocks[0].statements = {Statement::assign(2, original)};
                    Options options = Options::deep();
                    options.backend = backend;
                    options.max_invariants = 0;
                    Analysis analysis(program, options);
                    const auto proposals = analysis.run();
                    check(!proposals.empty() &&
                              cost(proposals.front().replacement) < cost(original),
                          "masked subtraction sum reduces with complete and partial masks");
                    const Term expected = expression(
                        Op::Xor, expression(Op::And, x, number(c ^ d, bits)), number(c, bits));
                    check(analysis.verify(0, 0, expected) == Verdict::Verified,
                          "masked subtraction sum is proved at every scalar width");
                    check(analysis.verify(0, 0, add(expected, number(1, bits))) ==
                              Verdict::Disproved,
                          "a changed masked-subtraction result has a counterexample");
                }
            }
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
    check(analysis.statistics().cobra.calls != 0,
          "legacy selector templates cannot supply the CoBRA backend's candidate");
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

void test_unconditional_chains()
{
    for (Backend backend : {Backend::Legacy, Backend::Cobra})
    {
        if (backend == Backend::Cobra && !cobra_backend::available())
            continue;
        Options options = Options::deep();
        options.backend = backend;
        auto program = make_program();
        program.blocks.resize(3);
        program.entry = 2;
        program.blocks[2].edges = {{0, {}, false}};
        program.blocks[0].edges = {{1, {}, false}};
        const Term x = read_register(0);
        program.blocks[0].statements = {Statement::assign(2, expression(Op::Xor, x, x))};
        Analysis wrappers(program, options);
        check(!wrappers.run().empty() && wrappers.statistics().invariant_candidates == 0,
              "empty unconditional wrappers need no invariant search");
        check(wrappers.verify(0, 0, number(0)) == Verdict::Verified &&
                  wrappers.verify(0, 0, number(1)) == Verdict::Disproved,
              "wrapper fast path retains independent replacement proofs");

        program.blocks[2].statements = {Statement::assign(0, number(7))};
        program.blocks[0].statements = {Statement::assign(2, expression(Op::Sub, x, number(7)))};
        Analysis assignments(program, options);
        assignments.run();
        check(assignments.statistics().invariant_candidates == 0 &&
                  assignments.verify(0, 0, number(0)) == Verdict::Verified &&
                  assignments.verify(0, 0, number(1)) == Verdict::Disproved,
              "unconditional chain executes predecessor assignments exactly");

        auto overwritten = program;
        overwritten.blocks[0].statements.insert(overwritten.blocks[0].statements.begin(),
                                                Statement::assign(0, number(9)));
        Analysis overwrite_analysis(overwritten, options);
        check(overwrite_analysis.verify(0, 1, number(2)) == Verdict::Verified &&
                  overwrite_analysis.verify(0, 1, number(0)) == Verdict::Disproved,
              "chain snapshots retain writes after a predecessor assignment");

        auto spoiled = program;
        spoiled.blocks[0].statements.insert(spoiled.blocks[0].statements.begin(),
                                            Statement::havoc({0}));
        Analysis spoiled_analysis(spoiled, options);
        check(spoiled_analysis.verify(0, 1, number(0)) == Verdict::Disproved,
              "chain havoc invalidates a predecessor register fact");

        auto memory = program;
        const Term address = number(4096, 32);
        memory.blocks[2].statements = {Statement::store(address, number(0x42))};
        memory.blocks[0].statements = {Statement::assign(2, load(address, 8))};
        Analysis memory_analysis(memory, options);
        check(memory_analysis.verify(0, 0, number(0x42)) == Verdict::Verified &&
                  memory_analysis.verify(0, 0, number(0x43)) == Verdict::Disproved &&
                  memory_analysis.statistics().invariant_candidates == 0,
              "chain forwards the exact predecessor memory array");
        memory.blocks[0].statements.insert(memory.blocks[0].statements.begin(),
                                           Statement::havoc({0}));
        Analysis clobbered_memory(memory, options);
        check(clobbered_memory.verify(0, 1, number(0x42)) == Verdict::Disproved,
              "chain havoc invalidates predecessor memory even with a scalar spoil list");

        program.blocks[2].statements.clear();
        program.blocks[2].edges[0].condition = expression(Op::Equal, x, number(7), 8);
        Analysis guarded(program, options);
        guarded.run();
        check(guarded.statistics().invariant_candidates > 0 &&
                  guarded.verify(0, 0, number(0)) == Verdict::Verified &&
                  guarded.verify(0, 0, number(1)) == Verdict::Disproved,
              "guarded empty wrappers retain their proved path constraints");

        program.blocks[2].edges[0].condition = {};
        program.blocks.resize(4);
        Analysis disconnected(program, options);
        disconnected.run();
        check(disconnected.statistics().invariant_candidates > 0 &&
                  disconnected.verify(0, 0, number(0)) == Verdict::Disproved,
              "an additional disconnected block does not authorize a contextual constant");
    }
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

    auto narrow_program = make_program(32);
    const auto narrow_quotient = expression(Op::UnsignedDivide, masked, constant(0x52AC7B5E, 32));
    narrow_program.blocks[0].statements = {Statement::assign(3, narrow_quotient)};
    const auto narrow_result = add(constant(2, 32), expression(Op::ZeroExtend, upper, {}, 32));
    for (Backend backend : {Backend::Legacy, Backend::Cobra})
    {
        if (backend == Backend::Cobra && !cobra_backend::available())
            continue;
        for (bool deep : {false, true})
        {
            Options options = deep ? Options::deep() : Options{};
            options.backend = backend;
            Analysis narrow(narrow_program, options);
            const auto candidates = narrow.run();
            check(candidates.size() == 1 && key(candidates[0].replacement) == key(narrow_result) &&
                      cost(candidates[0].replacement) < cost(narrow_quotient),
                  "32-bit quotient retains the equal-cost local two-bit predicate");
            check(narrow.verify(0, 0, narrow_result) == Verdict::Verified,
                  "the narrowed quotient is independently proved for every input");
        }
    }

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

void test_boolean_operand_complements()
{
    const auto x = variable(0, 32), y = variable(1, 32), z = variable(2, 32);
    const auto sum = add(x, y);
    Term body = add(multiply(constant(2, 32), expression(Op::And, x, sum)),
                    expression(Op::And, expression(Op::Not, expression(Op::And, z, x)), z));
    for (const Term &part :
         {expression(Op::Xor, x, sum), y, z, x, expression(Op::Or, expression(Op::Not, x), z),
          expression(Op::And, expression(Op::Not, z), expression(Op::Or, z, y)), constant(1, 32)})
        body = add(body, part);
    body = expression(Op::Sub, body, expression(Op::Or, z, y));
    const auto original = expression(Op::ZeroExtend, multiply(constant(2, 32), body), {}, 64);
    const auto expected = expression(
        Op::ZeroExtend, multiply(constant(2, 32), add(z, multiply(constant(2, 32), sum))), {}, 64);
    for (Backend backend : {Backend::Legacy, Backend::Cobra})
    {
        if (backend == Backend::Cobra && !cobra_backend::available())
            continue;
        for (bool deep : {false, true})
        {
            auto program = make_program(32);
            program.widths[3] = 64;
            program.blocks[0].statements = {Statement::assign(3, original)};
            Options options = deep ? Options::deep() : Options{};
            options.backend = backend;
            unsigned word_proofs = 0;
            detail::SessionTestHooks hooks;
            hooks.after_query = [&](const char *purpose, const z3::check_result &)
            {
                if (std::string(purpose) == "MBA Boolean word identity")
                    ++word_proofs;
            };
            struct Restore
            {
                detail::SessionTestHooks *previous;
                ~Restore() { detail::session_test_hooks = previous; }
            } restore{detail::session_test_hooks};
            detail::session_test_hooks = &hooks;
            Analysis analysis(program, options);
            check(!analysis.constant_value(0, 0) && word_proofs != 0,
                  "constant and fallback proofs prepare unconditional word identities first");
            const auto prepared_proofs = word_proofs;
            check(!analysis.constant_value(0, 0) && word_proofs == prepared_proofs,
                  "repeated queries reuse only same-session universal word proofs");
            const auto proposals = analysis.run();
            check(!proposals.empty() && cost(proposals.front().replacement) < cost(original),
                  "Boolean operand complements reduce within both profile budgets");
            check(analysis.verify(0, 0, expected) == Verdict::Verified &&
                      analysis.verify(0, 0, constant(0, 64)) == Verdict::Disproved,
                  "complement composition retains wrapping and its outer conversion");
        }
    }
}

void test_verified_complement_normalization()
{
    for (unsigned bits = 8; bits <= 64; bits += 8)
    {
        auto program = make_program(bits);
        Options options = Options::deep();
        Statistics statistics;
        detail::SolverSession session(options, statistics);
        detail::SymbolicProgram symbolic(program, session);
        symbolic.build();
        const auto &state = symbolic.block_entry(0);
        const auto x = symbolic.evaluate(variable(0, bits), state);
        const auto y = symbolic.evaluate(variable(1, bits), state);
        const auto original = ~((~x) | ~(x + y));
        const auto alternate = ~((-x - 1) | ~(x + y));
        check(z3::eq(symbolic.canonicalize_verified_complements(original), original),
              "an unproved complement theorem cannot normalize proof expressions");

        z3::solver theorem(session.context);
        theorem.add(~x != -x - 1);
        const bool proved = session.check(theorem, "MBA Boolean word identity") == z3::unsat;
        check(proved, "complement theorem is independently UNSAT at each byte width");
        if (!proved)
            continue;
        symbolic.verified_word_laws.insert({bits, detail::WordLaw::Invert});
        check(z3::eq(symbolic.apply_verified_rewrites(original), original),
              "final proof normalization cannot change retained-equality matching keys");
        const auto normalized = symbolic.canonicalize_verified_complements(original);
        check(z3::eq(normalized, symbolic.canonicalize_verified_complements(alternate)),
              "new complemented words share one canonical proof expression");
        z3::solver independent(session.context);
        independent.add(original != normalized);
        check(session.check(independent, "independent complement normalization") == z3::unsat,
              "canonicalization preserves the complete original bit-vector value");
        z3::solver corrupted(session.context);
        corrupted.add(normalized != symbolic.canonicalize_verified_complements(alternate + 1));
        check(session.check(corrupted, "corrupted complement normalization") == z3::sat,
              "canonicalization retains counterexamples for a corrupt replacement");
        const unsigned other_bits = bits == 64 ? 56 : 64;
        const auto other = ~session.fresh_value(other_bits);
        check(z3::eq(symbolic.canonicalize_verified_complements(other), other),
              "a complement proof cannot cross its proved scalar width");
    }
}

void test_legacy_masked_selectors()
{
    for (unsigned bits = 8; bits <= 64; bits += 8)
    {
        const uint64_t mask = bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1;
        const auto x = variable(0, bits);
        const auto literal = constant(UINT64_C(0xA35AA53C5AA55A56) & mask, bits);
        const auto opposite = constant(literal->value ^ mask, bits);
        const auto expected = expression(Op::Xor, x, literal);
        for (bool disjunctive : {false, true})
        {
            const auto negated =
                disjunctive ? expression(Op::Xor, x, constant(mask, bits)) : expression(Op::Not, x);
            const auto first = expression(disjunctive ? Op::And : Op::Or, negated, literal);
            const auto second = expression(disjunctive ? Op::And : Op::Or, opposite, x);
            const auto original = disjunctive
                                      ? expression(Op::Or, second, first)
                                      : expression(Op::Not, expression(Op::And, first, second));
            auto program = make_program(bits);
            program.blocks[0].statements = {Statement::assign(3, original)};
            Options options;
            options.backend = Backend::Legacy;
            options.max_candidates = 1;
            Analysis analysis(program, options);
            const auto proposals = analysis.run();
            check(!proposals.empty() && cost(proposals.front().replacement) <= 1,
                  "masked selector reduces at every width without general grammar enumeration");
            const auto candidate = analysis.prove_candidate(0, 0, expected);
            check(candidate && analysis.prove_emission(*candidate, expected),
                  "masked selector crosses both independent proof boundaries");

            const auto wrong_mask = constant(opposite->value ^ 1, bits);
            program.blocks[0].statements[0].value = expression(
                Op::Not, expression(Op::And, expression(Op::Or, expression(Op::Not, x), literal),
                                    expression(Op::Or, x, wrong_mask)));
            Analysis near_match(program, options);
            check(near_match.verify(0, 0, expected) == Verdict::Disproved,
                  "a near-complementary mask retains an XOR counterexample");
            const auto selected =
                expression(Op::And, x, constant((literal->value ^ wrong_mask->value) & mask, bits));
            const auto partial_expected =
                expression(Op::Xor, selected, constant(wrong_mask->value ^ mask, bits));
            const auto partial = near_match.run();
            check(!partial.empty() && cost(partial.front().replacement) <= 2 &&
                      near_match.verify(0, 0, partial_expected) == Verdict::Verified,
                  "partial selector masks retain their fixed output bits");
        }
    }

    auto program = make_program(32);
    const auto byte = expression(Op::Low, variable(0, 32), {}, 8);
    const auto promoted = expression(Op::SignExtend, byte, {}, 32);
    const auto selector = expression(
        Op::Not,
        expression(Op::And, expression(Op::Or, expression(Op::Not, promoted), constant(86, 32)),
                   expression(Op::Or, promoted, constant(UINT64_C(0xFFFFFFA9), 32))));
    const auto original = expression(Op::ZeroExtend, expression(Op::Low, selector, {}, 8), {}, 32);
    const auto expected =
        expression(Op::ZeroExtend, expression(Op::Xor, byte, constant(86, 8)), {}, 32);
    program.blocks[0].statements = {Statement::assign(3, original)};
    Options options;
    options.backend = Backend::Legacy;
    options.max_candidates = 1;
    Analysis analysis(program, options);
    check(!analysis.run().empty() && analysis.verify(0, 0, expected) == Verdict::Verified,
          "selector reconstruction preserves sign extension and the narrow return boundary");
}

void test_small_linear_word_boundaries()
{
    for (unsigned bits : {8u, 16u, 24u, 32u})
    {
        const auto x = variable(0, bits), y = variable(1, bits), z = variable(2, bits);
        const auto original =
            expression(Op::Sub, add(add(x, y), expression(Op::And, expression(Op::Not, z), y)),
                       expression(Op::Or, z, y));
        const auto expected = expression(Op::Sub, add(x, y), z);
        check(cost(original) < 8, "small word fixture stays below the old preparation floor");
        for (Backend backend : {Backend::Legacy, Backend::Cobra})
        {
            if (backend == Backend::Cobra && !cobra_backend::available())
                continue;
            auto program = make_program(bits);
            program.blocks[0].statements = {Statement::assign(3, original)};
            Options options;
            options.backend = backend;
            unsigned word_proofs = 0;
            detail::SessionTestHooks hooks;
            hooks.after_query = [&](const char *purpose, const z3::check_result &)
            {
                if (std::string(purpose) == "MBA Boolean word identity")
                    ++word_proofs;
            };
            struct Restore
            {
                detail::SessionTestHooks *previous;
                ~Restore() { detail::session_test_hooks = previous; }
            } restore{detail::session_test_hooks};
            detail::session_test_hooks = &hooks;
            Analysis analysis(program, options);
            check(!analysis.constant_value(0, 0) && word_proofs != 0,
                  "small nonconstant word prepares universal proofs before constant search");
            const auto proposals = analysis.run();
            check(!proposals.empty() && cost(proposals.front().replacement) < cost(original),
                  "complete small linear word reduces inside its Normal allowance");
            const auto candidate = analysis.prove_candidate(0, 0, expected);
            check(candidate && analysis.prove_emission(*candidate, expected),
                  "small linear word crosses both independent proof boundaries");
            check(candidate &&
                      !analysis.prove_emission(*candidate, add(expected, constant(1, bits))),
                  "word preparation cannot authorize a corrupt emitted value");
        }
    }
}

void test_cobra_compound_words()
{
    if (!cobra_backend::available())
        return;
    for (unsigned bits = 8; bits <= 64; bits += 8)
    {
        if (compound_width && bits != compound_width)
            continue;
        const auto x = variable(0, bits), y = variable(1, bits), z = variable(2, bits);
        const auto d = variable(3, bits);
        const auto two = constant(2, bits);
        const auto u = add(multiply(two, x), constant(1, bits));
        const auto v = expression(Op::Sub, y, constant(3, bits));
        const auto product = multiply(x, z);
        const auto selector = expression(
            Op::Xor,
            expression(Op::And, expression(Op::Sub, constant(28, bits), x), expression(Op::Not, y)),
            expression(Op::And, expression(Op::Sub, x, constant(29, bits)), y));
        const auto a = expression(Op::And, add(x, d), x), b = add(x, z);
        const std::vector<std::pair<Term, Term>> cases = {
            {selector, expression(Op::Xor, expression(Op::Sub, constant(28, bits), x), y)},
            {expression(Op::Sub, add(u, v), multiply(two, expression(Op::And, u, v))),
             expression(Op::Xor, u, v)},
            {expression(Op::Sub, expression(Op::Sub, add(y, multiply(two, x)), two),
                        multiply(two, expression(Op::And, u, v))),
             expression(Op::Xor, u, v)},
            {expression(Op::Sub, add(product, v), multiply(two, expression(Op::And, product, v))),
             expression(Op::Xor, product, v)},
            {expression(Op::Sub,
                        expression(Op::Sub, expression(Op::Sub, a, b),
                                   multiply(two, expression(Op::Or, expression(Op::Not, b), a))),
                        two),
             expression(Op::Xor, a, b)}};
        size_t shape = 0;
        for (const auto &[original, expected] : cases)
        {
            auto program = make_program(bits);
            program.blocks[0].statements = {Statement::assign(3, original)};
            Options options;
            options.backend = Backend::Cobra;
            options.max_invariants = 0;
            options.max_candidates = 1;
            Analysis analysis(program, options);
            const auto proposals = analysis.run();
            if (proposals.empty() || cost(proposals.front().replacement) > cost(expected))
                std::fprintf(
                    stderr,
                    "compound diagnostic bits=%u shape=%zu calls=%zu unknown=%zu exhausted=%zu "
                    "generated=%zu proved=%zu status=%u reason=%u solver=%d usable=%d\n",
                    bits, shape, analysis.statistics().cobra.calls, analysis.statistics().unknown,
                    analysis.statistics().exhausted, analysis.statistics().cobra.candidates,
                    analysis.statistics().cobra.proved, analysis.statistics().cobra.last_status,
                    analysis.statistics().cobra.last_reason,
                    analysis.statistics().last_solver_observed,
                    int(analysis.statistics().last_solver_usable));
            check(!proposals.empty() && cost(proposals.front().replacement) <= cost(expected),
                  "compound word and reassociated operands reduce within Normal");
            if (!proposals.empty())
            {
                const auto emitted = analysis.prove_emission(*proposals.front().proof,
                                                             proposals.front().replacement);
                check(emitted && emitted->has_emitted_proof() && emitted->from_cobra(),
                      "restored compound operands cross both independent proof boundaries");
            }
            Options independent_options = Options::deep();
            independent_options.backend = Backend::Cobra;
            independent_options.max_invariants = 0;
            Analysis independent(program, independent_options);
            independent.run();
            const auto reference = independent.verify(0, 0, expected);
            if (reference != Verdict::Verified)
                std::fprintf(stderr, "reference diagnostic bits=%u shape=%zu verdict=%u\n", bits,
                             shape, unsigned(reference));
            check(reference == Verdict::Verified,
                  "fresh analysis proves the complete reference at each byte width");
            check(independent.verify(0, 0, add(expected, constant(1, bits))) == Verdict::Disproved,
                  "compound proofs cannot authorize a corrupted complete reference");
            ++shape;
        }
    }
}

void test_cobra_word_view_guards()
{
    using namespace chernobog::mba_smt::detail;
    const auto x = variable(0, 64), y = variable(1, 64);
    const auto u = expression(Op::Sub, x, constant(0, 64));
    const auto source =
        expression(Op::Xor,
                   expression(Op::And, expression(Op::Sub, constant(UINT64_MAX, 64), x),
                              expression(Op::Not, y)),
                   expression(Op::And, u, y));
    Statistics statistics;
    SolverSession session(Options::deep(), statistics);
    CobraWordView view(source, session);
    check(view.lifted() && view.restore(view.input()),
          "complement preparation handles wrapped c+1");
    Program program = make_program(64);
    program.blocks[0].statements = {Statement::assign(3, source)};
    Analysis proof(program, Options::deep());
    check(proof.verify(0, 0, view.restore(view.input())) == Verdict::Verified,
          "candidate-only preparation itself preserves the full modular source value");

    const auto memory = add(load(variable(2, 64), 64), constant(1, 64));
    CobraWordView loads(expression(Op::And, memory, x), session);
    check(!loads.lifted(), "a virtual operand cannot hide a memory read");
    Term many = variable(0, 64);
    for (size_t i = 1; i < 13; ++i)
        many = add(many, variable(i, 64));
    CobraWordView over_limit(expression(Op::And, many, x), session);
    check(!over_limit.lifted(), "virtual operands cannot hide excessive raw source inputs");
    Options cancelled;
    cancelled.cancelled = [] { return true; };
    SolverSession stopped(cancelled, statistics);
    CobraWordView late(source, stopped);
    check(!late.lifted() && key(late.input()) == key(source),
          "cancelled preparation preserves the source and cannot yield a virtual candidate");
}

void test_word_proof_cancellation()
{
    auto program = make_program(32);
    const auto x = variable(0, 32), y = variable(1, 32);
    const auto carry =
        add(expression(Op::Xor, x, y), multiply(constant(2, 32), expression(Op::And, x, y)));
    program.blocks[0].statements = {Statement::assign(2, add(carry, carry))};
    for (Backend backend : {Backend::Legacy, Backend::Cobra})
    {
        if (backend == Backend::Cobra && !cobra_backend::available())
            continue;
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
        options.backend = backend;
        options.max_invariants = 0;
        options.cancelled = [&] { return cancelled; };
        Analysis analysis(program, options);
        check(analysis.run().empty() && observed_word_proof &&
                  analysis.statistics().cobra.calls == 0,
              "late word-theorem cancellation cannot authorize generation or a replacement");
        check(analysis.statistics().last_solver_observed == 2 &&
                  !analysis.statistics().last_solver_usable,
              "word-theorem observation and eligibility remain distinct");
    }
}

void test_snapshot_memory_values()
{
    {
        Program many;
        many.address_bits = 64;
        many.widths = {64};
        many.widths.resize(11, 32);
        many.blocks.resize(1);
        Term value;
        for (size_t i = 1; i <= 9; ++i)
        {
            many.blocks[0].statements.push_back(Statement::assign(i, load(variable(0, 64), 32)));
            const Term input = variable(i, 32);
            many.available.push_back(input);
            value = value ? expression(Op::Xor, value, input) : input;
        }
        many.blocks[0].statements.push_back(Statement::assign(10, value));
        many.targets = {{0, 9}};
        Options limited;
        limited.backend = Backend::Cobra;
        limited.snapshot_values = true;
        limited.max_invariants = 0;
        Analysis refused(many, limited);
        check(refused.run().empty(), "memory-value correlation cannot hide excessive raw inputs");
    }

    for (const bool big_endian : {false, true})
    {
        Program program;
        program.address_bits = 64;
        program.big_endian = big_endian;
        program.widths = {64, 64, 32, 32, 32, 32};
        program.blocks.resize(1);
        const auto p = variable(0, 64), q = variable(1, 64);
        const auto a = variable(2, 32), b = variable(3, 32), c = variable(4, 32);
        program.available = {a, b, c};
        const auto next = add(p, constant(4, 64));
        program.blocks[0].statements = {
            Statement::assign(2, load(p, 32)), Statement::assign(3, load(next, 32)),
            Statement::assign(4, load(p, 32)),
            Statement::assign(5, add(expression(Op::Sub, a, c),
                                     add(multiply(constant(2, 32), b), constant(51, 32))))};
        program.targets = {{0, 3}};
        Options options = Options::deep();
        options.backend = Backend::Cobra;
        options.snapshot_values = true;
        options.max_invariants = 0;
        Analysis same_memory(program, options);
        const auto proposals = same_memory.run();
        const auto reference = add(multiply(constant(2, 32), b), constant(51, 32));
        check(!proposals.empty() && cost(proposals.front().replacement) <= cost(reference),
              "materialized reads of the same memory version share a candidate value");
        if (!proposals.empty())
            check(bool(same_memory.prove_emission(*proposals.front().proof,
                                                  proposals.front().replacement)),
                  "snapshot-value candidate crosses both unchanged source proofs");
        check(same_memory.verify(0, 3, reference) == Verdict::Verified,
              "memory correlation is proved against the complete original read prefix");

        // Unknown parameter aliasing cannot preserve an earlier read through a
        // write. The array model, rather than a disjointness heuristic, decides.
        program.blocks[0].statements = {
            Statement::assign(2, load(p, 32)), Statement::store(q, constant(0xAB, 8)),
            Statement::assign(4, load(p, 32)), Statement::assign(5, expression(Op::Sub, a, c))};
        Analysis aliased(program, options);
        check(aliased.verify(0, 3, constant(0, 32)) == Verdict::Disproved,
              "possibly aliased partial store prevents stale read correlation");
        const auto changed = aliased.run();
        check(changed.empty() || changed.front().replacement->op != Op::Constant,
              "snapshot generation cannot turn distinct memory versions into a constant");

        program.blocks[0].statements[1] = Statement::havoc({1});
        Analysis havoc(program, options);
        check(havoc.verify(0, 3, constant(0, 32)) == Verdict::Disproved,
              "unknown effects and independent volatile observations split memory versions");

        program.blocks[0].statements = {
            Statement::store(p, constant(0x11223344, 32)),
            Statement::store(add(p, constant(1, 64)), constant(0xAA, 8)),
            Statement::assign(2, load(p, 32)), Statement::assign(5, add(a, constant(1, 32)))};
        Analysis forwarding(program, options);
        const uint64_t expected = big_endian ? 0x11AA3345 : 0x1122AA45;
        check(forwarding.verify(0, 3, constant(expected, 32)) == Verdict::Verified,
              "byte-array forwarding preserves partial-store endianness exactly");
        const auto constants = forwarding.run();
        check(!constants.empty() && constants.front().replacement->op == Op::Constant &&
                  constants.front().replacement->value == expected,
              "known stored bytes produce a proved constant candidate");
    }
}

void test_region_diagnostics_and_callback_gate()
{
    Options options;
    options.snapshot = {71, 9};
    options.diagnostic = {DiagnosticPhase::Memory, 0x1000, 8, true};
    Statistics inventory;
    for (size_t i = 0; i < 40; ++i)
        record_diagnostic(inventory, options, DiagnosticStage::Generation,
                          DiagnosticOutcome::NoImprovement, 2, i,
                          diagnostic_region_key(variable(i, 32)));
    check(inventory.regions.used == 32 && inventory.regions.unrecorded == 8 &&
              inventory.regions.counts[size_t(DiagnosticOutcome::NoImprovement)] == 40,
          "region details are bounded while every outcome is counted");
    Statistics combined;
    accumulate_statistics(combined, inventory);
    accumulate_statistics(combined, inventory);
    check(combined.regions.used == 32 && combined.regions.unrecorded == 48 &&
              combined.regions.events[0].snapshot == options.snapshot &&
              combined.regions.events[0].context.source_ea == 0x1000 &&
              combined.regions.counts[size_t(DiagnosticOutcome::NoImprovement)] == 80,
          "aggregation preserves each event's own source snapshot and overflow count");
    RegionDiagnostics self;
    self.record(inventory.regions.events[0]);
    self.accumulate(self);
    check(self.used == 2 && self.counts[size_t(DiagnosticOutcome::NoImprovement)] == 2,
          "diagnostic self-aggregation has ordinary value semantics");
    check(std::strcmp(diagnostic_stage_name(DiagnosticStage::SolverQuery), "solver_query") == 0,
          "solver failures have an explicit diagnostic stage");
    check(diagnostic_region_key(variable(0, 8)) != diagnostic_region_key(variable(0, 16)),
          "region correlation keys retain scalar widths");
    for (int mode = 0; mode < 3; ++mode)
    {
        auto time = std::chrono::steady_clock::time_point{};
        bool cancelled = false;
        detail::SessionTestHooks hooks;
        hooks.now = [&] { return time; };
        struct Restore
        {
            detail::SessionTestHooks *old;
            ~Restore() { detail::session_test_hooks = old; }
        } restore{detail::session_test_hooks};
        detail::session_test_hooks = &hooks;
        Program program = make_program(8);
        const auto x = variable(0, 8);
        program.blocks[0].statements = {Statement::assign(1, add(x, constant(0, 8)))};
        Options request;
        request.backend = Backend::Legacy;
        request.budget_ms = 100;
        request.snapshot = {81, 0};
        request.max_invariants = 0;
        request.cancelled = [&] { return cancelled; };
        request.diagnostic = options.diagnostic;
        request.diagnostic_context = [](size_t, size_t) -> DiagnosticContext
        { throw std::runtime_error("observational resolver fault"); };
        Analysis analysis(program, request);
        const auto candidate = analysis.prove_candidate(0, 0, x);
        const auto emitted = candidate ? analysis.prove_emission(*candidate, x) : nullptr;
        check(bool(emitted), "diagnostic resolver exceptions do not change either proof boundary");
        unsigned mutations = 0;
        if (emitted && analysis.eligible_for_commit(*emitted, mode != 1,
                                                    [&]
                                                    {
                                                        if (mode == 0)
                                                            cancelled = true;
                                                        else
                                                            time += std::chrono::milliseconds(150);
                                                        return true;
                                                    }))
            ++mutations;
        check(mutations == unsigned(mode == 2),
              "post-validation cancel/expiry reject while the intentional legacy waiver remains");
        if (mode != 2)
            check(analysis.statistics().regions.counts[size_t(DiagnosticOutcome::Exhausted)] != 0,
                  "commit rejection is attributed directly to its region");
    }
}

} // namespace

int main(int argc, char **argv)
{
    if (argc == 2 && (std::strcmp(argv[1], "--compound-words") == 0 ||
                      std::strcmp(argv[1], "--compound-64") == 0))
    {
        compound_width = std::strcmp(argv[1], "--compound-64") == 0 ? 64 : 0;
        test_cobra_compound_words();
        test_cobra_word_view_guards();
        return failures != 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--memory-values") == 0)
    {
        test_snapshot_memory_values();
        return failures != 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--diagnostics") == 0)
    {
        test_region_diagnostics_and_callback_gate();
        return failures != 0;
    }
    failures += mba_test_backend_selection();
    test_region_diagnostics_and_callback_gate();
    test_snapshot_memory_values();
    test_scalar_identity_synthesis();
    test_cobra_boolean_selector();
    test_masked_difference_sum();
    test_joins_and_memory();
    test_unconditional_chains();
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
    test_boolean_operand_complements();
    test_verified_complement_normalization();
    test_legacy_masked_selectors();
    test_small_linear_word_boundaries();
    test_cobra_compound_words();
    test_cobra_word_view_guards();
    test_word_proof_cancellation();
    std::printf("MBA SMT failures: %d\n", failures);
    return failures != 0;
}
