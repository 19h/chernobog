#include "vm_test_candidates.hpp"
#include "vm/transition.hpp"
#include "common/solver_evidence.hpp"
#include <iostream>
#include <stdexcept>
using namespace chernobog;
namespace
{
unsigned checks = 0;
void check(bool b, const char *name)
{
    ++checks;
    if (!b)
        throw std::runtime_error(name);
}
struct Fixture
{
    vm::Candidate c;
    hybrid::StatePoint entry, output;
    std::vector<hybrid::DataAcc> data;
};
uint64_t arithmetic_flags(uint64_t a, uint64_t b, uint64_t result, unsigned bits, bool subtract)
{
    const auto mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
    a &= mask;
    b &= mask;
    result &= mask;
    const auto sign = UINT64_C(1) << (bits - 1);
    uint64_t f = (subtract ? a < b : result < a) ? 1 : 0;
    unsigned parity = 0;
    for (unsigned i = 0; i < 8; ++i)
        parity += unsigned((result >> i) & 1);
    if (parity % 2 == 0)
        f |= 4;
    if ((a ^ b ^ result) & 16)
        f |= 16;
    if (!result)
        f |= 64;
    if (result & sign)
        f |= 128;
    if (((subtract ? a ^ b : ~(a ^ b)) & (a ^ result)) & sign)
        f |= 2048;
    return f;
}
Fixture fixture(unsigned mode, bool backward, bool keyed, uint8_t encoded, bool stack = false)
{
    Fixture f;
    f.c = vm_test::candidate(mode, backward, false, keyed);
    if (stack)
        f.c = vm_test::stack_candidate(f.c);
    auto &e = f.entry;
    e.pc = f.c.start;
    e.sequence = 1;
    e.source = 0x800;
    e.run_id = 2;
    e.seed = 19;
    for (int i = 0; i < (mode == 64 ? 16 : 8); ++i)
        e.regs.push_back({mode == 64 ? RAX_X86_GPR64(i) : RAX_X86_GPR32(i), uint64_t(0x100 + i),
                          uint8_t(mode / 8)});
    e.regs[6].value = 0x2000;
    e.regs[3].value = 0x12345a;
    e.regs[7].value = 0x3000;
    e.regs.push_back(
        {mode == 64 ? RAX_X86_REG_RFLAGS : RAX_X86_REG_EFLAGS, 0x202, uint8_t(mode / 8)});
    f.output = e;
    auto &o = f.output;
    o.pc = 0x1800;
    o.source = f.c.dispatch;
    o.sequence = 100;
    o.regs[6].value = backward ? 0x1fff : 0x2001;
    uint8_t decoded = encoded;
    if (keyed)
    {
        const uint8_t mixed = uint8_t(encoded ^ 0x5a);
        decoded = uint8_t(((unsigned(mixed) << 3) | (mixed >> 5)) + 7);
        o.regs[3].value = e.regs[3].value ^ decoded;
        const auto result = uint8_t(o.regs[3].value);
        o.regs.back().value = arithmetic_flags(0, 0, result, 8, false) & (4 | 64 | 128);
    }
    else
        o.regs.back().value = arithmetic_flags(0x2000, 1, o.regs[6].value, mode, backward);
    o.regs[0].value = decoded;
    f.data = {{f.c.read, backward ? 0x1fffu : 0x2000u, encoded, 1, RAX_MEM_READ,
               hybrid::DataScope::IMAGE, 10, 2, 19},
              {f.c.dispatch, (mode == 64 ? 0x3000 : 0) + uint64_t(decoded) * (mode / 8), o.pc,
               mode / 8, RAX_MEM_READ, hybrid::DataScope::IMAGE, 90, 2, 19}};
    if (stack)
    {
        const auto push = f.c.support[f.c.support.size() - 2].address,
                   slot = e.regs[4].value - mode / 8;
        f.data[1].from = push;
        f.data.push_back(
            {push, slot, o.pc, mode / 8, RAX_MEM_WRITE, hybrid::DataScope::STACK, 91, 2, 19});
        f.data.push_back({f.c.dispatch, slot, o.pc, mode / 8, RAX_MEM_READ,
                          hybrid::DataScope::STACK, 92, 2, 19});
    }
    return f;
}
vm::TransitionCheck run(const Fixture &f, unsigned timeout = 100, unsigned resource = 200000)
{
    return vm::check_transition(f.c, f.entry, f.output, f.data, timeout, resource);
}
struct Collector : solver_evidence::Collector
{
    std::vector<solver_evidence::Row> rows;
    bool accepts(const solver_evidence::Origin &) override { return true; }
    void publish(const solver_evidence::Origin &, solver_evidence::Row row) override
    {
        rows.push_back(std::move(row));
    }
};
}
int main()
{
    try
    {
        using R = vm::TransitionResult;
        for (unsigned mode : {32u, 64u})
            for (bool backward : {false, true})
                for (bool keyed : {false, true})
                    for (uint8_t byte : {0, 0x25, 0xff})
                        for (bool stack : {false, true})
                        {
                            auto f = fixture(mode, backward, keyed, byte, stack);
                            const auto good = run(f);
                            check(good.result == R::corroborated && good.queries == 2,
                                  "independent table transition");
                            for (size_t i = 0; i < f.output.regs.size() - 1; ++i)
                            {
                                f.output.regs[i].value ^= 1;
                                const auto bad = run(f);
                                check(bad.result == R::different && bad.queries == 2,
                                      "every output GPR checked");
                                f.output.regs[i].value ^= 1;
                            }
                            for (unsigned flag : {0u, 2u, 6u, 7u, 11u})
                            {
                                f.output.regs.back().value ^= UINT64_C(1) << flag;
                                check(run(f).result == R::different, "defined output flag checked");
                                f.output.regs.back().value ^= UINT64_C(1) << flag;
                            }
                            f.output.regs.back().value ^= 16;
                            check(run(f).result == (keyed ? R::corroborated : R::different),
                                  "AF definition contract");
                            f.output.regs.back().value ^= 16;
                            ++f.output.pc;
                            check(run(f).result == R::different, "dispatch target checked");
                            --f.output.pc;
                            ++f.data[0].addr;
                            check(run(f).result == R::different,
                                  "access address mismatch is not an input assumption");
                            --f.data[0].addr;
                            ++f.data[0].from;
                            check(run(f).result == R::different, "access source checked");
                            --f.data[0].from;
                            f.data[0].size = 2;
                            check(run(f).result == R::different, "access width checked");
                            f.data[0].size = 1;
                            f.data[0].seed = 20;
                            check(run(f).result == R::unsupported, "access identity checked");
                            f.data[0].seed = 19;
                            f.data[1].sequence = f.data[0].sequence;
                            check(run(f).result == R::unsupported, "access order checked");
                            f.data[1].sequence = 90;
                            if (stack)
                            {
                                ++f.data.back().value;
                                check(run(f).result == R::inconsistent,
                                      "return read must agree with target push");
                                ++f.data[f.data.size() - 2].value;
                                ++f.output.pc;
                                check(run(f).result == R::different,
                                      "consistent incorrect stack target is a counterexample");
                                f.data.pop_back();
                                check(run(f).result == R::different,
                                      "missing return read cannot corroborate");
                            }
                            f = fixture(mode, backward, keyed, byte, stack);
                            f.entry.regs.pop_back();
                            check(run(f).result == R::unsupported, "missing input flags");
                        }
        auto f = fixture(64, false, false, 0);
        f.entry.regs[6].value = 0x3000;
        f.output.regs[6].value = 0x3001;
        f.data[0].addr = 0x3000;
        f.output.pc = 0x1811;
        f.data[1].value = 0x1811;
        const auto inconsistent = run(f);
        check(inconsistent.result == R::inconsistent && inconsistent.queries == 1,
              "conflicting initial reads cannot prove outputs");
        f = fixture(64, false, true, 0);
        f.c = vm_test::candidate(64, false, true, true);
        f.entry.pc = f.c.start;
        f.entry.regs[3].value = UINT64_C(0x112233445566775a);
        f.entry.regs[4].value = 0x8000;
        f.entry.regs[7].value = 0x4000;
        f.output = f.entry;
        f.output.source = f.c.dispatch;
        f.output.pc = 0x3fe0;
        f.output.sequence = 100;
        f.output.regs[0].value = UINT64_C(0xffffffffffffffe0);
        f.output.regs[6].value = 0x2004;
        f.output.regs[3].value = UINT64_C(0x11223344aa9988ba);
        f.output.regs[7].value = 0x3fe0;
        f.output.regs.back().value =
            arithmetic_flags(0x4000, UINT64_C(0xffffffffffffffe0), 0x3fe0, 64, false);
        uint64_t push = 0, update = 0, pop = 0;
        for (const auto &i : f.c.support)
        {
            if (i.op == vm::Op::push)
                push = i.address;
            if (i.op == vm::Op::bit_xor && i.dst.kind == vm::Kind::memory)
                update = i.address;
            if (i.op == vm::Op::pop)
                pop = i.address;
        }
        f.data = {
            {f.c.read, 0x2000, 0x6a9988a1, 4, RAX_MEM_READ, hybrid::DataScope::IMAGE, 10, 2, 19},
            {push, 0x7ff8, UINT64_C(0x112233445566775a), 8, RAX_MEM_WRITE, hybrid::DataScope::STACK,
             20, 2, 19},
            {update, 0x7ff8, 0x5566775a, 4, RAX_MEM_READ, hybrid::DataScope::STACK, 30, 2, 19},
            {update, 0x7ff8, 0xaa9988ba, 4, RAX_MEM_WRITE, hybrid::DataScope::STACK, 40, 2, 19},
            {pop, 0x7ff8, UINT64_C(0x11223344aa9988ba), 8, RAX_MEM_READ, hybrid::DataScope::STACK,
             50, 2, 19}};
        check(run(f).result == R::corroborated, "ordered aliased stack effects");
        f.data.back().value ^= 1;
        check(run(f).result == R::inconsistent && run(f).queries == 0,
              "read must agree with observed write");
        f.data[3].value ^= 1;
        f.output.regs[3].value ^= 1;
        check(run(f).result == R::different,
              "consistent incorrect write is a modeled counterexample");
        f = fixture(64, false, true, 0x25);
        const auto unknown = run(f, 1, 1);
        check(unknown.result == R::unknown && !unknown.reason.empty(),
              "actual resource exhaustion abstains");
        Collector collector;
        solver_evidence::collector = &collector;
        {
            solver_evidence::Scope scope({0, 0x800, f.c.start, -1, "vm-observed-transition"});
            check(run(f).result == R::corroborated, "observed query execution");
        }
        solver_evidence::collector = nullptr;
        check(collector.rows.size() == 2 && collector.rows[0].at("result") == "sat" &&
                  collector.rows[1].at("result") == "unsat",
              "nonvacuous SAT then UNSAT transcript");
        f.output.regs.push_back(f.output.regs[0]);
        ++f.output.regs.back().value;
        check(run(f).result == R::unsupported, "conflicting output register");
        std::cout << checks << " VM transition checks passed\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
