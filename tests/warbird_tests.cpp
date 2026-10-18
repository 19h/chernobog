#include "vm/warbird/model.hpp"
#include "vm/warbird/key_domain.hpp"
#include "vm/warbird/byte_memory.hpp"
#include <rax.h>
#include <algorithm>
#include <cstdlib>
#include <iostream>
using namespace chernobog;
namespace
{
void require(bool value, const char *why)
{
    if (!value)
    {
        std::cerr << why << '\n';
        std::exit(1);
    }
}
hybrid::ProgramImage fixture(std::initializer_list<uint8_t> code)
{
    hybrid::ProgramImage image;
    image.arch = hybrid::HybridArch::X86_64;
    image.lo = 0x1000;
    image.hi = 0x2000;
    hybrid::SegImage segment;
    segment.start = 0x1000;
    segment.end = 0x2000;
    segment.perm = 5;
    segment.bitness = 2;
    segment.bytes.resize(4096, 0xcc);
    segment.mask.resize(512, 0xff);
    std::copy(code.begin(), code.end(), segment.bytes.begin());
    image.segs.push_back(std::move(segment));
    return image;
}
warbird::Report run(const hybrid::ProgramImage &image, uint64_t key = 1,
                    warbird::Limits limits = {})
{
    static warbird::Profile profile{"fixture", "", 0, 0, 0, 2, {0, 1, 2, 3}, {4, 5}, 4, false, {1}};
    warbird::Admission a;
    a.profile = &profile;
    a.handlers = {0x1000, 0x1000};
    warbird::Lease lease;
    lease.database = 1;
    lease.key = key;
    std::atomic_bool cancel{false};
    return warbird::explore(image, a, lease, limits, cancel);
}
}
int main()
{
    // Finite covers are exhaustive, including a proof beyond the last model.
    z3::context context;
    auto x = context.bv_const("key_input", 64);
    auto choice = context.bool_const("choice");
    auto numeral = [&](uint64_t n) { return context.bv_val(n, 64); };
    auto finite = warbird::resolve_key_domain(z3::ite(choice, numeral(7), numeral(11)),
                                              context.bool_val(true));
    require(finite.complete() && finite.values == std::vector<uint64_t>({7, 11}) &&
                finite.queries == 0,
            "conditional key cover failed");
    auto transformed = warbird::resolve_key_domain(
        z3::ite(choice, numeral(7), numeral(11)) * numeral(2) + numeral(3), context.bool_val(true));
    require(transformed.complete() && transformed.queries == 0 &&
                transformed.values == std::vector<uint64_t>({17, 25}),
            "bit-vector transforms lost finite key cover");
    auto joined = warbird::resolve_key_domain(
        z3::concat(z3::ite(choice, context.bv_val(0xffffffffu, 32), context.bv_val(0, 32)),
                   context.bv_val(5, 32)),
        context.bool_val(true));
    require(joined.complete() && joined.queries == 0 &&
                joined.values == std::vector<uint64_t>({5, 0xffffffff00000005ULL}),
            "concatenated finite key cover failed");
    auto masked =
        warbird::resolve_key_domain(x & numeral(3), z3::ult(x, numeral(4)) && x != numeral(1), 4);
    require(masked.complete() && masked.values == std::vector<uint64_t>({0, 2, 3}) &&
                masked.queries == 4,
            "exhaustive SMT key cover failed");
    auto unbounded = warbird::resolve_key_domain(x, context.bool_val(true), 3);
    require(unbounded.status == warbird::KeyDomainStatus::VALUE_LIMIT && !unbounded.complete(),
            "model prefix was treated as a complete key set");
    auto impossible = warbird::resolve_key_domain(x, x == numeral(1) && x == numeral(2));
    require(impossible.status == warbird::KeyDomainStatus::UNSATISFIABLE,
            "contradictory key domain accepted");
    require(warbird::resolve_key_domain(context.bv_val(1, 32), context.bool_val(true)).status ==
                warbird::KeyDomainStatus::INVALID,
            "non-64-bit key accepted");
    // Compare the sparse overlay against a separately constructed byte array.
    warbird::ByteMemory memory(context);
    auto reference =
        context.constant("memory", context.array_sort(context.bv_sort(64), context.bv_sort(8)));
    auto reference_store = [&](z3::expr address, z3::expr value, unsigned width)
    {
        for (unsigned byte = 0; byte < width / 8; ++byte)
            reference = z3::store(reference, address + numeral(byte),
                                  value.extract(byte * 8 + 7, byte * 8));
        memory.write(address, value, width);
    };
    reference_store(numeral(0x1000), numeral(0x1122334455667788), 64);
    reference_store(numeral(0x1002), context.bv_val(0xaabb, 16), 16);
    auto fork = memory;
    reference_store(x, context.bv_val(0xcc, 8), 8);
    reference_store(numeral(0x1003), context.bv_val(0xdd, 8), 8);
    z3::solver parity(context);
    parity.add(memory.materialize() != reference);
    require(parity.check() == z3::unsat, "symbolic store lost byte-overlay aliases or ordering");
    uint64_t old_value = 0;
    require(fork.read(numeral(0x1000), 64).is_numeral_u64(old_value) &&
                old_value == 0x11223344aabb7788ULL,
            "forked byte memory was mutated by a later store");
    auto symbolic_read = memory.read(x, 64);
    auto reference_read = z3::select(reference, x);
    for (unsigned byte = 1; byte < 8; ++byte)
        reference_read = z3::concat(z3::select(reference, x + numeral(byte)), reference_read);
    z3::solver read_parity(context);
    read_parity.add(symbolic_read != reference_read);
    require(read_parity.check() == z3::unsat, "symbolic read bypassed concrete overlay");
    warbird::ByteMemory bounded(context, 1);
    bounded.write(numeral(0), context.bv_val(1, 8), 8);
    bool exhausted = false;
    try
    {
        bounded.write(numeral(0), context.bv_val(0x2222, 16), 16);
    }
    catch (const std::runtime_error &)
    {
        exhausted = true;
    }
    uint64_t retained = 0;
    require(exhausted && bounded.concrete_bytes() == 1 &&
                bounded.read(numeral(0), 8).is_numeral_u64(retained) && retained == 1,
            "byte memory quota accepted a partial write");
    warbird::ByteMemory wrapped(context);
    wrapped.write(numeral(UINT64_MAX), context.bv_val(0x1234, 16), 16);
    require(wrapped.read(numeral(0), 8).is_numeral_u64(retained) && retained == 0x12,
            "byte address wrap changed little-endian order");
    auto conditional =
        fixture({0x83, 0xfa, 1, 0x75, 0x13, 0x48, 0x83, 0x39, 0,    0xb8, 0,    0,    0,   0,
                 0xba, 2,    0, 0,    0,    0x48, 0x0f, 0x45, 0xc2, 0xc3, 0x31, 0xc0, 0xc3});
    auto split = run(conditional);
    require(split.exploration_complete() && split.key_splits == 1 && split.edges.size() == 3,
            "conditional native next keys were not recovered");
    require(std::count_if(split.edges.begin(), split.edges.end(),
                          [](const auto &e) { return e.key == 1 && e.next == 0; }) == 1 &&
                std::count_if(split.edges.begin(), split.edges.end(),
                              [](const auto &e) { return e.key == 1 && e.next == 2; }) == 1 &&
                std::count_if(split.edges.begin(), split.edges.end(),
                              [](const auto &e) { return e.key == 2 && e.next == 0; }) == 1,
            "conditional key edges lost a successor");
    auto zero = fixture({0x31, 0xc0, 0xc3});
    auto r = run(zero);
    require(r.exploration_complete() && r.edges.size() == 1 && r.edges[0].next == 0,
            "zero-key return must terminate");
    r = run(zero, 0);
    require(r.exploration_complete() && r.instructions == 0,
            "zero entry must not dispatch table slot zero");
    auto alias_return = fixture({0x48, 0x8b, 0x01, 0x48, 0xc7, 0x00, 0, 0, 0, 0, 0x31, 0xc0, 0xc3});
    auto alias_report = run(alias_return);
    require(!alias_report.exploration_complete() && alias_report.return_splits == 1 &&
                alias_report.edges.size() == 1 && alias_report.edges[0].next == 0 &&
                !alias_report.frontiers.empty(),
            "ordinary return continuation or nonlocal frontier was lost");
    auto unknown = fixture({0x48, 0x8b, 0x01, 0xc3});
    r = run(unknown);
    require(!r.exploration_complete() && r.edges.empty(),
            "uninitialized context must remain unknown");
    auto overlap =
        fixture({0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89,
                 0x01, 0x66, 0xc7, 0x41, 0x02, 0,    0,    0x48, 0x8b, 0x01, 0x48, 0xbb,
                 0x88, 0x77, 0,    0,    0x44, 0x33, 0x22, 0x11, 0x48, 0x31, 0xd8, 0xc3});
    r = run(overlap);
    require(r.exploration_complete() && r.edges.size() == 1 && r.edges[0].next == 0,
            "byte-overlap store forwarding mismatch");
    auto full_key = fixture({0x48, 0x89, 0xd0, 0x48, 0xc1, 0xe8, 0x20, 0xc3});
    r = run(full_key, 0x100000001ULL);
    require(r.exploration_complete() && r.edges.size() == 2 && r.edges[0].next == 1 &&
                r.edges[1].next == 0,
            "same-index keys must preserve high 32 bits");
    auto loop = fixture({0xeb, 0xfe});
    r = run(loop);
    require(!r.exploration_complete() && r.instructions == 1 && !r.frontiers.empty(),
            "exact-state native loop must remain explicit without a fabricated exit");
    warbird::Limits quota;
    quota.instructions = 1;
    r = run(overlap, 1, quota);
    require(!r.exploration_complete(), "instruction quota must retain frontier");
    warbird::Lease a;
    a.database = 1;
    auto b = a;
    require(a.matches(b), "identical lease rejected");
    ++b.revision;
    require(!a.matches(b), "revision change accepted");
    b = a;
    ++b.base;
    require(!a.matches(b), "rebase accepted");
    b = a;
    ++b.model;
    require(!a.matches(b), "model change accepted");
    warbird::Dependency d{0x1000, 5, {0x31, 0xc0, 0xc3}};
    require(warbird::dependencies_match(zero, {d}), "matching dependency rejected");
    zero.segs[0].bytes[0] ^= 1;
    require(!warbird::dependencies_match(zero, {d}), "patched dependency accepted");
    // Native admission binds the full table and explicit dispatch contract.
    auto native =
        fixture({0x48, 0x8b, 0xc2, 0x48, 0x8d, 0x0d, 0xf6, 0x1f, 0,    0,    0x25, 1,    0,
                 0,    0,    0x48, 0x8b, 0x04, 0xc1, 0x48, 0x8d, 0x4d, 0x10, 0xff, 0x15, 0,
                 0,    0,    0,    0x48, 0x8b, 0xd0, 0x48, 0x85, 0xc0, 0x75, 0xf0});
    native.segs[0].bytes[0x60] = 0x31;
    native.segs[0].bytes[0x61] = 0xc0;
    hybrid::SegImage table;
    table.start = 0x3000;
    table.end = 0x3010;
    table.perm = 4;
    table.bitness = 2;
    table.mask = {255, 255};
    table.bytes.resize(16);
    for (unsigned i = 0; i < 2; ++i)
    {
        table.bytes[i * 8] = 0x80;
        table.bytes[i * 8 + 1] = 0x10;
    }
    native.segs.push_back(table);
    warbird::Profile profile{"test", "", 0x2000, 0,   0,    2,           {0, 1, 2, 3},
                             {4, 5}, 4,  false,  {1}, 0x60, {0x31, 0xc0}};
    auto accepted = warbird::admit(native, 0x1000, profile);
    require(accepted.valid(), "valid dispatcher rejected");
    auto tampered = native;
    tampered.segs[0].bytes[11] = 3;
    require(!warbird::admit(tampered, 0x1000, profile).valid(), "changed dispatch mask accepted");
    tampered = native;
    tampered.segs[0].bytes[0x60] = 0x90;
    require(!warbird::admit(tampered, 0x1000, profile).valid(),
            "changed context initialization accepted");
    tampered = native;
    tampered.segs[1].mask[0] = 0;
    require(!warbird::admit(tampered, 0x1000, profile).valid(), "unloaded table accepted");
    tampered = native;
    tampered.segs[0].perm |= 2;
    require(!warbird::admit(tampered, 0x1000, profile).valid(), "mutable handler code accepted");
    size_t keys = 0;
    for (const auto &p : warbird::profiles())
        keys += p.entry_keys.size();
    require(keys == 11, "corpus entry key count changed");
    warbird::Lease incompatible;
    incompatible.database = 1;
    incompatible.key = 1;
    incompatible.smir_abi = 99;
    std::atomic_bool stopped{false};
    auto rejected = warbird::explore(native, accepted, incompatible, {}, stopped);
    require(!rejected.exploration_complete() && rejected.instructions == 0,
            "incompatible SMIR ABI accepted");
    stopped.store(true);
    incompatible.smir_abi = 1;
    rejected = warbird::explore(native, accepted, incompatible, {}, stopped);
    require(rejected.cancelled && !rejected.exploration_complete(),
            "cancelled job was treated as complete");

    // Direct x86 interpreter parity for the first key transition. This is
    // separate execution code, not an architectural or whole-corpus proof.
    rax_engine *engine = nullptr;
    rax_engine_config config{};
    config.size = sizeof(config);
    config.arch = RAX_ARCH_X86;
    config.mode = RAX_MODE_64;
    config.backend = RAX_BACKEND_EMULATOR;
    config.mem_base = 0x1000;
    config.mem_size = 0x10000;
    config.mem_perms = RAX_PROT_ALL;
    require(rax_engine_open_config(&config, &engine) == RAX_OK, "direct interpreter open failed");
    const uint64_t return_pc = 0x2000;
    require(rax_mem_write(engine, 0x8000, &return_pc, sizeof(return_pc)) == RAX_OK,
            "direct stack write failed");
    std::vector<hybrid::ProgramImage> programs = {
        full_key,
        fixture({0x48, 0x89, 0xd0, 0xf9, 0x48, 0x83, 0xd0, 0, 0x48, 0xc1, 0xe8, 0x20, 0xc3}),
        fixture({0x48, 0x89, 0xd0, 0xf9, 0x48, 0x83, 0xd8, 0, 0x48, 0xc1, 0xe8, 0x20, 0xc3}),
        fixture({0x48, 0x89, 0xd0, 0xf9, 0x48, 0xd1, 0xd0, 0x48, 0xc1, 0xe8, 0x20, 0xc3}),
        fixture({0x48, 0x89, 0xd0, 0xf8, 0x48, 0xd1, 0xd8, 0x48, 0xc1, 0xe8, 0x20, 0xc3}),
        fixture({0x48, 0x89, 0xd0, 0xf9, 0x48, 0x83, 0xd0, 0,    0x0f, 0x92, 0xc1, 0x0f,
                 0x90, 0xc2, 0x0f, 0xb6, 0xc9, 0x0f, 0xb6, 0xd2, 0x8d, 0x04, 0x51, 0xc3}),
        fixture({0x48, 0x89, 0xd0, 0xf9, 0x48, 0x83, 0xd8, 0,    0x0f, 0x92, 0xc1, 0x0f,
                 0x90, 0xc2, 0x0f, 0xb6, 0xc9, 0x0f, 0xb6, 0xd2, 0x8d, 0x04, 0x51, 0xc3})};
    programs.push_back(fixture({0x48, 0x89, 0xd0, 0xbb, 0x7f, 0,    0, 0, 0xf6, 0xe3,
                                0x48, 0xc1, 0xe8, 8,    0x25, 0xff, 0, 0, 0,    0xc3}));
    programs.push_back(fixture({0x48, 0x89, 0xd0, 0xbb, 0x7f, 0,    0, 0, 0xf6, 0xeb,
                                0x48, 0xc1, 0xe8, 8,    0x25, 0xff, 0, 0, 0,    0xc3}));

    programs.push_back(
        fixture({0x48, 0x89, 0xd0, 0xf9, 0x48, 0xd1, 0xd0, 0x0f, 0x92, 0xc1, 0x0f, 0x90,
                 0xc2, 0x0f, 0xb6, 0xc9, 0x0f, 0xb6, 0xd2, 0x8d, 0x04, 0x51, 0xc3}));
    programs.push_back(
        fixture({0x48, 0x89, 0xd0, 0xf8, 0x48, 0xd1, 0xd8, 0x0f, 0x92, 0xc1, 0x0f, 0x90,
                 0xc2, 0x0f, 0xb6, 0xc9, 0x0f, 0xb6, 0xd2, 0x8d, 0x04, 0x51, 0xc3}));
    std::vector<uint64_t> inputs = {1,
                                    2,
                                    UINT64_MAX,
                                    uint64_t(1) << 63,
                                    (uint64_t(1) << 63) - 1,
                                    0xffffffff00000000ULL,
                                    0x100000000ULL};
    uint64_t random = 0x82A2B175229D6A5FULL;
    for (unsigned n = 0; n < 1024; ++n)
    {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        inputs.push_back(random);
    }
    size_t comparisons = 0;
    for (const auto &program : programs)
    {
        require(rax_mem_write(engine, 0x1000, program.segs[0].bytes.data(), 4096) == RAX_OK,
                "direct code write failed");
        for (auto input : inputs)
        {
            require(rax_reg_write_u64(engine, RAX_X86_REG_RDX, input) == RAX_OK &&
                        rax_reg_write_u64(engine, RAX_X86_REG_RSP, 0x8000) == RAX_OK,
                    "direct register write failed");
            require(rax_emu_start(engine, 0x1000, return_pc, 0, 32) == RAX_OK,
                    "direct execution failed");
            rax_exit exit{};
            require(rax_emu_last_exit(engine, &exit) == RAX_OK && exit.reason == RAX_STOP_UNTIL &&
                        exit.address == return_pc,
                    "direct interpreter did not complete the native handler");
            uint64_t observed = 0;
            require(rax_reg_read_u64(engine, RAX_X86_REG_RAX, &observed) == RAX_OK,
                    "direct result unavailable");
            warbird::Limits first_transition;
            first_transition.states = 3;
            auto candidate = run(program, input, first_transition);
            if (candidate.edges.empty() || candidate.edges.front().next != observed)
            {
                std::cerr << "transition mismatch program=" << (&program - programs.data())
                          << " input=" << std::hex << input << " direct=" << observed << "\n"
                          << candidate.json() << "\n";
                std::exit(1);
            }
            ++comparisons;
        }
    }
    require(comparisons == 11341, "incomplete direct comparison matrix");
    rax_engine_close(engine);
    std::cout << "warbird tests passed\n";
}
