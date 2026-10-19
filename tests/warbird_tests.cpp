#include "vm/warbird/model.hpp"
#include "vm/warbird/key_domain.hpp"
#include "vm/warbird/byte_memory.hpp"
#include "vm/warbird/pool_model.hpp"
#include "vm/warbird/alias.hpp"
#include "vm/warbird/stack_model.hpp"
#include "vm/warbird/recovery.hpp"
#include "vm/warbird/loop_model.hpp"
#include <rax.h>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <type_traits>
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
                    warbird::Limits limits = {}, std::vector<warbird::ImportBinding> imports = {})
{
    static warbird::Profile profile{"fixture", "", 0, 0, 0, 2, {0, 1, 2, 3}, {4, 5}, 4, false, {1}};
    warbird::Admission a;
    a.profile = &profile;
    a.abstract_handler_abi = true;
    a.handlers = {0x1000, 0x1000};
    warbird::bind_imports(image, a, std::move(imports));
    warbird::Lease lease;
    lease.database = 1;
    lease.key = key;
    std::atomic_bool cancel{false};
    return warbird::explore(image, a, lease, limits, cancel);
}
}
int main()
{
    // Import directory parsing uses bounded loaded metadata, never IAT values
    // as an execution address. Named exports retain case; modules do not.
    auto imported = fixture({0xff, 0x15, 0xfa, 0x03, 0, 0, 0x31, 0xc0, 0xc3});
    auto &import_bytes = imported.segs[0].bytes;
    std::fill(import_bytes.begin() + 0x200, import_bytes.begin() + 0x600, 0);
    auto field = [&](size_t offset, uint64_t value, unsigned size)
    {
        for (unsigned n = 0; n < size; ++n)
            import_bytes[offset + n] = uint8_t(value >> (n * 8));
    };
    auto string = [&](size_t offset, const std::string &value)
    { std::copy(value.begin(), value.end(), import_bytes.begin() + offset); };
    field(0x200, 0x300, 4);
    field(0x20c, 0x500, 4);
    field(0x210, 0x400, 4);
    field(0x300, 0x580, 8);
    field(0x400, 0x580, 8);
    string(0x500, "NTOSKRNL.EXE");
    string(0x582, "ExAllocatePoolWithTag");
    auto imports = warbird::read_pe_imports(imported, 0x1000, 0x200, 40);
    require(imports.size() == 1 && imports[0].slot == 0x1400 &&
                imports[0].module == "ntoskrnl.exe" && imports[0].symbol == "ExAllocatePoolWithTag",
            "PE import identity parsing failed");
    auto unknown_imports = imports;
    unknown_imports[0].symbol = "UnmodeledHelper";
    auto external = run(imported, 1, {}, unknown_imports);
    require(external.frontiers.size() == 1 &&
                external.frontiers[0].reason == "external import: ntoskrnl.exe!UnmodeledHelper",
            "file import-name RVA was treated as executable code");
    field(0x308, 0x8000000000000011ULL, 8);
    field(0x408, 0x8000000000000011ULL, 8);
    imports = warbird::read_pe_imports(imported, 0x1000, 0x200, 40);
    require(imports.size() == 2 && imports[1].symbol.empty() && imports[1].ordinal == 17,
            "ordinal import identity lost");
    field(0x200, 0, 4);
    require(warbird::read_pe_imports(imported, 0x1000, 0x200, 40) == imports,
            "missing original lookup table was not handled");
    auto rejects_imports = [&](auto action, const char *why)
    {
        bool rejected = false;
        try
        {
            action();
        }
        catch (const std::exception &)
        {
            rejected = true;
        }
        require(rejected, why);
    };
    rejects_imports([&] { warbird::read_pe_imports(imported, 0x1000, 0x200, 20); },
                    "unterminated import descriptors accepted");
    rejects_imports([&] { warbird::read_pe_imports(imported, UINT64_MAX, 0x200, 40); },
                    "overflowing import base accepted");
    rejects_imports(
        [&]
        {
            auto duplicate = imports;
            duplicate.push_back(imports[0]);
            warbird::validate_imports(imported, duplicate);
        },
        "duplicate import slot accepted");
    rejects_imports(
        [&]
        {
            auto overlap = imports;
            overlap[1].slot = overlap[0].slot + 4;
            warbird::validate_imports(imported, overlap);
        },
        "overlapping import slot accepted");
    field(0x400, 0x1100, 8);
    import_bytes[0x100] = 0xc3;
    auto loaded_helper = run(imported, 1, {}, {imports[0]});
    require(loaded_helper.exploration_complete() && loaded_helper.edges.size() == 1 &&
                loaded_helper.edges[0].next == 0,
            "mapped native helper was replaced by an import model");
    auto unresolved = imported;
    unresolved.segs[0].mask[0x400 / 8] = 0;
    auto unresolved_imports = std::vector<warbird::ImportBinding>{imports[0]};
    warbird::validate_imports(unresolved, unresolved_imports);
    require(unresolved_imports[0].loaded_mask == 0 && unresolved_imports[0].snapshot_value == 0,
            "unloaded IDA import bytes acquired a fabricated pointer");
    require(unresolved_imports != std::vector<warbird::ImportBinding>{imports[0]},
            "import byte-availability change did not invalidate identity");
    const std::vector<uint8_t> pool_call = {
        0x48, 0x83, 0xec, 0x28, 0xb9, 1,    0, 0, 0, 0xba, 32,   0,    0,    0,    0x41, 0xb8, 0x45,
        0x50, 0,    0,    0xff, 0x15, 0xe6, 3, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0x31, 0xc0, 0xc3};
    std::copy(pool_call.begin(), pool_call.end(), unresolved.segs[0].bytes.begin());
    auto pool_report = run(unresolved, 1, {}, unresolved_imports);
    require(pool_report.external_calls == 1 && pool_report.edges.size() == 2 &&
                !pool_report.exploration_complete(),
            "pool normal outcomes, unresolved binding frontier or native return lost");
    auto vector_call = unresolved;
    const std::vector<uint8_t> xmm_preservation = {
        0x48, 0x83, 0xec, 0x28, 0x66, 0x48, 0x0f, 0x6e, 0xf2, 0xb9, 1,    0,    0,    0,   0xba,
        32,   0,    0,    0,    0x41, 0xb8, 0x45, 0x50, 0,    0,    0xff, 0x15, 0xe1, 3,   0,
        0,    0x66, 0x48, 0x0f, 0x7e, 0xf0, 0x83, 0xf0, 1,    0x48, 0x83, 0xc4, 0x28, 0xc3};
    std::copy(xmm_preservation.begin(), xmm_preservation.end(), vector_call.segs[0].bytes.begin());
    const auto nonvolatile_xmm = run(vector_call, 1, {}, unresolved_imports);
    require(nonvolatile_xmm.edges.size() == 2 && nonvolatile_xmm.vector_operations >= 3 &&
                std::all_of(nonvolatile_xmm.edges.begin(), nonvolatile_xmm.edges.end(),
                            [](const auto &edge) { return edge.next == 0; }),
            "external pool model clobbered nonvolatile XMM6");
    vector_call.segs[0].bytes[8] = 0xc2;  // MOVQ XMM0,RDX
    vector_call.segs[0].bytes[35] = 0xc0; // MOVQ RAX,XMM0
    const auto volatile_xmm = run(vector_call, 1, {}, unresolved_imports);
    require(volatile_xmm.edges.empty() && volatile_xmm.vector_operations >= 3,
            "external pool model retained volatile XMM0");
    auto tail_helper = unresolved;
    const std::vector<uint8_t> native_call = {0xe8, 0xe7, 0, 0, 0, 0x90};
    std::copy(native_call.begin(), native_call.end(), tail_helper.segs[0].bytes.begin() + 20);
    const std::vector<uint8_t> native_tail = {0xff, 0x25, 0xfa, 2, 0, 0};
    std::copy(native_tail.begin(), native_tail.end(), tail_helper.segs[0].bytes.begin() + 0x100);
    const auto tail_report = run(tail_helper, 1, {}, unresolved_imports);
    require(tail_report.external_calls == 1 && tail_report.edges.size() == 2,
            "external tail call lost its native caller return");
    auto alloc_free = unresolved;
    const std::vector<uint8_t> pool_lifetime = {
        0x48, 0x83, 0xec, 0x28, 0xb9, 1,    0,    0,    0,    0xba, 32,   0,    0,
        0,    0x41, 0xb8, 0x45, 0x50, 0,    0,    0xff, 0x15, 0xe6, 3,    0,    0,
        0x48, 0x85, 0xc0, 0x74, 0x0e, 0x48, 0x89, 0xc1, 0xba, 0x45, 0x50, 0,    0,
        0xff, 0x15, 0xdb, 3,    0,    0,    0x48, 0x83, 0xc4, 0x28, 0x31, 0xc0, 0xc3};
    std::copy(pool_lifetime.begin(), pool_lifetime.end(), alloc_free.segs[0].bytes.begin());
    alloc_free.segs[0].mask[0x408 / 8] = 0;
    const auto lifetime_report = run(alloc_free, 1, {},
                                     {{0x1400, "ntoskrnl.exe", "ExAllocatePoolWithTag", 0},
                                      {0x1408, "ntoskrnl.exe", "ExFreePoolWithTag", 0}});
    require(lifetime_report.external_calls == 2 && lifetime_report.edges.size() == 2 &&
                std::none_of(lifetime_report.frontiers.begin(), lifetime_report.frontiers.end(),
                             [](const auto &f)
                             { return f.reason.find("no matching live") != std::string::npos; }),
            "native allocate/free paths lost lifetime, tag or void-return semantics");
    field(0x400, UINT64_MAX - 10, 8);
    rejects_imports([&] { warbird::read_pe_imports(imported, 0x1000, 0x200, 40); },
                    "bound IAT was parsed as a lookup table");
    // Finite covers are exhaustive, including a proof beyond the last model.
    z3::context context;
    auto x = context.bv_const("key_input", 64);
    auto choice = context.bool_const("choice");
    auto numeral = [&](uint64_t n) { return context.bv_val(n, 64); };
    const auto merged =
        warbird::merge_ranges({{0x1008, 0x1010}, {0x1000, 0x1008}, {0x2000, 0x2008}});
    require(merged == warbird::AddressRanges({{0x1000, 0x1010}, {0x2000, 0x2008}}),
            "alias ranges did not merge overlapping/adjacent intervals");
    warbird::AliasOracle alias_oracle(context);
    const warbird::AddressRanges region{{0x4000, 0x5000}};
    auto outside_region = z3::ult(x, numeral(0x4000)) || z3::uge(x, numeral(0x5000));
    require(alias_oracle.classify(x, 1, outside_region, region) == warbird::AliasResult::DISJOINT,
            "alias oracle failed a disjoint byte proof");
    const auto query_count = alias_oracle.queries();
    require(alias_oracle.classify(x, 1, outside_region, region) == warbird::AliasResult::DISJOINT &&
                alias_oracle.queries() == query_count,
            "alias proof cache did not reuse the same retained AST identity");
    require(alias_oracle.classify(x, 2, outside_region, region) == warbird::AliasResult::MAY_ALIAS,
            "multi-byte overlap was lost at a range boundary");
    require(alias_oracle.classify(numeral(UINT64_MAX), 2, context.bool_val(true), {{0, 1}}) ==
                warbird::AliasResult::MAY_ALIAS,
            "alias proof ignored a write wrapping through address zero");
    warbird::AliasOracle no_queries(context, 0);
    require(no_queries.classify(x, 1, outside_region, region) == warbird::AliasResult::UNKNOWN,
            "unproved alias query was treated as disjoint");
    auto satisfiable = [&](const z3::expr &expression)
    {
        z3::solver solver(context);
        solver.add(expression);
        return solver.check() == z3::sat;
    };
    for (unsigned bytes = 1; bytes <= 16; ++bytes)
        for (const auto &range :
             warbird::AddressRanges{{0, 1}, {0x4000, 0x5000}, {UINT64_MAX - 16, UINT64_MAX}})
        {
            auto bytewise = context.bool_val(false);
            for (unsigned byte = 0; byte < bytes; ++byte)
            {
                const auto at = x + numeral(byte);
                bytewise = bytewise || (z3::uge(at, numeral(range.first)) &&
                                        z3::ult(at, numeral(range.second)));
            }
            require(!satisfiable(bytewise != warbird::overlaps(x, bytes, {range})),
                    "compact modular overlap check differs from byte-wise definition");
        }
    {
        z3::context other;
        rejects_imports(
            [&]
            { alias_oracle.classify(other.bv_const("x", 64), 1, other.bool_val(true), region); },
            "alias proof cache accepted a foreign Z3 context");
    }
    const auto allocation =
        warbird::pool_allocate({}, numeral(1), numeral(24), numeral(0x5045), numeral(0x10000));
    require(allocation.size() == 3 && satisfiable(allocation[1].condition) &&
                satisfiable(allocation[2].condition) && !satisfiable(allocation[0].condition),
            "pool allocation lost failure or success outcome");
    const auto &live_pool = allocation[2].state;
    auto overlapping = warbird::pool_allocate(live_pool, numeral(1), numeral(24), numeral(0x5045),
                                              numeral(0x10010));
    require(!satisfiable(overlapping[2].condition), "overlapping live pool allocation accepted");
    auto freed = warbird::pool_free(live_pool, numeral(0x10000), numeral(0x5045), x);
    require(freed.size() == 2 && satisfiable(freed[0].condition) &&
                !freed[0].state.blocks[0].live && !satisfiable(freed[1].condition),
            "pool free lost base/tag/lifetime relation");
    auto double_free = warbird::pool_free(freed[0].state, numeral(0x10000), numeral(0x5045), x);
    require(double_free.size() == 1 && !double_free[0].frontier.empty() &&
                satisfiable(double_free[0].condition),
            "double free was accepted");
    auto wrong_tag = warbird::pool_free(live_pool, numeral(0x10000), numeral(0x5046), x);
    require(!satisfiable(wrong_tag[0].condition) && satisfiable(wrong_tag[1].condition),
            "wrong pool tag was accepted");
    auto reuse = warbird::pool_allocate(freed[0].state, numeral(1), numeral(24), numeral(0x5045),
                                        numeral(0x10000));
    require(satisfiable(reuse[2].condition), "freed pool address could not be reused");
    for (auto type : {0u, 1u, 512u, 17u})
        for (auto size : {0u, 1u, 16u, 32u, 4095u, 4096u, 4097u})
            for (auto pointer : {0u, 0x10000u, 0x10010u, 0x10ff0u})
            {
                auto candidate = warbird::pool_allocate({}, numeral(type), numeral(size),
                                                        numeral(1), numeral(pointer));
                bool expected =
                    (type == 0 || type == 1 || type == 512) && size != 0 && pointer != 0 &&
                    (pointer & 15) == 0 &&
                    (size >= 4096 ? (pointer & 4095) == 0 : (pointer & 4095) + size <= 4096);
                require(satisfiable(candidate[2].condition) == expected,
                        "pool alignment/type/size boundary mismatch");
            }
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
    warbird::ByteMemory reused(context);
    reused.write(numeral(0x4000), numeral(0x1122334455667788), 64);
    const auto before_havoc = reused;
    auto fresh_bytes = context.constant(
        "fresh_pool_bytes", context.array_sort(context.bv_sort(64), context.bv_sort(8)));
    reused.havoc(numeral(0x4002), numeral(2), fresh_bytes);
    auto expected_fresh = z3::concat(z3::select(fresh_bytes, numeral(0x4003)),
                                     z3::select(fresh_bytes, numeral(0x4002)));
    require(!satisfiable(reused.read(numeral(0x4002), 16) != expected_fresh) &&
                !satisfiable(reused.read(numeral(0x4004), 32) != context.bv_val(0x11223344, 32)) &&
                satisfiable(reused.read(numeral(0x4002), 16) != context.bv_val(0, 16)),
            "pool reuse lost fresh bytes or changed bytes outside allocation");
    require(before_havoc.read(numeral(0x4000), 64).is_numeral_u64(retained) &&
                retained == 0x1122334455667788ULL,
            "range havoc changed another memory fork");
    auto symbolic_havoc = before_havoc;
    symbolic_havoc.havoc(x, numeral(1), fresh_bytes);
    require(!satisfiable(symbolic_havoc.read(x, 8) != z3::select(fresh_bytes, x)),
            "symbolic range havoc did not freshen addressed byte");
    auto ordinary_write = before_havoc, isolated_write = before_havoc;
    ordinary_write.write(x, context.bv_val(0xee, 8), 8);
    isolated_write.write(x, context.bv_val(0xee, 8), 8, region);
    auto write_probe = context.bv_const("write_probe", 64);
    require(!satisfiable(outside_region && ordinary_write.read(write_probe, 8) !=
                                               isolated_write.read(write_probe, 8)),
            "isolated symbolic write violated its no-overlap proof");
    require(isolated_write.read(numeral(0x4000), 64).is_numeral_u64(retained) &&
                retained == 0x1122334455667788ULL,
            "isolated symbolic write obscured a disjoint concrete cell");
    require(satisfiable(x == numeral(0x4000) && ordinary_write.read(numeral(0x4000), 8) !=
                                                    isolated_write.read(numeral(0x4000), 8)),
            "alias regression does not test the necessity of the no-overlap guard");
    auto naive_pool_havoc = before_havoc;
    auto disjoint_pool_havoc = before_havoc;
    naive_pool_havoc.havoc(x, numeral(16), fresh_bytes);
    disjoint_pool_havoc.havoc(x, numeral(16), fresh_bytes, {{0x4000, 0x5000}});
    const auto disjoint =
        z3::ugt(x + numeral(16), x) &&
        (z3::ule(x + numeral(16), numeral(0x4000)) || z3::uge(x, numeral(0x5000)));
    auto probe = context.bv_const("havoc_probe", 64);
    require(!satisfiable(disjoint &&
                         naive_pool_havoc.read(probe, 8) != disjoint_pool_havoc.read(probe, 8)),
            "excluded pool ranges changed memory despite disjointness proof");
    require(disjoint_pool_havoc.read(numeral(0x4000), 64).is_numeral_u64(retained) &&
                retained == 0x1122334455667788ULL,
            "disjoint pool havoc obscured concrete private memory");
    warbird::ByteMemory wide_memory(context);
    auto wide_value = z3::concat(numeral(0x1020304050607080), numeral(0x90a0b0c0d0e0f001));
    wide_memory.write(numeral(0x5000), wide_value, 128);
    wide_memory.write(numeral(0x5007), context.bv_val(0x1234, 16), 16);
    auto wide_expected =
        z3::concat(z3::concat(wide_value.extract(127, 72), context.bv_val(0x1234, 16)),
                   wide_value.extract(55, 0));
    require(!satisfiable(wide_memory.read(numeral(0x5000), 128) != wide_expected),
            "128-bit memory lost overlapping scalar bytes");
    warbird::ByteMemory wide_quota(context, 8);
    rejects_imports([&] { wide_quota.write(numeral(0), wide_value, 128); },
                    "128-bit store exceeded concrete-byte quota");
    require(wide_quota.concrete_bytes() == 0, "128-bit rejected store partially committed");
    // Caching a dispatch pointer under its equality guard must preserve every
    // byte of memory; without that guard the same replacement is not valid.
    warbird::ByteMemory binding_memory(context);
    const auto binding_before = binding_memory.materialize();
    const auto binding_slot = numeral(0x7800);
    const auto binding_expected = numeral(0x12345678abcdef00ULL);
    const auto binding_equal = binding_memory.read(binding_slot, 64) == binding_expected;
    binding_memory.write(binding_slot, binding_expected, 64);
    const auto binding_probe = context.bv_const("dispatch_binding_probe", 64);
    const auto binding_difference =
        z3::select(binding_before, binding_probe) != binding_memory.read(binding_probe, 8);
    z3::solver binding_solver(context);
    binding_solver.set("timeout", 1000u);
    binding_solver.add(binding_equal && binding_difference);
    require(binding_solver.check() == z3::unsat,
            "guarded dispatch pointer normalization changed memory");
    binding_solver.reset();
    binding_solver.add(binding_difference);
    require(binding_solver.check() == z3::sat,
            "dispatch pointer normalization guard necessity was not exercised");
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
    auto misaligned = run(fixture({0x0f, 0x28, 0x41, 1, 0x31, 0xc0, 0xc3}));
    require(misaligned.edges.empty() && misaligned.frontiers.size() == 1 &&
                misaligned.frontiers[0].reason == "misaligned vector memory address",
            "aligned vector access did not reject a misaligned address");
    auto maybe_aligned = run(fixture({0x48, 0x8b, 0x01, 0x0f, 0x28, 0x00, 0x31, 0xc0, 0xc3}));
    require(maybe_aligned.edges.size() == 1 && !maybe_aligned.frontiers.empty(),
            "symbolic vector alignment lost either the fault or normal continuation");
    auto zero = fixture({0x31, 0xc0, 0xc3});
    auto r = run(zero);
    require(r.exploration_complete() && r.edges.size() == 1 && r.edges[0].next == 0,
            "zero-key return must terminate");
    // A repeated-store relation agrees with ordered individual stores at every
    // queried byte, including a symbolic base that may wrap through zero.
    {
        z3::context c;
        const auto at = c.bv_const("repeat_index", 64);
        // Translation by an arbitrary base is a bijection on 64-bit addresses;
        // the relative query keeps the same universal coverage and exposes
        // cancellation before the solver bit-blasts address arithmetic.
        const auto query = at + c.bv_const("byte_offset", 64);
        const auto pattern = c.bv_const("pattern", 128);
        for (unsigned count : {0u, 1u, 2u, 4u})
        {
            warbird::ByteMemory repeated(c), ordered(c);
            repeated.write(c.bv_val(7, 64), c.bv_val(0x42, 8), 8);
            ordered.write(c.bv_val(7, 64), c.bv_val(0x42, 8), 8);
            const auto initial = ordered;
            repeated.repeat(at, c.bv_val(count * 16, 64), pattern);
            for (unsigned i = 0; i < count; ++i)
                ordered.write(at + c.bv_val(i * 16, 64), pattern, 128);
            auto prove_equal =
                [&](const z3::expr &left, const z3::expr &right, const z3::expr &domain)
            {
                z3::solver solver(c);
                solver.set("timeout", 5000u);
                solver.add(domain && left != right);
                const auto proof = solver.check();
                if (proof != z3::unsat)
                    std::cerr << "repeat proof count=" << count << " result=" << proof
                              << " reason=" << solver.reason_unknown() << '\n';
                require(proof == z3::unsat,
                        "repeated store differs from its ordered modular byte effects");
            };
            // These disjoint cases cover every modular byte address: each
            // written offset and the entire symbolic complement. Splitting
            // keeps the proof within the solver limit without dropping cases.
            for (unsigned offset = 0; offset < count * 16; ++offset)
            {
                const auto where = at + c.bv_val(offset, 64);
                prove_equal(repeated.read(where, 8), ordered.read(where, 8), c.bool_val(true));
            }
            const auto outside = z3::uge(query - at, c.bv_val(count * 16, 64));
            prove_equal(repeated.read(query, 8), initial.read(query, 8), outside);
            // Each native store preserves every outside byte for an arbitrary
            // input array. These frame properties compose across all stores.
            for (unsigned iteration = 0; iteration < count; ++iteration)
            {
                warbird::ByteMemory before(c), step(c);
                step.write(at + c.bv_val(iteration * 16, 64), pattern, 128);
                prove_equal(step.read(query, 8), before.read(query, 8), outside);
            }
        }
        // The binder name must never capture an address supplied by a caller.
        warbird::ByteMemory havoc(c);
        const auto havoc_at = c.bv_const("havoc_index", 64);
        const auto fresh = c.constant("new_bytes", c.array_sort(c.bv_sort(64), c.bv_sort(8)));
        havoc.havoc(havoc_at, c.bv_val(16, 64), fresh);
        z3::solver solver(c);
        solver.add(havoc.read(havoc_at, 8) != z3::select(fresh, havoc_at));
        require(solver.check() == z3::unsat, "havoc captured its caller's address variable");
        warbird::ByteMemory original(c);
        solver.reset();
        const auto outside_havoc = havoc_at + c.bv_val(16, 64);
        solver.add(havoc.read(outside_havoc, 8) != original.read(outside_havoc, 8));
        require(solver.check() == z3::unsat, "havoc binder changed bytes outside its interval");
    }
    // Recovery objects remain valid after the explorer and its local context
    // owners are destroyed; COW snapshots preserve the pre-write memory.
    auto artifact =
        run(fixture({0xc6, 0x01, 0x11, 0xc6, 0x01, 0x22, 0x0f, 0xb6, 0x01, 0x83, 0xf0, 0x22, 0xc3}))
            .recovery;
    require(artifact && artifact->valid() && artifact->capture_complete &&
                artifact->exploration_complete && artifact->relations.size() == 1 &&
                artifact->instructions.size() == 5,
            "complete recovery relation or its owning context was lost");
    const auto &relation = artifact->relations.front();
    const auto &entry_state = artifact->states[relation.input];
    const auto &exit_state = artifact->states[relation.output];
    auto &retained_context = *artifact->arena;
    const auto context_address = retained_context.bv_val(0x10000000000ULL, 64);
    uint64_t retained_value = 0;
    require(exit_state.memory.read(context_address, 8).is_numeral_u64(retained_value) &&
                retained_value == 0x22 && !entry_state.memory.read(context_address, 8).is_numeral(),
            "recovery output mutated its artifact input memory");
    std::vector<uint64_t> written;
    for (auto id : artifact->ordered_effects(relation))
    {
        const auto &effect = artifact->effects[id];
        require(effect.origin == warbird::EffectOrigin::Native,
                "dispatcher effects leaked into a native handler relation");
        if (effect.kind == warbird::EffectKind::Write)
        {
            require(effect.value.simplify().is_numeral_u64(retained_value),
                    "artifact write value unavailable");
            written.push_back(retained_value);
        }
    }
    require(written == std::vector<uint64_t>({0x11, 0x22}),
            "recovery discarded or reordered overwritten memory effects");
    auto guarded = run(fixture({0x80, 0x39, 0, 0x74, 7, 0xc6, 0x41, 1, 7, 0x31, 0xc0, 0xc3, 0xc6,
                                0x41, 1, 9, 0x31, 0xc0, 0xc3}))
                       .recovery;
    require(guarded && guarded->valid() && guarded->relations.size() == 2 &&
                guarded->relations[0].input == guarded->relations[1].input,
            "branch relations lost their shared input state");
    z3::solver guard_solver(*guarded->arena);
    guard_solver.add(guarded->relations[0].domain && guarded->relations[1].domain);
    require(guard_solver.check() == z3::unsat, "artifact branch guards overlap");
    guard_solver.reset();
    guard_solver.add(!(guarded->relations[0].domain || guarded->relations[1].domain));
    require(guard_solver.check() == z3::unsat, "artifact branch guards lost an alternative");
    const auto effect_path0 = guarded->ordered_effects(guarded->relations[0]);
    const auto effect_path1 = guarded->ordered_effects(guarded->relations[1]);
    require(!effect_path0.empty() && !effect_path1.empty() && effect_path0[0] == effect_path1[0],
            "forked effect histories lost their common prefix");
    warbird::Recovery damaged = *artifact;
    damaged.effects.back().previous = uint32_t(damaged.effects.size() - 1);
    require(!damaged.valid(), "cyclic recovery effects accepted");
    warbird::Recovery damaged_instruction = *artifact;
    damaged_instruction.instructions.begin()->second.operations.front().opcode = 0;
    require(!damaged_instruction.valid(), "corrupt retained SMIR operation accepted");
    warbird::Recovery damaged_state = *artifact;
    damaged_state.states.front().registers.pop_back();
    require(!damaged_state.valid(), "malformed recovery register bank accepted");
    static_assert(!std::is_copy_assignable_v<warbird::Recovery> &&
                      !std::is_move_assignable_v<warbird::Recovery> &&
                      !std::is_move_constructible_v<warbird::Recovery>,
                  "recovery arena must not be replaced while expressions are alive");
    std::weak_ptr<z3::context> copied_context;
    std::shared_ptr<const warbird::Recovery> copied_artifact;
    {
        auto original = run(fixture({0x31, 0xc0, 0xc3})).recovery;
        copied_context = original->arena;
        copied_artifact = std::make_shared<warbird::Recovery>(*original);
        original.reset();
        require(!copied_context.expired() && copied_artifact->valid(),
                "copy construction failed to retain the recovery arena");
    }
    copied_artifact.reset();
    require(copied_context.expired(), "recovery context outlived its final artifact owner");
    warbird::Limits no_capture;
    no_capture.recovery_bytes = 0;
    const auto omitted = run(zero, 1, no_capture);
    require(omitted.exploration_complete() && omitted.recovery &&
                !omitted.recovery->capture_complete && !omitted.recovery->omission.empty() &&
                omitted.recovery->relations.empty(),
            "recovery exhaustion was silent or changed the native exploration result");
    warbird::RecoveryRecorder recording(artifact->arena, artifact->lease, 8 * 1024 * 1024);
    rejects_imports(
        [&]
        {
            recording.effect(warbird::no_record, warbird::EffectOrigin::Native,
                             warbird::EffectKind::Read, 0, 8, numeral(0),
                             retained_context.bv_val(0, 8), retained_context.bv_val(1, 64));
        },
        "recovery accepted a foreign expression context");
    const auto deep_input =
        recording.state(1, 0x1000, warbird::no_record, true, true, true, entry_state.registers,
                        entry_state.vectors, entry_state.flags, entry_state.memory,
                        entry_state.stack, entry_state.pool, entry_state.domain);
    uint32_t tail = warbird::no_record;
    for (unsigned n = 0; n < 16384; ++n)
        tail = recording.effect(tail, warbird::EffectOrigin::Native, warbird::EffectKind::Read,
                                0x1000, 8, context_address, retained_context.bv_val(0, 8),
                                retained_context.bv_val(1, 64));
    const auto deep_output = recording.state(
        1, 0x1000, tail, true, true, true, exit_state.registers, exit_state.vectors,
        exit_state.flags, exit_state.memory, exit_state.stack, exit_state.pool, exit_state.domain);
    recording.relation(deep_input, deep_output, retained_context.bv_val(0, 64), entry_state.domain);
    auto deep = recording.finish(true);
    require(deep->valid() && deep->capture_complete &&
                deep->ordered_effects(deep->relations.front()).size() == 16384,
            "deep effect history was truncated or traversed incorrectly");
    auto changing_table = fixture({0x48, 0x8b, 0x01, 0xc6, 0x00, 7, 0xb8, 2, 0, 0, 0, 0xc3});
    changing_table.segs[0].bytes[0x100] = 0x31;
    changing_table.segs[0].bytes[0x101] = 0xc0;
    changing_table.segs[0].bytes[0x102] = 0xc3;
    auto writable = changing_table.segs[0];
    writable.start = 0x3000;
    writable.end = 0x4000;
    writable.perm = 6;
    changing_table.segs.push_back(std::move(writable));
    changing_table.hi = 0x4000;
    warbird::Profile table_profile{"guarded table", "",     0x3000, 0,     0,  2,
                                   {0, 1, 2, 3},    {4, 5}, 4,      false, {1}};
    warbird::Admission table_admission;
    table_admission.profile = &table_profile;
    table_admission.abstract_handler_abi = true;
    table_admission.handlers = {0x1100, 0x1000};
    warbird::Lease table_lease;
    table_lease.database = 1;
    table_lease.key = 1;
    std::atomic_bool keep_going{false};
    const auto guarded_table =
        warbird::explore(changing_table, table_admission, table_lease, {}, keep_going);
    require(guarded_table.keys == std::vector<uint64_t>({1, 2}) &&
                guarded_table.edges.size() == 2 && guarded_table.write_guard_splits >= 2 &&
                !guarded_table.frontiers.empty(),
            "possible table write lost its guarded unchanged-table continuation");
    const std::vector<uint8_t> definite_table_write = {0x48, 0xb8, 0, 0x30, 0, 0, 0, 0, 0,   0,
                                                       0xc6, 0,    7, 0xb8, 2, 0, 0, 0, 0xc3};
    std::copy(definite_table_write.begin(), definite_table_write.end(),
              changing_table.segs[0].bytes.begin());
    const auto changed_table =
        warbird::explore(changing_table, table_admission, table_lease, {}, keep_going);
    require(
        changed_table.keys == std::vector<uint64_t>({1}) &&
            std::any_of(changed_table.frontiers.begin(), changed_table.frontiers.end(),
                        [](const auto &f)
                        { return f.reason == "mutable dispatch table may have been overwritten"; }),
        "definite dispatch-table mutation incorrectly reused the admitted table");
    const auto aligned_entry =
        run(fixture({0x48, 0x89, 0xe0, 0x83, 0xe0, 15, 0x83, 0xf0, 8, 0xc3}));
    require(aligned_entry.exploration_complete() && aligned_entry.edges.size() == 1 &&
                aligned_entry.edges[0].next == 0,
            "Win64 handler entry stack alignment violated");
    r = run(zero, 0);
    require(r.exploration_complete() && r.instructions == 0,
            "zero entry must not dispatch table slot zero");
    auto alias_return = fixture({0x48, 0x8b, 0x01, 0x48, 0xc7, 0x00, 0, 0, 0, 0, 0x31, 0xc0, 0xc3});
    auto alias_report = run(alias_return);
    require(!alias_report.exploration_complete() && alias_report.return_splits == 1 &&
                alias_report.edges.size() == 1 && alias_report.edges[0].next == 0 &&
                !alias_report.frontiers.empty(),
            "ordinary return continuation or nonlocal frontier was lost");
    require(alias_report.recovery && alias_report.recovery->valid(),
            "guarded-return recovery artifact is invalid");
    for (const auto &edge : alias_report.recovery->flow)
        if (edge.kind == warbird::FlowKind::Return)
        {
            bool checked = false;
            for (const auto &access : alias_report.recovery->effects)
                if (access.site == edge.source && access.kind == warbird::EffectKind::Read &&
                    access.bits == 64 && access.origin == warbird::EffectOrigin::Native)
                {
                    z3::solver guarded_return_solver(*alias_report.recovery->arena);
                    guarded_return_solver.add(
                        edge.domain &&
                        access.value != alias_report.recovery->arena->bv_val(edge.target, 64));
                    require(guarded_return_solver.check() == z3::unsat,
                            "retained return edge forgot its target equality guard");
                    checked = true;
                }
            require(checked, "retained return edge has no saved-address read");
        }
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
    table.end = 0x3020;
    table.perm = 4;
    table.bitness = 2;
    table.mask = {255, 255, 255, 255};
    table.bytes.resize(32);
    for (unsigned i = 0; i < 2; ++i)
    {
        table.bytes[i * 8] = 0x80;
        table.bytes[i * 8 + 1] = 0x10;
    }
    table.bytes[16] = 0;
    table.bytes[17] = 0x1f;
    native.segs[0].bytes[0xf00] = 0xff;
    native.segs[0].bytes[0xf01] = 0xe0;
    for (unsigned i = 0; i < 4; ++i)
        native.segs[0].bytes[25 + i] = uint8_t((0x2010 - 29) >> (i * 8));
    native.segs.push_back(table);
    warbird::Profile profile{"test", "", 0x2000, 0,   0,    2,           {0, 1, 2, 3},
                             {4, 5}, 4,  false,  {1}, 0x60, {0x31, 0xc0}};
    auto accepted = warbird::admit(native, 0x1000, profile);
    require(accepted.valid(), "valid dispatcher rejected");
    require(accepted.handler_return == 0x101d && accepted.dispatch_pointer == 0x3010 &&
                accepted.dispatch_target == 0x1f00 && !accepted.abstract_handler_abi,
            "native dispatcher transfer contract was not derived from bytes");
    auto bad_thunk = native;
    bad_thunk.segs[0].bytes[0xf00] = 0xc3;
    require(!warbird::admit(bad_thunk, 0x1000, profile).valid(),
            "returning thunk was admitted as a tail transfer");
    auto missing_pointer = native;
    missing_pointer.segs[1].mask[2] = 0;
    require(!warbird::admit(missing_pointer, 0x1000, profile).valid(),
            "unloaded dispatcher transfer pointer was admitted");
    auto changed_pointer = native;
    changed_pointer.segs[1].bytes[16] = 8;
    require(!warbird::dependencies_match(changed_pointer, accepted.dependencies),
            "dispatcher transfer pointer change did not invalidate its lease");

    auto zero_profile = profile;
    zero_profile.setup_rva = 0x70;
    zero_profile.setup_bytes = {0x48, 0x83, 0xa5, 0xc8, 1, 0, 0, 0};
    zero_profile.zero_slot = 55;
    auto zero_native = native;
    std::copy(zero_profile.setup_bytes.begin(), zero_profile.setup_bytes.end(),
              zero_native.segs[0].bytes.begin() + 0x70);
    const std::vector<uint8_t> read_zero_slot = {0x48, 0x8b, 0x81, 0xb8, 1, 0, 0, 0xc3};
    std::copy(read_zero_slot.begin(), read_zero_slot.end(),
              zero_native.segs[0].bytes.begin() + 0x80);
    auto zero_admission = warbird::admit(zero_native, 0x1000, zero_profile);
    require(zero_admission.valid() && zero_admission.zero_slots == std::vector<unsigned>({55}),
            "verified native zero slot was not admitted");
    warbird::Lease zero_lease;
    zero_lease.database = 1;
    zero_lease.key = 1;
    zero_lease.base = 0x1000;
    std::atomic_bool zero_cancel{false};
    auto initialized = warbird::explore(zero_native, zero_admission, zero_lease, {}, zero_cancel);
    require(initialized.exploration_complete() && initialized.edges.size() == 1 &&
                initialized.edges[0].next == 0 &&
                initialized.context_zero_slots == std::vector<unsigned>({55}),
            "native zero slot did not seed the initial context");
    auto neighbor_native = zero_native;
    neighbor_native.segs[0].bytes[0x83] = 0xb0; // adjacent, uninitialized slot 54
    auto neighbor_admission = warbird::admit(neighbor_native, 0x1000, zero_profile);
    auto neighbor =
        warbird::explore(neighbor_native, neighbor_admission, zero_lease, {}, zero_cancel);
    require(!neighbor.exploration_complete() && neighbor.edges.empty(),
            "native zero slot contaminated an adjacent unknown slot");
    auto wrong_slot = zero_profile;
    wrong_slot.zero_slot = 54;
    require(!warbird::admit(zero_native, 0x1000, wrong_slot).valid(),
            "zero-slot metadata contradicted native instruction displacement");
    auto wrong_zero = zero_native;
    wrong_zero.segs[0].bytes[0x77] = 1;
    auto wrong_zero_profile = zero_profile;
    wrong_zero_profile.setup_bytes[7] = 1;
    require(!warbird::admit(wrong_zero, 0x1000, wrong_zero_profile).valid(),
            "nonzero AND immediate admitted as zero initialization");
    auto stack_native = zero_native;
    auto stack_profile = zero_profile;
    const std::vector<uint8_t> align_floor = {0x48, 0x8d, 0x59, 0x0f, 0x48, 0x83, 0xe3, 0xf0};
    stack_profile.setup_bytes.insert(stack_profile.setup_bytes.end(), align_floor.begin(),
                                     align_floor.end());
    stack_profile.dispatcher_rva = 0x10;
    stack_profile.frame_bytes.resize(0x60, 0x90);
    const std::vector<uint8_t> frame_prologue = {0x40, 0x55, 0x48, 0x81, 0xec, 0,    2,
                                                 0,    0,    0x48, 0x8d, 0x6c, 0x24, 0x20};
    const std::vector<uint8_t> frame_reserve = {0x48, 0x83, 0xec, 0x10, 0x8b, 0x04, 0x24,
                                                0x8b, 0x04, 0x24, 0x48, 0x83, 0xec, 0x40,
                                                0x48, 0x8d, 0x4c, 0x24, 0x20, 0x8b, 0x01};
    std::copy(frame_prologue.begin(), frame_prologue.end(), stack_profile.frame_bytes.begin());
    std::copy(frame_reserve.begin(), frame_reserve.end(),
              stack_profile.frame_bytes.end() - frame_reserve.size());
    std::copy(stack_profile.frame_bytes.begin(), stack_profile.frame_bytes.end(),
              stack_native.segs[0].bytes.begin() + stack_profile.dispatcher_rva);
    const std::vector<uint8_t> native_maintenance = {
        0x48, 0x85, 0xd2, 0x74, 0x6a, 0x48, 0x8b, 0x85, 0xc8, 0x01, 0x00, 0x00, 0x48, 0x85, 0xc0,
        0x74, 0x39, 0x48, 0x3b, 0xc3, 0x73, 0x34, 0x48, 0x2b, 0xd8, 0x8b, 0xc3, 0x48, 0x8d, 0x48,
        0x0f, 0x48, 0x3b, 0xc8, 0x77, 0x0a, 0x48, 0xb9, 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x0f, 0x48, 0x83, 0xe1, 0xf0, 0x48, 0x8b, 0xc1, 0xe8, 0xb0, 0x6c, 0xf7, 0xff, 0x48, 0x2b,
        0xe1, 0x48, 0x83, 0xa5, 0xc8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x5c, 0x24, 0x20};
    const std::vector<uint8_t> native_seed = {0x33, 0xc0, 0x48, 0x89, 0x5d, 0x30, 0x48, 0x89, 0x5d,
                                              0x38, 0x48, 0x89, 0x03, 0x48, 0x8b, 0x85, 0x10, 0x02,
                                              0,    0,    0x48, 0x89, 0x45, 0x28, 0x4c, 0x89, 0x55,
                                              0x10, 0x4c, 0x89, 0x45, 0x18, 0x4c, 0x89, 0x4d, 0x20};
    stack_profile.setup_bytes.insert(stack_profile.setup_bytes.end(), native_seed.begin(),
                                     native_seed.end());
    const auto maintenance_offset = stack_profile.setup_bytes.size();
    stack_profile.setup_bytes.insert(stack_profile.setup_bytes.end(), native_maintenance.begin(),
                                     native_maintenance.end());
    stack_profile.dispatch_rva = stack_profile.setup_rva + stack_profile.setup_bytes.size();
    stack_profile.stack_maintenance = true;
    std::copy(stack_profile.setup_bytes.begin(), stack_profile.setup_bytes.end(),
              stack_native.segs[0].bytes.begin() + 0x70);
    std::copy_n(native.segs[0].bytes.begin(), 43,
                stack_native.segs[0].bytes.begin() + stack_profile.dispatch_rva);
    const uint32_t displacement = uint32_t(0x2000 - stack_profile.dispatch_rva - 10);
    for (unsigned i = 0; i < 4; ++i)
        stack_native.segs[0].bytes[stack_profile.dispatch_rva + 6 + i] =
            uint8_t(displacement >> (8 * i));
    for (unsigned i = 0; i < 4; ++i)
        stack_native.segs[0].bytes[stack_profile.dispatch_rva + 25 + i] =
            uint8_t((0x2010 - stack_profile.dispatch_rva - 29) >> (8 * i));
    stack_native.segs[1].bytes[0] = 0;
    stack_native.segs[1].bytes[1] = 0x15;
    stack_native.segs[1].bytes[8] = 0;
    stack_native.segs[1].bytes[9] = 0x14;
    const std::vector<uint8_t> stack_request = {0x48, 0x8b, 0x41, 0x20, 0x48, 0x83, 0xe8,
                                                17,   0x48, 0x89, 0x81, 0xb8, 1,    0,
                                                0,    0xb8, 2,    0,    0,    0,    0xc3};
    std::copy(stack_request.begin(), stack_request.end(),
              stack_native.segs[0].bytes.begin() + 0x400);
    // The initial virtual stack, RSP home area and context share native storage.
    // After a 32-byte growth, the old zero word is both [RBX+32] and [RCX-96].
    const std::vector<uint8_t> stack_aliases = {0x48, 0x8d, 0x44, 0x24, 0x28, 0x48, 0x39, 0xd8,
                                                0x75, 0x10, 0x48, 0x8b, 0x41, 0xa0, 0x48, 0x0b,
                                                0x43, 0x20, 0x48, 0x0b, 0x81, 0xb8, 1,    0,
                                                0,    0xc3, 0xb8, 3,    0,    0,    0,    0xc3};
    std::copy(stack_aliases.begin(), stack_aliases.end(),
              stack_native.segs[0].bytes.begin() + 0x500);
    auto stack_admission = warbird::admit(stack_native, 0x1000, stack_profile);
    require(stack_admission.valid() && stack_admission.stack_maintenance &&
                stack_admission.context_stack_gap == 96,
            "stack maintenance witness rejected");
    auto return_reader = stack_native;
    std::vector<uint8_t> read_native_return = {0x48, 0x8b, 0x04, 0x24, 0x48, 0xba};
    for (unsigned byte = 0; byte < 8; ++byte)
        read_native_return.push_back(uint8_t(stack_admission.handler_return >> (byte * 8)));
    read_native_return.insert(read_native_return.end(), {0x48, 0x31, 0xd0, 0xc3});
    std::copy(read_native_return.begin(), read_native_return.end(),
              return_reader.segs[0].bytes.begin() + 0x400);
    auto observed_return =
        warbird::explore(return_reader, stack_admission, zero_lease, {}, zero_cancel);
    require(observed_return.exploration_complete() && observed_return.edges.size() == 1 &&
                observed_return.edges[0].next == 0 &&
                observed_return.handler_return == stack_admission.handler_return,
            "native handler observed a synthetic return address");
    auto carry_native = stack_native;
    const std::vector<uint8_t> set_carry = {
        0x41, 0xb8, 0x11, 0,    0,    0,    0x41, 0xb9, 0x22, 0, 0,    0,    0x41, 0xba,
        0x33, 0,    0,    0,    0x41, 0xbb, 0x44, 0,    0,    0, 0x66, 0x49, 0x0f, 0x6e,
        0xc0, 0x66, 0x49, 0x0f, 0x6e, 0xe9, 0xb8, 2,    0,    0, 0,    0xc3};
    const std::vector<uint8_t> check_carry = {
        0x4c, 0x89, 0xc0, 0x48, 0x83, 0xf0, 0x11, 0x49, 0x83, 0xf1, 0x22, 0x4c, 0x09, 0xc8,
        0x49, 0x83, 0xf2, 0x33, 0x4c, 0x09, 0xd0, 0x49, 0x83, 0xf3, 0x44, 0x4c, 0x09, 0xd8,
        0x66, 0x48, 0x0f, 0x7e, 0xc2, 0x48, 0x83, 0xf2, 0x11, 0x48, 0x09, 0xd0, 0x66, 0x48,
        0x0f, 0x7e, 0xea, 0x48, 0x83, 0xf2, 0x22, 0x48, 0x09, 0xd0, 0xc3};
    std::copy(set_carry.begin(), set_carry.end(), carry_native.segs[0].bytes.begin() + 0x400);
    std::copy(check_carry.begin(), check_carry.end(), carry_native.segs[0].bytes.begin() + 0x500);
    const auto carried =
        warbird::explore(carry_native, stack_admission, zero_lease, {}, zero_cancel);
    require(carried.exploration_complete() && carried.edges.size() == 2 &&
                carried.edges.back().next == 0 && carried.dispatch_instructions == 14,
            "native dispatch lost volatile GPR or XMM values between handlers");
    auto dispatch_flags = stack_native;
    const std::vector<uint8_t> set_cf = {0xf9, 0xb8, 2, 0, 0, 0, 0xc3};
    const std::vector<uint8_t> check_flags = {
        0x0f, 0x92, 0xc0, 0x0f, 0x94, 0xc2, 0x0f, 0x98, 0xc1, 0x41, 0x0f, 0x9a,
        0xc0, 0x0f, 0xb6, 0xc0, 0x0f, 0xb6, 0xd2, 0x0f, 0xb6, 0xc9, 0x45, 0x0f,
        0xb6, 0xc0, 0xd1, 0xe2, 0xc1, 0xe1, 2,    0x41, 0xc1, 0xe0, 3,    0x09,
        0xd0, 0x09, 0xc8, 0x44, 0x09, 0xc0, 0x83, 0xf0, 10,   0xc3};
    std::copy(set_cf.begin(), set_cf.end(), dispatch_flags.segs[0].bytes.begin() + 0x400);
    std::copy(check_flags.begin(), check_flags.end(), dispatch_flags.segs[0].bytes.begin() + 0x500);
    const auto flag_result =
        warbird::explore(dispatch_flags, stack_admission, zero_lease, {}, zero_cancel);
    require(flag_result.exploration_complete() && flag_result.edges.size() == 2 &&
                flag_result.edges.back().next == 0 && flag_result.dispatch_instructions == 14,
            "native dispatch did not reproduce index-mask arithmetic flags");
    auto growth_carry = carry_native;
    std::vector<uint8_t> grow_then_set = {0x48, 0x8b, 0x41, 0x20, 0x48, 0x83, 0xe8, 17,
                                          0x48, 0x89, 0x81, 0xb8, 1,    0,    0};
    grow_then_set.insert(grow_then_set.end(), set_carry.begin(), set_carry.end());
    std::copy(grow_then_set.begin(), grow_then_set.end(),
              growth_carry.segs[0].bytes.begin() + 0x400);
    const auto uncertain_carry =
        warbird::explore(growth_carry, stack_admission, zero_lease, {}, zero_cancel);
    require(!uncertain_carry.exploration_complete() && uncertain_carry.stack_growth_paths == 1 &&
                uncertain_carry.edges.size() == 1,
            "unmodeled stack probe acquired exact volatile-state preservation");
    warbird::Limits dispatch_quota;
    dispatch_quota.instructions = carried.initialization_instructions + 3;
    const auto limited_dispatch =
        warbird::explore(carry_native, stack_admission, zero_lease, dispatch_quota, zero_cancel);
    require(limited_dispatch.keys.empty() && limited_dispatch.dispatch_instructions == 3 &&
                !limited_dispatch.exploration_complete(),
            "partial dispatcher execution was published as a handler entry");
    auto writable_dispatch = stack_native;
    writable_dispatch.segs[1].perm = 6;
    const std::vector<uint8_t> symbolic_pointer_write = {0x48, 0x8b, 0x01, 0xc6, 0x00, 7,
                                                         0xb8, 2,    0,    0,    0,    0xc3};
    std::copy(symbolic_pointer_write.begin(), symbolic_pointer_write.end(),
              writable_dispatch.segs[0].bytes.begin() + 0x400);
    const std::vector<uint8_t> stop_dispatch = {0x31, 0xc0, 0xc3};
    std::copy(stop_dispatch.begin(), stop_dispatch.end(),
              writable_dispatch.segs[0].bytes.begin() + 0x500);
    auto writable_admission = warbird::admit(writable_dispatch, 0x1000, stack_profile);
    auto guarded_dispatch =
        warbird::explore(writable_dispatch, writable_admission, zero_lease, {}, zero_cancel);
    require(guarded_dispatch.keys == std::vector<uint64_t>({1, 2}) &&
                std::any_of(guarded_dispatch.frontiers.begin(), guarded_dispatch.frontiers.end(),
                            [](const auto &f)
                            { return f.reason == "possible dispatcher transfer pointer write"; }),
            "writable dispatcher pointer lost its guarded continuation");
    const std::vector<uint8_t> definite_pointer_write = {0x48, 0xb8, 0x10, 0x30, 0,    0, 0,   0,
                                                         0,    0,    0x48, 0xc7, 0x00, 0, 0,   0,
                                                         0,    0xb8, 2,    0,    0,    0, 0xc3};
    std::copy(definite_pointer_write.begin(), definite_pointer_write.end(),
              writable_dispatch.segs[0].bytes.begin() + 0x400);
    auto changed_dispatch =
        warbird::explore(writable_dispatch, writable_admission, zero_lease, {}, zero_cancel);
    require(changed_dispatch.keys == std::vector<uint64_t>({1}) &&
                std::any_of(changed_dispatch.frontiers.begin(), changed_dispatch.frontiers.end(),
                            [](const auto &f)
                            { return f.reason == "dispatcher transfer pointer overwritten"; }),
            "overwritten dispatcher pointer still entered another handler");
    auto wrong_maintenance = stack_native;
    auto wrong_maintenance_profile = stack_profile;
    wrong_maintenance.segs[0].bytes[stack_profile.setup_rva + maintenance_offset] ^= 1;
    wrong_maintenance_profile.setup_bytes[maintenance_offset] ^= 1;
    require(!warbird::admit(wrong_maintenance, 0x1000, wrong_maintenance_profile).valid(),
            "nonmatching maintenance semantics were accepted from profile metadata");
    auto wrong_frame = stack_native;
    wrong_frame.segs[0].bytes[0x10] ^= 1;
    require(!warbird::admit(wrong_frame, 0x1000, stack_profile).valid(),
            "modified stack frame witness was accepted");
    auto grown = warbird::explore(stack_native, stack_admission, zero_lease, {}, zero_cancel);
    require(!grown.exploration_complete() && grown.keys == std::vector<uint64_t>({1, 2}) &&
                grown.stack_growth_paths == 1 && grown.edges.back().next == 0 &&
                grown.initialization_instructions > 0 && grown.initialization_copy_bytes == 0,
            "dispatcher failed to grow and clear its requested minimum before the next handler");
    auto correlated_argument = stack_native;
    const std::vector<uint8_t> compare_stack_argument = {0x48, 0x8b, 0x41, 0x18, 0x48, 0x33,
                                                         0x81, 0x00, 0x02, 0x00, 0x00, 0xc3};
    std::copy(compare_stack_argument.begin(), compare_stack_argument.end(),
              correlated_argument.segs[0].bytes.begin() + 0x400);
    auto correlated =
        warbird::explore(correlated_argument, stack_admission, zero_lease, {}, zero_cancel);
    require(correlated.exploration_complete() && correlated.edges.size() == 1 &&
                correlated.edges[0].next == 0 && correlated.initialization_instructions > 0,
            "native initialization lost the caller-stack argument alias");
    auto copied_setup = stack_native;
    auto copied_profile = stack_profile;
    copied_profile.copies_fifth_argument = true;
    const std::vector<uint8_t> copy_reserve = {
        0x48, 0x83, 0xec, 0x10, 0x8b, 0x04, 0x24, 0x8b, 0x04, 0x24, 0x48, 0x83, 0xec,
        0x50, 0x48, 0x8d, 0x4c, 0x24, 0x20, 0x8b, 0x01, 0x41, 0x0f, 0x10, 0x02, 0x33,
        0xc0, 0x48, 0x8d, 0x59, 0x0f, 0x48, 0x83, 0xe3, 0xf0, 0x0f, 0x11, 0x43, 0x28,
        0xf2, 0x41, 0x0f, 0x10, 0x4a, 0x10, 0xf2, 0x0f, 0x11, 0x4b, 0x38};
    std::copy(copy_reserve.begin(), copy_reserve.end(),
              copied_profile.frame_bytes.end() - copy_reserve.size());
    std::copy(copied_profile.frame_bytes.begin(), copied_profile.frame_bytes.end(),
              copied_setup.segs[0].bytes.begin() + copied_profile.dispatcher_rva);
    const std::vector<uint8_t> return_zero = {0x31, 0xc0, 0xc3};
    std::copy(return_zero.begin(), return_zero.end(), copied_setup.segs[0].bytes.begin() + 0x400);
    copied_profile.setup_bytes[16 + 26] = 0x5d; // Store R11 as ClipSp's first argument.
    std::copy(copied_profile.setup_bytes.begin(), copied_profile.setup_bytes.end(),
              copied_setup.segs[0].bytes.begin() + copied_profile.setup_rva);
    auto copied_admission = warbird::admit(copied_setup, 0x1000, copied_profile);
    auto copied = warbird::explore(copied_setup, copied_admission, zero_lease, {}, zero_cancel);
    require(copied_admission.valid() && copied.exploration_complete() &&
                copied.initialization_copy_bytes == 24 && copied.edges.size() == 1 &&
                copied.edges[0].next == 0,
            "native initialization did not execute the complete argument copy");
    auto wrong_copy_metadata = stack_profile;
    wrong_copy_metadata.copies_fifth_argument = true;
    require(!warbird::admit(stack_native, 0x1000, wrong_copy_metadata).valid(),
            "argument-copy metadata contradicted native setup");
    auto unexpected_flow = stack_native;
    auto unexpected_profile = stack_profile;
    unexpected_profile.setup_bytes[16] = 0xeb;
    unexpected_profile.setup_bytes[17] = 0xfe;
    std::copy(unexpected_profile.setup_bytes.begin(), unexpected_profile.setup_bytes.end(),
              unexpected_flow.segs[0].bytes.begin() + unexpected_profile.setup_rva);
    auto unexpected_admission = warbird::admit(unexpected_flow, 0x1000, unexpected_profile);
    require(unexpected_admission.valid(), "initialization-flow fixture not admitted");
    auto stopped_setup =
        warbird::explore(unexpected_flow, unexpected_admission, zero_lease, {}, zero_cancel);
    require(stopped_setup.keys.empty() && !stopped_setup.exploration_complete() &&
                stopped_setup.frontiers.back().reason ==
                    "unexpected native initialization control flow",
            "initialization accepted a branch or entered a handler after failure");
    warbird::Limits initialization_quota;
    initialization_quota.instructions = 1;
    auto limited_setup = warbird::explore(stack_native, stack_admission, zero_lease,
                                          initialization_quota, zero_cancel);
    require(limited_setup.keys.empty() && limited_setup.initialization_instructions == 1 &&
                !limited_setup.exploration_complete(),
            "initialization exceeded its instruction quota");
    warbird::Limits stack_quota;
    stack_quota.stack_bytes = 16;
    auto too_deep =
        warbird::explore(stack_native, stack_admission, zero_lease, stack_quota, zero_cancel);
    require(!too_deep.exploration_complete() && too_deep.keys == std::vector<uint64_t>({1}) &&
                std::any_of(too_deep.frontiers.begin(), too_deep.frontiers.end(), [](const auto &f)
                            { return f.reason == "dispatcher stack growth quota"; }),
            "dispatcher stack quota did not retain a frontier");
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
    programs.push_back(
        fixture({0x48, 0x89, 0xd0, 0x48, 0x0f, 0xba, 0xf8, 40, 0x48, 0xc1, 0xe8, 32, 0xc3}));
    programs.push_back(
        fixture({0x48, 0x89, 0xd0, 0x48, 0x0f, 0xba, 0xe8, 40, 0x48, 0xc1, 0xe8, 32, 0xc3}));
    programs.push_back(
        fixture({0x48, 0x89, 0xd0, 0x48, 0x0f, 0xba, 0xf0, 40, 0x48, 0xc1, 0xe8, 32, 0xc3}));
    programs.push_back(fixture(
        {0x48, 0x89, 0xd0, 0x48, 0x0f, 0xba, 0xe0, 40, 0x0f, 0x92, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3}));
    programs.push_back(fixture({0x48, 0x89, 0xd0, 0x0f, 0xba, 0xf8, 31, 0xc3}));
    programs.push_back(fixture({0x48, 0x89, 0xd0, 0x66, 0x0f, 0xba, 0xf8, 15, 0xc3}));
    programs.push_back(
        fixture({0x48, 0x89, 0x11, 0x48, 0x0f, 0xba, 0x39, 40, 0x48, 0x8b, 0x01, 0xc3}));
    programs.push_back(fixture({0x48, 0x89, 0x11, 0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x48,
                                0x0f, 0xa3, 0x41, 8,    0x0f, 0x92, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3}));
    // Legacy SSE data moves are compared through the independent native decoder/interpreter.
    programs.push_back(fixture(
        {0x66, 0x48, 0x0f, 0x6e, 0xc2, 0x66, 0x48, 0x0f, 0x7e, 0xc0, 0x48, 0xc1, 0xe8, 32, 0xc3}));
    programs.push_back(fixture(
        {0x66, 0x0f, 0x6e, 0xc2, 0x66, 0x48, 0x0f, 0x7e, 0xc0, 0x48, 0xc1, 0xe8, 32, 0xc3}));
    programs.push_back(fixture({0x66, 0x48, 0x0f, 0x6e, 0xc2, 0x0f, 0x16, 0xc0, 0x0f, 0x11,
                                0x01, 0x48, 0x8b, 0x41, 8,    0x48, 0xc1, 0xe8, 32,   0xc3}));
    programs.push_back(fixture({0x66, 0x4c, 0x0f, 0x6e, 0xc2, 0x45, 0x0f, 0x16, 0xc0, 0x44, 0x0f,
                                0x11, 0x01, 0x48, 0x8b, 0x41, 8,    0x48, 0xc1, 0xe8, 32,   0xc3}));
    programs.push_back(fixture({0x48, 0x89, 0xd0, 0xf9, 0x0f, 0x57, 0xc0, 0x48, 0x83, 0xd0, 0, 0x48,
                                0xc1, 0xe8, 32, 0xc3}));
    programs.push_back(
        fixture({0x48, 0xff, 0xc1, 0x48, 0x89, 0x11, 0x48, 0x89, 0x51, 8,    0xf3, 0x0f, 0x6f, 0x01,
                 0x0f, 0x12, 0xc0, 0x66, 0x48, 0x0f, 0x7e, 0xc0, 0x48, 0xc1, 0xe8, 32,   0xc3}));
    programs.push_back(
        fixture({0x66, 0x48, 0x0f, 0x6e, 0xc2, 0x0f, 0x16, 0xc0, 0x0f, 0x57, 0xc9, 0xf3, 0x0f, 0x10,
                 0xc1, 0x0f, 0x29, 0x01, 0x48, 0x8b, 0x41, 8,    0x48, 0xc1, 0xe8, 32,   0xc3}));
    programs.push_back(fixture({0x0f, 0x10, 0x05, 0xf9, 0,    0,    0,    0x0f, 0x12, 0xc0,
                                0x66, 0x48, 0x0f, 0x7e, 0xc0, 0x48, 0xc1, 0xe8, 32,   0xc3}));
    programs.push_back(
        fixture({0x66, 0x48, 0x0f, 0x6e, 0xc2, 0x0f, 0x16, 0xc0, 0x0f, 0x11, 0x01, 0xf3,
                 0x0f, 0x7e, 0x01, 0x0f, 0x12, 0xc0, 0x66, 0x48, 0x0f, 0x7e, 0xc0, 0xc3}));
    programs.push_back(
        fixture({0x66, 0x48, 0x0f, 0x6e, 0xc2, 0x0f, 0x16, 0xc0, 0x0f, 0x11, 0x01, 0xf3, 0x0f,
                 0x10, 0x01, 0x66, 0x48, 0x0f, 0x7e, 0xc0, 0x48, 0xc1, 0xe8, 32,   0xc3}));
    programs.push_back(
        fixture({0x0f, 0x57, 0xc0, 0x66, 0x0f, 0xc4, 0xc2, 3, 0x66, 0x0f, 0xc5, 0xc0, 3, 0xc3}));
    programs.push_back(fixture({0x0f, 0x57, 0xc0, 0x66, 0x0f, 0x3a, 0x20, 0xc2, 7, 0x66, 0x0f, 0x3a,
                                0x14, 0xc0, 7, 0xc3}));
    programs.push_back(fixture({0x66, 0x48, 0x0f, 0x6e, 0xc2, 0x0f, 0x28, 0xc8, 0x66, 0x48, 0x0f,
                                0x7e, 0xc8, 0x48, 0xc1, 0xe8, 32, 0xc3}));
    programs.push_back(
        fixture({0x48, 0x8d, 0x69, 0xf0, 0x48, 0x89, 0x95, 0xc8, 1,    0, 0, 0x48, 0x83, 0xa5,
                 0xc8, 1,    0,    0,    0,    0x48, 0x8b, 0x85, 0xc8, 1, 0, 0,    0xc3}));
    // Match the native setup's ordered 16-byte then 8-byte copy. The forward
    // overlap overwrites the later source word before that word is loaded.
    for (uint8_t destination : {uint8_t(8), uint8_t(64)})
        programs.push_back(fixture({0x48,
                                    0x89,
                                    0x11,
                                    0x48,
                                    0xf7,
                                    0xd2,
                                    0x48,
                                    0x89,
                                    0x51,
                                    8,
                                    0x48,
                                    0xc1,
                                    0xca,
                                    7,
                                    0x48,
                                    0x89,
                                    0x51,
                                    16,
                                    0x0f,
                                    0x10,
                                    0x01,
                                    0x0f,
                                    0x11,
                                    0x41,
                                    destination,
                                    0xf2,
                                    0x0f,
                                    0x10,
                                    0x49,
                                    16,
                                    0xf2,
                                    0x0f,
                                    0x11,
                                    0x49,
                                    uint8_t(destination + 16),
                                    0x48,
                                    0x8b,
                                    0x41,
                                    destination,
                                    0x48,
                                    0x33,
                                    0x41,
                                    uint8_t(destination + 8),
                                    0x48,
                                    0x33,
                                    0x41,
                                    uint8_t(destination + 16),
                                    0xc3}));
    // A real CALL followed by JMP RAX leaves the CALL fallthrough as the
    // handler's observable return address. Vary the key independently.
    auto tail_call_program = fixture({0xb8, 0x40, 0x10, 0, 0, 0xe8, 0x16, 0, 0, 0, 0xc3});
    tail_call_program.segs[0].bytes[0x20] = 0xff;
    tail_call_program.segs[0].bytes[0x21] = 0xe0;
    const std::vector<uint8_t> inspect_tail_return = {0x48, 0x8b, 0x04, 0x24, 0x48, 0x35, 0x0a,
                                                      0x10, 0,    0,    0x48, 0x31, 0xd0, 0xc3};
    std::copy(inspect_tail_return.begin(), inspect_tail_return.end(),
              tail_call_program.segs[0].bytes.begin() + 0x40);
    programs.push_back(std::move(tail_call_program));
    // Execute each complete real setup window with controlled register and
    // memory inputs through both native RAX and the symbolic SMIR interpreter.
    for (const auto &native_profile : warbird::profiles())
    {
        std::vector<uint8_t> code = {
            0x49, 0x89, 0xe7,                   // Save the real handler RSP in R15.
            0x48, 0x8d, 0x69, 0xf0,             // RBP = context - 16.
            0x48, 0x8d, 0x61, 0xd0,             // RSP before reservation = context - 48.
            0x49, 0x89, 0xd2, 0x49, 0x89, 0xd3, // First argument in R10/R11.
            0x4c, 0x8d, 0x42, 1,    0x4c, 0x8d, 0x4a, 2,    0x48, 0x89, 0x91, 0,    2,
            0,    0,                               // Fourth argument in the caller frame.
            0x48, 0x8d, 0x81, 0,    3,    0,    0, // Fifth argument points to context+768.
            0x48, 0x89, 0x81, 8,    2,    0,    0,    0x48, 0x89, 0x10, 0x48, 0xf7, 0xd2,
            0x48, 0x89, 0x50, 8,    0x48, 0xc1, 0xca, 7,    0x48, 0x89, 0x50, 16};
        if (native_profile.copies_fifth_argument)
            code.insert(code.end(), {0x49, 0x89, 0xc2});
        const size_t prefix_size = native_profile.copies_fifth_argument ? 50 : 21;
        code.insert(code.end(), native_profile.frame_bytes.end() - prefix_size,
                    native_profile.frame_bytes.end());
        code.insert(code.end(), native_profile.setup_bytes.begin(),
                    native_profile.setup_bytes.end() - 74);
        code.insert(code.end(), {0x48, 0x8d, 0x4d, 0x10}); // Restore context in RCX.
        for (unsigned slot = 0; slot < 4; ++slot)
        {
            code.insert(code.end(), {0x48, uint8_t(slot == 0 ? 0x8b : 0x33), 0x81});
            const uint32_t offset = native_profile.argument_slots[slot] * 8;
            for (unsigned byte = 0; byte < 4; ++byte)
                code.push_back(uint8_t(offset >> (8 * byte)));
        }
        if (native_profile.copies_fifth_argument)
        {
            code.insert(code.end(), {0x48, 0x33, 0x41, 0xb8, 0x48, 0x33, 0x41, 0xc8});
        }
        code.insert(code.end(), {0x4c, 0x89, 0xfc, 0xc3}); // Restore RSP before RET.
        auto native_setup_program = fixture({});
        require(code.size() < native_setup_program.segs[0].bytes.size(),
                "native initialization program exceeds fixture");
        std::copy(code.begin(), code.end(), native_setup_program.segs[0].bytes.begin());
        programs.push_back(std::move(native_setup_program));
    }
    // Complete native dispatch scaffold, including the pointer call and tail
    // jump. Its independent closed form below checks both flag and data flow.
    auto dispatch_program = fixture({});
    std::vector<uint8_t> dispatch_code = {0x48, 0x8d, 0x69, 0xf0, 0x41, 0xb8, 17,   0,
                                          0,    0,    0x66, 0x49, 0x0f, 0x6e, 0xc0, 0xf9};
    const size_t dispatch_offset = dispatch_code.size();
    dispatch_code.insert(dispatch_code.end(), native.segs[0].bytes.begin(),
                         native.segs[0].bytes.begin() + 29);
    const uint32_t local_table = uint32_t(0x1800 - (0x1000 + dispatch_offset + 10));
    const uint32_t local_pointer = uint32_t(0x1820 - (0x1000 + dispatch_offset + 29));
    for (unsigned i = 0; i < 4; ++i)
    {
        dispatch_code[dispatch_offset + 6 + i] = uint8_t(local_table >> (8 * i));
        dispatch_code[dispatch_offset + 25 + i] = uint8_t(local_pointer >> (8 * i));
    }
    dispatch_code.insert(dispatch_code.end(),
                         {0x66, 0x48, 0x0f, 0x7e, 0xc2, 0x48, 0x31, 0xd0, 0xc3});
    std::copy(dispatch_code.begin(), dispatch_code.end(), dispatch_program.segs[0].bytes.begin());
    auto word_at = [&](size_t offset, uint64_t value)
    {
        for (unsigned i = 0; i < 8; ++i)
            dispatch_program.segs[0].bytes[offset + i] = uint8_t(value >> (8 * i));
    };
    word_at(0x800, 0x1a00);
    word_at(0x808, 0x1a40);
    word_at(0x820, 0x1900);
    dispatch_program.segs[0].bytes[0x900] = 0xff;
    dispatch_program.segs[0].bytes[0x901] = 0xe0;
    const std::vector<uint8_t> selected_handler = {0x48, 0x89, 0xd0, 0x41, 0x0f, 0x94,
                                                   0xc1, 0x45, 0x0f, 0xb6, 0xc9, 0x4c,
                                                   0x31, 0xc8, 0x4c, 0x31, 0xc0, 0xc3};
    for (size_t offset : {0xa00u, 0xa40u})
        std::copy(selected_handler.begin(), selected_handler.end(),
                  dispatch_program.segs[0].bytes.begin() + offset);
    const auto dispatch_program_index = programs.size();
    programs.push_back(std::move(dispatch_program));
    auto loop_program = fixture({});
    std::vector<uint8_t> loop_code = {0x49, 0x89, 0xd1, 0x49, 0x83, 0xe1, 7,    0x49, 0xff,
                                      0xc1, 0x66, 0x48, 0x0f, 0x6e, 0xc2, 0x0f, 0x16, 0xc0,
                                      0x48, 0x8d, 0x89, 0,    1,    0,    0};
    const auto loop_offset = loop_code.size();
    loop_code.insert(loop_code.end(), warbird::store_loop_bytes.begin(),
                     warbird::store_loop_bytes.end());
    loop_code.insert(loop_code.end(), {0x0f, 0x92, 0xc0, 0x0f, 0xb6, 0xc0, 0x48, 0x33, 0x41, 0xf0,
                                       0x4c, 0x31, 0xc8, 0xc3});
    std::copy(loop_code.begin(), loop_code.end(), loop_program.segs[0].bytes.begin());
    auto control_loop = loop_program;
    const auto return_offset = loop_code.size() - 1;
    control_loop.segs[0].bytes[return_offset] = 0x31;
    control_loop.segs[0].bytes[return_offset + 1] = 0xc0;
    control_loop.segs[0].bytes[return_offset + 2] = 0xc3;
    warbird::Limits loop_limits;
    loop_limits.states = 64;
    for (unsigned count = 1; count <= 8; ++count)
    {
        auto accelerated = run(control_loop, count, loop_limits);
        loop_limits.summarize_loops = false;
        auto ordered = run(control_loop, count, loop_limits);
        loop_limits.summarize_loops = true;
        if (accelerated.loop_summaries != 1 || ordered.loop_summaries != 0 ||
            accelerated.edges.empty() || ordered.edges.empty() || !accelerated.recovery->valid())
            std::cerr << "loop comparison input=" << count
                      << " summaries=" << accelerated.loop_summaries
                      << " accelerated_edges=" << accelerated.edges.size()
                      << " ordered_edges=" << ordered.edges.size()
                      << " valid=" << accelerated.recovery->valid() << '\n';
        require(accelerated.loop_summaries == 1 && ordered.loop_summaries == 0 &&
                    !accelerated.edges.empty() && !ordered.edges.empty() &&
                    accelerated.edges.front().next == ordered.edges.front().next &&
                    accelerated.recovery->valid() && accelerated.recovery->loops.size() == 1,
                "counted store loop differs from native instruction-by-instruction execution");
        const auto &loop = accelerated.recovery->loops.front();
        const auto &output = accelerated.recovery->states[loop.output];
        uint64_t value = 0;
        require(output.registers[9].is_numeral_u64(value) && value == 0 &&
                    output.flags[1].is_true() && output.flags[4].is_true() &&
                    output.flags[2].is_false() && output.flags[3].is_false() &&
                    output.flags[5].is_false(),
                "counted store loop lost its exit register or defined flags");
        const auto &input_state = accelerated.recovery->states[loop.input];
        require(z3::eq(input_state.flags[6], output.flags[6]),
                "counted store loop modified the direction flag");
        for (unsigned reg = 0; reg < input_state.registers.size(); ++reg)
            if (reg != 1 && reg != 9)
                require(z3::eq(input_state.registers[reg], output.registers[reg]),
                        "counted store loop changed an untouched register");
        for (unsigned reg = 0; reg < input_state.vectors.size(); ++reg)
            require(z3::eq(input_state.vectors[reg], output.vectors[reg]),
                    "counted store loop changed an untouched vector");
        warbird::Recovery broken = *accelerated.recovery;
        broken.loops.front().effect = warbird::no_record;
        require(!broken.valid(), "malformed counted-store evidence was accepted");
    }
    auto changed_loop = control_loop;
    changed_loop.segs[0].bytes[loop_offset + 6] = 8; // Non-contiguous stores are not admitted.
    require(run(changed_loop, 1, loop_limits).loop_summaries == 0,
            "changed native loop acquired a summary");
    auto immutable_loop = control_loop;
    const std::array<uint8_t, 7> immutable_pointer = {0xb9, 0, 0x11, 0, 0, 0x90, 0x90};
    std::copy(immutable_pointer.begin(), immutable_pointer.end(),
              immutable_loop.segs[0].bytes.begin() + loop_offset - immutable_pointer.size());
    const auto rejected_store = run(immutable_loop, 1, loop_limits);
    require(rejected_store.loop_summaries == 0 && rejected_store.edges.empty() &&
                std::any_of(rejected_store.frontiers.begin(), rejected_store.frontiers.end(),
                            [](const auto &f)
                            { return f.reason == "possible repeated store to immutable image"; }),
            "counted store loop wrote immutable native bytes");
    auto symbolic_pointer_loop = control_loop;
    const std::array<uint8_t, 7> symbolic_pointer = {0x48, 0x8b, 0x09, 0x90, 0x90, 0x90, 0x90};
    std::copy(symbolic_pointer.begin(), symbolic_pointer.end(),
              symbolic_pointer_loop.segs[0].bytes.begin() + loop_offset - symbolic_pointer.size());
    const auto guarded_store = run(symbolic_pointer_loop, 1, loop_limits);
    require(guarded_store.loop_summaries == 1 && !guarded_store.exploration_complete() &&
                guarded_store.recovery->valid() && !guarded_store.recovery->loops.empty(),
            "symbolic repeated store lost its protected-span frontier or guarded continuation");
    const auto &guarded_loop = guarded_store.recovery->loops.front();
    const auto &guarded_effect = guarded_store.recovery->effects[guarded_loop.effect];
    z3::solver protected_span(*guarded_store.recovery->arena);
    protected_span.add(
        guarded_loop.domain &&
        warbird::overlaps(guarded_effect.address, guarded_effect.bytes, {{0x1000, 0x2000}}));
    require(protected_span.check() == z3::unsat,
            "guarded repeated store still overlaps immutable bytes");
    auto zero_count_loop = control_loop;
    std::fill_n(zero_count_loop.segs[0].bytes.begin(), 10, uint8_t(0x90));
    zero_count_loop.segs[0].bytes[0] = 0x45;
    zero_count_loop.segs[0].bytes[1] = 0x31;
    zero_count_loop.segs[0].bytes[2] = 0xc9;
    const auto zero_count = run(zero_count_loop, 1, loop_limits);
    require(zero_count.edges.empty() && !zero_count.exploration_complete() &&
                std::any_of(zero_count.frontiers.begin(), zero_count.frontiers.end(),
                            [](const auto &f)
                            { return f.reason == "counted store loop iteration quota"; }),
            "zero-count do-while store loop was treated as empty");
    auto symbolic_loop = zero_count_loop;
    symbolic_loop.segs[0].bytes[0] = 0x4c;
    symbolic_loop.segs[0].bytes[1] = 0x8b;
    symbolic_loop.segs[0].bytes[2] = 0x09;
    const auto symbolic_count = run(symbolic_loop, 1, loop_limits);
    require(symbolic_count.loop_summaries == 1 && !symbolic_count.exploration_complete() &&
                symbolic_count.recovery->valid() && !symbolic_count.recovery->loops.empty(),
            "symbolic count lost its bounded loop relation or unsupported-count frontier");
    const auto &symbolic_relation = symbolic_count.recovery->loops.front();
    z3::solver count_guard(*symbolic_count.recovery->arena);
    count_guard.add(
        symbolic_relation.domain &&
        (symbolic_relation.iterations == symbolic_count.recovery->arena->bv_val(0, 64) ||
         z3::ugt(symbolic_relation.iterations,
                 symbolic_count.recovery->arena->bv_val(symbolic_relation.iteration_bound, 64))));
    require(count_guard.check() == z3::unsat, "symbolic loop relation escaped its iteration bound");
    auto loop_quota = loop_limits;
    loop_quota.instructions = 20;
    const auto quota_count = run(control_loop, 7, loop_quota);
    require(quota_count.loop_summaries == 0 && quota_count.edges.empty() &&
                !quota_count.exploration_complete(),
            "loop summary evaded the native instruction quota");
    const auto loop_program_index = programs.size();
    programs.push_back(std::move(loop_program));
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
                        rax_reg_write_u64(engine, RAX_X86_REG_RSP, 0x8000) == RAX_OK &&
                        rax_reg_write_u64(engine, RAX_X86_REG_RCX, 0x9000) == RAX_OK,
                    "direct register write failed");
            require(rax_emu_start(engine, 0x1000, return_pc, 0, 128) == RAX_OK,
                    "direct execution failed");
            rax_exit exit{};
            require(rax_emu_last_exit(engine, &exit) == RAX_OK && exit.reason == RAX_STOP_UNTIL &&
                        exit.address == return_pc,
                    "direct interpreter did not complete the native handler");
            uint64_t observed = 0;
            require(rax_reg_read_u64(engine, RAX_X86_REG_RAX, &observed) == RAX_OK,
                    "direct result unavailable");
            if (&program == &programs[dispatch_program_index])
                require(observed == (input ^ ((input & 1) ? uint64_t(0) : uint64_t(1))),
                        "native dispatcher result violates its independent closed form");
            if (&program == &programs[loop_program_index])
                require(observed == input, "native store-loop result violates its closed form");
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
            require(candidate.recovery && !candidate.recovery->relations.empty(),
                    "native comparison lost its retained semantic relation");
            const auto &saved_relation = candidate.recovery->relations.front();
            uint64_t saved_value = 0;
            if (saved_relation.next_key.simplify().is_numeral_u64(saved_value))
                require(saved_value == observed,
                        "retained semantic relation differs from direct native execution");
            else
            {
                z3::solver retained_solver(*candidate.recovery->arena);
                retained_solver.set("timeout", 1000u);
                retained_solver.add(saved_relation.domain &&
                                    saved_relation.next_key !=
                                        candidate.recovery->arena->bv_val(observed, 64));
                require(retained_solver.check() == z3::unsat,
                        "retained guarded relation differs from direct native execution");
            }
            if (input == inputs.front())
                require(candidate.recovery->valid(),
                        "retained native instruction graph is malformed");
            ++comparisons;
        }
    }
    require(comparisons == 42271, "incomplete direct comparison matrix");
    // Independent native integer sequence for the dispatcher's stack ledger.
    // R8/R9 represent its virtual floor/native top; no host stack is allocated.
    const std::vector<uint8_t> stack_reference = {
        0x48, 0x89, 0xd0, 0x48, 0x85, 0xc0, 0x74, 0x1f, 0x4c, 0x39, 0xc0, 0x73, 0x1a,
        0x4d, 0x89, 0xc2, 0x49, 0x29, 0xc2, 0x44, 0x89, 0xd0, 0x4c, 0x8d, 0x58, 0x0f,
        0x49, 0x83, 0xe3, 0xf0, 0x4d, 0x29, 0xd9, 0x4d, 0x8d, 0x41, 0x28, 0x31, 0xd2,
        0x4c, 0x89, 0x01, 0x4c, 0x89, 0x49, 8,    0x48, 0x89, 0x51, 16,   0xc3};
    require(rax_mem_write(engine, 0x1000, stack_reference.data(), stack_reference.size()) == RAX_OK,
            "native stack reference write failed");
    size_t stack_comparisons = 0;
    for (auto input : inputs)
    {
        const uint64_t floor = 0x30000010000ULL, top = floor - 40;
        const uint64_t used = (input >> 32) & 0xffff;
        const uint64_t distance = input & 0x1ffff;
        const unsigned mode = unsigned((input >> 8) & 7);
        const uint64_t minimum = mode == 0   ? 0
                                 : mode == 1 ? floor + distance
                                 : mode == 2 ? floor - distance
                                 : mode == 3 ? UINT64_MAX
                                 : mode == 4 ? floor - (uint64_t(1) << 32) - distance
                                 : mode == 5 ? floor - 0xffffffffULL
                                 : mode == 6 ? floor - 1
                                             : floor;
        require(rax_reg_write_u64(engine, RAX_X86_REG_RDX, minimum) == RAX_OK &&
                    rax_reg_write_u64(engine, RAX_X86_REG_R8, floor) == RAX_OK &&
                    rax_reg_write_u64(engine, RAX_X86_REG_R9, top) == RAX_OK &&
                    rax_reg_write_u64(engine, RAX_X86_REG_RCX, 0x9000) == RAX_OK &&
                    rax_reg_write_u64(engine, RAX_X86_REG_RSP, 0x8000) == RAX_OK,
                "native stack reference input failed");
        require(rax_emu_start(engine, 0x1000, return_pc, 0, 128) == RAX_OK,
                "native stack reference did not run");
        rax_exit exit{};
        require(rax_emu_last_exit(engine, &exit) == RAX_OK && exit.reason == RAX_STOP_UNTIL,
                "native stack reference did not return");
        std::array<uint8_t, 24> memory{};
        require(rax_mem_read(engine, 0x9000, memory.data(), memory.size()) == RAX_OK,
                "native stack reference result unavailable");
        std::array<uint64_t, 3> values{};
        for (unsigned word = 0; word < 3; ++word)
            for (unsigned byte = 0; byte < 8; ++byte)
                values[word] |= uint64_t(memory[word * 8 + byte]) << (byte * 8);
        auto update = warbird::update_stack({numeral(floor), numeral(top), numeral(used)},
                                            numeral(minimum), 0x10000);
        std::array<z3::expr, 3> actual{update.state.floor, update.state.native_top, update.minimum};
        for (unsigned word = 0; word < 3; ++word)
        {
            uint64_t value = 0;
            require(actual[word].simplify().is_numeral_u64(value) && value == values[word],
                    "dispatcher stack model differs from native integer sequence");
        }
        const bool grows = minimum != 0 && minimum < floor;
        const uint64_t rounded = floor - values[0];
        const bool allowed =
            !grows || ((floor - minimum) <= 0x10000 - used && rounded <= 0x10000 - used);
        require(update.allowed.simplify().is_true() == allowed,
                "dispatcher stack quota accepted an out-of-budget reservation");
        ++stack_comparisons;
    }
    require(
        warbird::update_stack({numeral(0x1000), numeral(0x1000), numeral(0)}, numeral(0), 0x10000)
            .allowed.simplify()
            .is_false(),
        "unrelated native and virtual stacks were accepted");
    require(warbird::update_stack({numeral(0x1028), numeral(0x1000), numeral(0x10001)}, numeral(0),
                                  0x10000)
                .allowed.simplify()
                .is_false(),
            "invalid prior stack accounting was accepted");
    require(warbird::update_stack({numeral(0x18), numeral(UINT64_MAX - 15), numeral(0)}, numeral(0),
                                  0x10000)
                .allowed.simplify()
                .is_false(),
            "wrapping stack address relation was accepted");
    require(stack_comparisons == 1031, "incomplete native stack comparison matrix");
    rax_engine_close(engine);
    std::cout << "warbird tests passed\n";
}
