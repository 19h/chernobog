#include "vm/warbird/model.hpp"
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
    auto zero = fixture({0x31, 0xc0, 0xc3});
    auto r = run(zero);
    require(r.exploration_complete() && r.edges.size() == 1 && r.edges[0].next == 0,
            "zero-key return must terminate");
    r = run(zero, 0);
    require(r.exploration_complete() && r.instructions == 0,
            "zero entry must not dispatch table slot zero");
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
    require(rax_mem_write(engine, 0x1000, full_key.segs[0].bytes.data(), 4096) == RAX_OK,
            "direct code write failed");
    const uint64_t return_pc = 0x2000;
    require(rax_mem_write(engine, 0x8000, &return_pc, sizeof(return_pc)) == RAX_OK,
            "direct stack write failed");
    uint64_t random = 0x82A2B175229D6A5FULL;
    for (unsigned n = 0; n < 1024; ++n)
    {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        require(rax_reg_write_u64(engine, RAX_X86_REG_RDX, random) == RAX_OK &&
                    rax_reg_write_u64(engine, RAX_X86_REG_RSP, 0x8000) == RAX_OK,
                "direct register write failed");
        require(rax_emu_start(engine, 0x1000, return_pc, 0, 16) == RAX_OK,
                "direct execution failed");
        uint64_t observed = 0;
        require(rax_reg_read_u64(engine, RAX_X86_REG_RAX, &observed) == RAX_OK,
                "direct result unavailable");
        auto candidate = run(full_key, random);
        require(!candidate.edges.empty() && candidate.edges.front().next == observed,
                "direct versus symbolic transition mismatch");
    }
    rax_engine_close(engine);
    std::cout << "warbird tests passed\n";
}
