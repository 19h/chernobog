#include "model.hpp"
#include "../../common/inspection_json.hpp"
#include <algorithm>
#include <limits>
#include <sstream>

namespace chernobog::warbird
{
const std::vector<Profile> &profiles()
{
    static const std::vector<Profile> list = {
        {"ci",
         "0f0b00d3287c4f6003f7a9898c62b318e265e8744b55ca3cda0149a2502a2d01",
         0xb9b20,
         0xb27c4,
         0xb28b3,
         2048,
         {8, 5, 39, 18},
         {49, 15},
         49,
         false,
         {0xFAF1D7C599A70ADDULL, 0x5AE67008BCF20E68ULL, 0x2BCB62DCCD8476A8ULL,
          0xC11B999C187B4D0EULL, 0x5D168CB62BBFB4A9ULL, 0x83A892154132EF92ULL},
         0xb2839,
         {0x33, 0xc0, 0x48, 0x89, 0x9d, 0x98, 0x01, 0x00, 0x00, 0x48, 0x89, 0x9d,
          0x88, 0x00, 0x00, 0x00, 0x48, 0x89, 0x03, 0x48, 0x8b, 0x85, 0x10, 0x02,
          0x00, 0x00, 0x48, 0x89, 0x85, 0xa0, 0x00, 0x00, 0x00, 0x4c, 0x89, 0x55,
          0x50, 0x4c, 0x89, 0x45, 0x38, 0x4c, 0x89, 0x8d, 0x48, 0x01, 0x00, 0x00}},
        {"clipsp",
         "01274c7f3d4a339083aecc53683d2ccf7931ccbfb86bbe2e3efcbebd27956061",
         0x392f0,
         0xd9cc8,
         0xd9dd8,
         2048,
         {48, 17, 26, 21},
         {9, 45},
         45,
         true,
         {0xDD2DB593FD3F965BULL},
         0xd9d55,
         {0x48, 0x83, 0xa5, 0xc8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0x9d, 0x78, 0x01, 0x00, 0x00,
          0x48, 0x89, 0x5d, 0x58, 0x48, 0x89, 0x03, 0x48, 0x8b, 0x85, 0x10, 0x02, 0x00, 0x00, 0x48,
          0x89, 0x85, 0xb8, 0x00, 0x00, 0x00, 0x4c, 0x89, 0x9d, 0x90, 0x01, 0x00, 0x00, 0x4c, 0x89,
          0x85, 0x98, 0x00, 0x00, 0x00, 0x4c, 0x89, 0x8d, 0xe0, 0x00, 0x00, 0x00}},
        {"peauth",
         "a9831743d885a29b287e341dd62894e14f84c5bd1f19f6033361dc0ca07bdada",
         0xbe2a0,
         0xad00c,
         0xad0fe,
         4096,
         {30, 25, 44, 11},
         {41, 54},
         41,
         false,
         {0x36C23CED3AE0067FULL, 0x54FBDBC57D84C904ULL, 0x71230978383912F6ULL,
          0xCDD752B6329244D2ULL},
         0xad081,
         {0x33, 0xc0, 0x48, 0x89, 0x9d, 0x58, 0x01, 0x00, 0x00, 0x48, 0x89, 0x9d, 0xc0,
          0x01, 0x00, 0x00, 0x48, 0x89, 0x03, 0x48, 0x8b, 0x85, 0x10, 0x02, 0x00, 0x00,
          0x48, 0x89, 0x45, 0x68, 0x4c, 0x89, 0x95, 0x00, 0x01, 0x00, 0x00, 0x4c, 0x89,
          0x85, 0xd8, 0x00, 0x00, 0x00, 0x4c, 0x89, 0x8d, 0x70, 0x01, 0x00, 0x00}}};
    return list;
}
namespace
{
bool collect(const hybrid::ProgramImage &image, uint64_t address, size_t size,
             std::vector<Dependency> &out, std::vector<uint8_t> &bytes, bool executable)
{
    const auto *segment = image.segment_at(address);
    const auto view = image.loaded_view(address, size);
    if (!segment || size == 0 || view.size != size || !image.readable(address) ||
        (executable && (!image.executable(address) || image.writable(address))))
        return false;
    bytes.assign(view.data, view.data + view.size);
    out.push_back({address, segment->perm, bytes});
    return true;
}
}
Admission admit(const hybrid::ProgramImage &image, uint64_t base, const Profile &profile)
{
    Admission out;
    out.image_base = base;
    auto fail = [&](const char *reason)
    {
        out.rejection = reason;
        return out;
    };
    if (image.arch != hybrid::HybridArch::X86_64 || image.big_endian)
        return fail("AMD64 little-endian image required");
    if (!profile.table_count || (profile.table_count & (profile.table_count - 1)) ||
        profile.table_count > 4096 ||
        base > std::numeric_limits<uint64_t>::max() - profile.dispatch_rva - 43 ||
        base > std::numeric_limits<uint64_t>::max() - profile.table_rva -
                   size_t(profile.table_count) * 8)
        return fail("invalid profile range");
    std::vector<uint8_t> dispatch;
    if (!collect(image, base + profile.dispatch_rva, 43, out.dependencies, dispatch, true))
        return fail("dispatcher bytes unavailable or mutable");
    // Native dispatch contract: mov rax,rdx; lea rcx,[rip+table]; and eax,mask;
    // mov rax,[rcx+rax*8]; lea rcx,[rbp+0x10]; call [guard_dispatch];
    // mov rdx,rax; test rax,rax; jne loop. Keep the actual import target in
    // the dependency but do not assume the import implements a direct call.
    const uint8_t prefix[] = {0x48, 0x8b, 0xc2, 0x48, 0x8d, 0x0d};
    if (!std::equal(std::begin(prefix), std::end(prefix), dispatch.begin()) || dispatch[10] != 0x25)
        return fail("dispatcher signature mismatch");
    auto u32 = [&](size_t n)
    {
        uint32_t v = 0;
        for (unsigned i = 0; i < 4; ++i)
            v |= uint32_t(dispatch[n + i]) << (8 * i);
        return v;
    };
    const uint64_t table = base + profile.dispatch_rva + 10 + int64_t(int32_t(u32(6)));
    const uint8_t middle[] = {0x48, 0x8b, 0x04, 0xc1, 0x48, 0x8d, 0x4d, 0x10, 0xff, 0x15};
    const uint8_t suffix[] = {0x48, 0x8b, 0xd0, 0x48, 0x85, 0xc0, 0x75};
    if (table != base + profile.table_rva || u32(11) != profile.table_count - 1 ||
        !std::equal(std::begin(middle), std::end(middle), dispatch.begin() + 15) ||
        !std::equal(std::begin(suffix), std::end(suffix), dispatch.begin() + 29))
        return fail("table mask, handler ABI or zero-key exit mismatch");
    std::vector<uint8_t> bytes;
    if (!collect(image, table, size_t(profile.table_count) * 8, out.dependencies, bytes, false))
        return fail("handler table unavailable");
    for (size_t i = 0; i < profile.table_count; ++i)
    {
        uint64_t target = 0;
        for (unsigned j = 0; j < 8; ++j)
            target |= uint64_t(bytes[i * 8 + j]) << (8 * j);
        if (!image.executable(target) || image.writable(target) || !image.byte_loaded(target))
            return fail("table target is not immutable loaded executable code");
        out.handlers.push_back(target);
    }
    if (profile.setup_bytes.empty() || base > std::numeric_limits<uint64_t>::max() -
                                                  profile.setup_rva - profile.setup_bytes.size())
        return fail("context setup contract missing");
    std::vector<uint8_t> setup;
    if (!collect(image, base + profile.setup_rva, profile.setup_bytes.size(), out.dependencies,
                 setup, true) ||
        setup != profile.setup_bytes)
        return fail("native context setup mismatch");
    out.profile = &profile;
    return out;
}
bool dependencies_match(const hybrid::ProgramImage &image, const std::vector<Dependency> &deps)
{
    for (const auto &d : deps)
    {
        const auto *s = image.segment_at(d.address);
        const auto v = image.loaded_view(d.address, d.bytes.size());
        if (!s || s->perm != d.permissions || v.size != d.bytes.size() ||
            !std::equal(d.bytes.begin(), d.bytes.end(), v.data))
            return false;
    }
    return true;
}
bool Lease::matches(const Lease &o) const
{
    return database >= 0 && database == o.database && generation == o.generation &&
           image_hash == o.image_hash && base == o.base && key == o.key && model == o.model &&
           smir_abi == o.smir_abi && revision == o.revision;
}
std::string Report::json() const
{
    using chernobog::inspection_json_quote;
    auto hex = [](uint64_t v)
    {
        std::ostringstream s;
        s << "0x" << std::hex << v;
        return s.str();
    };
    std::ostringstream s;
    s << "{\"schema\":1,\"profile\":" << inspection_json_quote(profile)
      << ",\"entry_key\":" << inspection_json_quote(hex(lease.key))
      << ",\"model_version\":" << lease.model << ",\"smir_abi\":" << lease.smir_abi
      << ",\"limits\":{\"states\":" << limits.states << ",\"instructions\":" << limits.instructions
      << ",\"operations\":" << limits.operations << ",\"estimated_bytes\":" << limits.bytes
      << ",\"milliseconds\":" << limits.time.count() << ",\"call_depth\":" << limits.call_depth
      << "}"

      << ",\"exploration_complete\":" << (exploration_complete() ? "true" : "false")
      << ",\"semantic_equivalence_checked\":false,\"memory_faults_checked\":false,\"pseudocode_eligible\":false,\"cancelled\":"
      << (cancelled ? "true" : "false") << ",\"states\":" << states
      << ",\"instructions\":" << instructions << ",\"operations\":" << operations
      << ",\"key_splits\":" << key_splits << ",\"key_queries\":" << key_queries
      << ",\"return_splits\":" << return_splits << ",\"keys\":[";
    for (size_t i = 0; i < keys.size(); ++i)
    {
        if (i)
            s << ',';
        s << inspection_json_quote(hex(keys[i]));
    }
    s << "],\"edges\":[";
    for (size_t i = 0; i < edges.size(); ++i)
    {
        if (i)
            s << ',';
        const auto &e = edges[i];
        s << "{\"key\":" << inspection_json_quote(hex(e.key))
          << ",\"next\":" << inspection_json_quote(hex(e.next))
          << ",\"return\":" << inspection_json_quote(hex(e.native_return))
          << ",\"condition\":" << inspection_json_quote(e.condition) << '}';
    }
    s << "],\"frontiers\":[";
    for (size_t i = 0; i < frontiers.size(); ++i)
    {
        if (i)
            s << ',';
        const auto &f = frontiers[i];
        s << "{\"key\":" << inspection_json_quote(hex(f.key))
          << ",\"native\":" << inspection_json_quote(hex(f.native))
          << ",\"reason\":" << inspection_json_quote(f.reason) << '}';
    }
    s << "]}";
    return s.str();
}
} // namespace chernobog::warbird
