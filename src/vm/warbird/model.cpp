#include "model.hpp"
#include "../../common/inspection_json.hpp"
#include <algorithm>
#include <limits>
#include <sstream>
#include <stdexcept>

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
         0xb2829,
         {0x48, 0x83, 0xa5, 0xc8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x59, 0x0f, 0x48, 0x83,
          0xe3, 0xf0, 0x33, 0xc0, 0x48, 0x89, 0x9d, 0x98, 0x01, 0x00, 0x00, 0x48, 0x89, 0x9d,
          0x88, 0x00, 0x00, 0x00, 0x48, 0x89, 0x03, 0x48, 0x8b, 0x85, 0x10, 0x02, 0x00, 0x00,
          0x48, 0x89, 0x85, 0xa0, 0x00, 0x00, 0x00, 0x4c, 0x89, 0x55, 0x50, 0x4c, 0x89, 0x45,
          0x38, 0x4c, 0x89, 0x8d, 0x48, 0x01, 0x00, 0x00, 0x48, 0x85, 0xd2, 0x74, 0x6a, 0x48,
          0x8b, 0x85, 0xc8, 0x01, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x39, 0x48, 0x3b, 0xc3,
          0x73, 0x34, 0x48, 0x2b, 0xd8, 0x8b, 0xc3, 0x48, 0x8d, 0x48, 0x0f, 0x48, 0x3b, 0xc8,
          0x77, 0x0a, 0x48, 0xb9, 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x48, 0x83,
          0xe1, 0xf0, 0x48, 0x8b, 0xc1, 0xe8, 0xb0, 0x6c, 0xf7, 0xff, 0x48, 0x2b, 0xe1, 0x48,
          0x83, 0xa5, 0xc8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x5c, 0x24, 0x20},
         55,
         true,
         {0x40, 0x55, 0x48, 0x81, 0xec, 0x00, 0x02, 0x00, 0x00, 0x48, 0x8d, 0x6c, 0x24, 0x20, 0x48,
          0x89, 0x9d, 0xf8, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x05, 0x10, 0x49, 0xf8, 0xff, 0x48, 0x33,
          0xc5, 0x48, 0x89, 0x85, 0xd0, 0x01, 0x00, 0x00, 0x8b, 0x05, 0xb4, 0x28, 0x00, 0x00, 0x4c,
          0x8b, 0xd2, 0x48, 0x8b, 0xd1, 0xa8, 0x01, 0x75, 0x10, 0x83, 0xc8, 0x01, 0x89, 0x05, 0xa1,
          0x28, 0x00, 0x00, 0xc6, 0x05, 0x9e, 0x28, 0x00, 0x00, 0x00, 0xc6, 0x45, 0x00, 0x22, 0x8a,
          0x45, 0x00, 0x8b, 0x04, 0x24, 0x48, 0x83, 0xec, 0x10, 0x8b, 0x04, 0x24, 0x8b, 0x04, 0x24,
          0x48, 0x83, 0xec, 0x40, 0x48, 0x8d, 0x4c, 0x24, 0x20, 0x8b, 0x01}},
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
          0x85, 0x98, 0x00, 0x00, 0x00, 0x4c, 0x89, 0x8d, 0xe0, 0x00, 0x00, 0x00, 0x48, 0x85, 0xd2,
          0x74, 0x6a, 0x48, 0x8b, 0x85, 0xc8, 0x01, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x39, 0x48,
          0x3b, 0xc3, 0x73, 0x34, 0x48, 0x2b, 0xd8, 0x8b, 0xc3, 0x48, 0x8d, 0x48, 0x0f, 0x48, 0x3b,
          0xc8, 0x77, 0x0a, 0x48, 0xb9, 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x48, 0x83,
          0xe1, 0xf0, 0x48, 0x8b, 0xc1, 0xe8, 0x99, 0x76, 0xf5, 0xff, 0x48, 0x2b, 0xe1, 0x48, 0x83,
          0xa5, 0xc8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x5c, 0x24, 0x20},
         55,
         true,
         {0x40, 0x55, 0x48, 0x81, 0xec, 0x00, 0x02, 0x00, 0x00, 0x48, 0x8d, 0x6c, 0x24, 0x20, 0x48,
          0x89, 0x9d, 0xf8, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x05, 0xdc, 0x24, 0xfc, 0xff, 0x48, 0x33,
          0xc5, 0x48, 0x89, 0x85, 0xd0, 0x01, 0x00, 0x00, 0x8b, 0x05, 0xf8, 0x3c, 0xfc, 0xff, 0x4c,
          0x8b, 0xda, 0x4c, 0x8b, 0x95, 0x18, 0x02, 0x00, 0x00, 0x48, 0x8b, 0xd1, 0xa8, 0x01, 0x75,
          0x14, 0x83, 0xc8, 0x01, 0x89, 0x05, 0xde, 0x3c, 0xfc, 0xff, 0xe8, 0xf9, 0x8d, 0xf5, 0xff,
          0x88, 0x05, 0xd7, 0x3c, 0xfc, 0xff, 0xc6, 0x45, 0x00, 0x19, 0x8a, 0x45, 0x00, 0x8b, 0x04,
          0x24, 0x48, 0x83, 0xec, 0x10, 0x8b, 0x04, 0x24, 0x8b, 0x04, 0x24, 0x48, 0x83, 0xec, 0x50,
          0x48, 0x8d, 0x4c, 0x24, 0x20, 0x8b, 0x01, 0x41, 0x0f, 0x10, 0x02, 0x33, 0xc0, 0x48, 0x8d,
          0x59, 0x0f, 0x48, 0x83, 0xe3, 0xf0, 0x0f, 0x11, 0x43, 0x28, 0xf2, 0x41, 0x0f, 0x10, 0x4a,
          0x10, 0xf2, 0x0f, 0x11, 0x4b, 0x38}},
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
         0xad071,
         {0x48, 0x83, 0xa5, 0xc8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x59, 0x0f, 0x48, 0x83, 0xe3,
          0xf0, 0x33, 0xc0, 0x48, 0x89, 0x9d, 0x58, 0x01, 0x00, 0x00, 0x48, 0x89, 0x9d, 0xc0, 0x01,
          0x00, 0x00, 0x48, 0x89, 0x03, 0x48, 0x8b, 0x85, 0x10, 0x02, 0x00, 0x00, 0x48, 0x89, 0x45,
          0x68, 0x4c, 0x89, 0x95, 0x00, 0x01, 0x00, 0x00, 0x4c, 0x89, 0x85, 0xd8, 0x00, 0x00, 0x00,
          0x4c, 0x89, 0x8d, 0x70, 0x01, 0x00, 0x00, 0x48, 0x85, 0xd2, 0x74, 0x6a, 0x48, 0x8b, 0x85,
          0xc8, 0x01, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x39, 0x48, 0x3b, 0xc3, 0x73, 0x34, 0x48,
          0x2b, 0xd8, 0x8b, 0xc3, 0x48, 0x8d, 0x48, 0x0f, 0x48, 0x3b, 0xc8, 0x77, 0x0a, 0x48, 0xb9,
          0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x48, 0x83, 0xe1, 0xf0, 0x48, 0x8b, 0xc1,
          0xe8, 0x73, 0xc8, 0xf7, 0xff, 0x48, 0x2b, 0xe1, 0x48, 0x83, 0xa5, 0xc8, 0x01, 0x00, 0x00,
          0x00, 0x48, 0x8d, 0x5c, 0x24, 0x20},
         55,
         true,
         {0x40, 0x55, 0x48, 0x81, 0xec, 0x00, 0x02, 0x00, 0x00, 0x48, 0x8d, 0x6c, 0x24, 0x20, 0x48,
          0x89, 0x9d, 0xf8, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x05, 0x58, 0xd0, 0xf8, 0xff, 0x48, 0x33,
          0xc5, 0x48, 0x89, 0x85, 0xd0, 0x01, 0x00, 0x00, 0x8b, 0x05, 0x6c, 0xf1, 0x01, 0x00, 0x4c,
          0x8b, 0xd2, 0x48, 0x8b, 0xd1, 0xa8, 0x01, 0x75, 0x10, 0x83, 0xc8, 0x01, 0x89, 0x05, 0x59,
          0xf1, 0x01, 0x00, 0xc6, 0x05, 0x4e, 0xf1, 0x01, 0x00, 0x00, 0xc6, 0x45, 0x00, 0x22, 0x8a,
          0x45, 0x00, 0x8b, 0x04, 0x24, 0x48, 0x83, 0xec, 0x10, 0x8b, 0x04, 0x24, 0x8b, 0x04, 0x24,
          0x48, 0x83, 0xec, 0x40, 0x48, 0x8d, 0x4c, 0x24, 0x20, 0x8b, 0x01}}};
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
    if (profile.zero_slot > context_bytes / 8)
        return fail("invalid initial zero slot");
    if (profile.zero_slot < context_bytes / 8)
    {
        if (setup.size() < 8 || setup[0] != 0x48 || setup[1] != 0x83 || setup[2] != 0xa5 ||
            setup[7] != 0)
            return fail("native zero-slot instruction mismatch");
        uint32_t displacement = 0;
        for (unsigned n = 0; n < 4; ++n)
            displacement |= uint32_t(setup[3 + n]) << (8 * n);
        const uint32_t offset = displacement - 16u;
        if (displacement < 16 || offset % 8 || offset > context_bytes - 8 ||
            offset / 8 != profile.zero_slot ||
            std::find(profile.argument_slots.begin(), profile.argument_slots.end(),
                      profile.zero_slot) != profile.argument_slots.end() ||
            std::find(profile.stack_slots.begin(), profile.stack_slots.end(), profile.zero_slot) !=
                profile.stack_slots.end())
            return fail("native zero-slot destination mismatch");
        out.zero_slots.push_back(profile.zero_slot);
    }
    if (profile.stack_maintenance)
    {
        if (out.zero_slots.size() != 1 || profile.setup_bytes.size() < 74 ||
            profile.setup_rva + profile.setup_bytes.size() != profile.dispatch_rva)
            return fail("dispatcher maintenance witness missing");
        const uint8_t maintenance[] = {
            0x48, 0x85, 0xd2, 0x74, 0x6a, 0x48, 0x8b, 0x85, 0xc8, 0x01, 0x00, 0x00, 0x48,
            0x85, 0xc0, 0x74, 0x39, 0x48, 0x3b, 0xc3, 0x73, 0x34, 0x48, 0x2b, 0xd8, 0x8b,
            0xc3, 0x48, 0x8d, 0x48, 0x0f, 0x48, 0x3b, 0xc8, 0x77, 0x0a, 0x48, 0xb9, 0xf0,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x48, 0x83, 0xe1, 0xf0, 0x48, 0x8b,
            0xc1, 0xe8, 0xb0, 0x6c, 0xf7, 0xff, 0x48, 0x2b, 0xe1, 0x48, 0x83, 0xa5, 0xc8,
            0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x5c, 0x24, 0x20};
        const auto start = setup.size() - sizeof(maintenance);
        if (profile.zero_slot != 55)
            return fail("dispatcher maintenance slot mismatch");
        for (size_t i = 0; i < sizeof(maintenance); ++i)
            if ((i < 54 || i >= 58) && setup[start + i] != maintenance[i])
                return fail("dispatcher maintenance instruction mismatch");
        std::vector<uint8_t> frame;
        if (profile.dispatcher_rva >= profile.setup_rva ||
            profile.frame_bytes.size() != profile.setup_rva - profile.dispatcher_rva ||
            !collect(image, base + profile.dispatcher_rva, profile.frame_bytes.size(),
                     out.dependencies, frame, true) ||
            frame != profile.frame_bytes)
            return fail("dispatcher frame witness mismatch");
        const std::vector<uint8_t> prologue = {0x40, 0x55, 0x48, 0x81, 0xec, 0x00, 0x02,
                                               0x00, 0x00, 0x48, 0x8d, 0x6c, 0x24, 0x20};
        const std::vector<uint8_t> scalar_frame = {0x48, 0x83, 0xec, 0x10, 0x8b, 0x04, 0x24,
                                                   0x8b, 0x04, 0x24, 0x48, 0x83, 0xec, 0x40,
                                                   0x48, 0x8d, 0x4c, 0x24, 0x20, 0x8b, 0x01};
        const std::vector<uint8_t> copy_frame = {
            0x48, 0x83, 0xec, 0x10, 0x8b, 0x04, 0x24, 0x8b, 0x04, 0x24, 0x48, 0x83, 0xec,
            0x50, 0x48, 0x8d, 0x4c, 0x24, 0x20, 0x8b, 0x01, 0x41, 0x0f, 0x10, 0x02, 0x33,
            0xc0, 0x48, 0x8d, 0x59, 0x0f, 0x48, 0x83, 0xe3, 0xf0, 0x0f, 0x11, 0x43, 0x28,
            0xf2, 0x41, 0x0f, 0x10, 0x4a, 0x10, 0xf2, 0x0f, 0x11, 0x4b, 0x38};
        auto ends_with = [&](const auto &suffix)
        {
            return frame.size() >= suffix.size() &&
                   std::equal(suffix.begin(), suffix.end(), frame.end() - suffix.size());
        };
        const std::vector<uint8_t> align_floor = {0x48, 0x8d, 0x59, 0x0f, 0x48, 0x83, 0xe3, 0xf0};
        if (frame.size() < prologue.size() ||
            !std::equal(prologue.begin(), prologue.end(), frame.begin()))
            return fail("dispatcher frame prologue mismatch");
        if (ends_with(scalar_frame) && setup.size() >= 16 &&
            std::equal(align_floor.begin(), align_floor.end(), setup.begin() + 8))
            out.context_stack_gap = 96;
        else if (ends_with(copy_frame))
            out.context_stack_gap = 112;
        else
            return fail("dispatcher frame layout mismatch");
        out.stack_maintenance = true;
    }
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
void bind_imports(const hybrid::ProgramImage &image, Admission &admission,
                  std::vector<ImportBinding> imports)
{
    if (!admission.valid())
        throw std::runtime_error("imports require valid profile admission");
    validate_imports(image, imports);
    auto dependencies = admission.dependencies;
    for (const auto &i : imports)
    {
        for (unsigned n = 0; n < 8; ++n)
            if (i.loaded_mask & (1u << n))
                dependencies.push_back({i.slot + n,
                                        image.segment_at(i.slot)->perm,
                                        {uint8_t(i.snapshot_value >> (n * 8))}});
    }
    admission.dependencies = std::move(dependencies);
    admission.imports = std::move(imports);
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
      << ",\"stack_bytes\":" << limits.stack_bytes << "}"

      << ",\"exploration_complete\":" << (exploration_complete() ? "true" : "false")
      << ",\"semantic_equivalence_checked\":false,\"memory_faults_checked\":false,\"pseudocode_eligible\":false,\"cancelled\":"
      << (cancelled ? "true" : "false") << ",\"states\":" << states
      << ",\"instructions\":" << instructions << ",\"operations\":" << operations
      << ",\"key_splits\":" << key_splits << ",\"key_queries\":" << key_queries
      << ",\"return_splits\":" << return_splits << ",\"external_calls\":" << external_calls
      << ",\"vector_operations\":" << vector_operations << ",\"alias_queries\":" << alias_queries
      << ",\"write_guard_splits\":" << write_guard_splits
      << ",\"private_writes_isolated\":" << private_writes_isolated
      << ",\"stack_growth_paths\":" << stack_growth_paths
      << ",\"stack_maintenance\":" << (stack_maintenance ? "true" : "false")
      << ",\"context_stack_gap\":" << context_stack_gap << ",\"keys\":[";
    for (size_t i = 0; i < keys.size(); ++i)
    {
        if (i)
            s << ',';
        s << inspection_json_quote(hex(keys[i]));
    }
    s << "],\"context_zero_slots\":[";
    for (size_t i = 0; i < context_zero_slots.size(); ++i)
    {
        if (i)
            s << ',';
        s << context_zero_slots[i];
    }
    s << "],\"imports\":[";
    for (size_t i = 0; i < imports.size(); ++i)
    {
        if (i)
            s << ',';
        const auto &binding = imports[i];
        s << "{\"slot\":" << inspection_json_quote(hex(binding.slot))
          << ",\"module\":" << inspection_json_quote(binding.module)
          << ",\"symbol\":" << inspection_json_quote(binding.symbol)
          << ",\"ordinal\":" << binding.ordinal
          << ",\"loaded_mask\":" << unsigned(binding.loaded_mask) << '}';
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
