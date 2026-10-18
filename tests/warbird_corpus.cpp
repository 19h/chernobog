// Development-only corpus probe. The plugin never launches this executable.
#include "vm/warbird/model.hpp"
#include "vm/warbird/recovery.hpp"
#include <algorithm>
#include <charconv>
#include <limits>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
using namespace chernobog;
namespace
{
hybrid::ProgramImage read_pe(const char *path, uint64_t &base,
                             std::vector<warbird::ImportBinding> &imports)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file)
        throw std::runtime_error("cannot open corpus image");
    const auto size = file.tellg();
    if (size < 0 || size > 64 * 1024 * 1024)
        throw std::runtime_error("corpus file quota");
    file.seekg(0);
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char *>(bytes.data()), size))
        throw std::runtime_error("corpus read failed");
    auto word = [&](size_t offset, unsigned size)
    {
        if (offset > bytes.size() || size > bytes.size() - offset)
            throw std::runtime_error("truncated PE");
        uint64_t v = 0;
        for (unsigned i = 0; i < size; ++i)
            v |= uint64_t(bytes[offset + i]) << (8 * i);
        return v;
    };
    if (word(0, 2) != 0x5a4d)
        throw std::runtime_error("MZ signature");
    const size_t pe = word(0x3c, 4);
    if (word(pe, 4) != 0x4550)
        throw std::runtime_error("PE signature");
    const unsigned sections = word(pe + 6, 2);
    const size_t optional = pe + 24;
    if (word(optional, 2) != 0x20b || word(pe + 4, 2) != 0x8664)
        throw std::runtime_error("AMD64 PE32+ required");
    base = word(optional + 24, 8);
    hybrid::ProgramImage image;
    image.arch = hybrid::HybridArch::X86_64;
    image.lo = base;
    const auto optional_size = word(pe + 20, 2);
    if (optional_size < 112 || base > std::numeric_limits<uint64_t>::max() - 128 * 1024 * 1024)
        throw std::runtime_error("optional header bounds");
    size_t header = optional + optional_size;
    if (sections > 96)
        throw std::runtime_error("section quota");
    for (unsigned i = 0; i < sections; ++i, header += 40)
    {
        const uint64_t rva = word(header + 12, 4), raw = word(header + 20, 4),
                       raw_size = word(header + 16, 4),
                       size = std::max(word(header + 8, 4), raw_size), flags = word(header + 36, 4);
        if (!size)
            continue;
        if (size > 64 * 1024 * 1024 || rva > 64 * 1024 * 1024 || raw > bytes.size() ||
            raw_size > bytes.size() - raw)
            throw std::runtime_error("section bounds");
        hybrid::SegImage s;
        s.start = base + rva;
        s.end = s.start + size;
        s.bitness = 2;
        s.perm = ((flags & 0x20000000) ? 1 : 0) | ((flags & 0x80000000) ? 2 : 0) |
                 ((flags & 0x40000000) ? 4 : 0);
        s.bytes.resize(size);
        s.mask.resize((size + 7) / 8);
        std::copy_n(bytes.data() + raw, raw_size, s.bytes.data());
        for (size_t n = 0; n < raw_size; ++n)
            s.mask[n / 8] |= uint8_t(1u << (n % 8));
        image.hi = std::max(image.hi, s.end);
        image.segs.push_back(std::move(s));
    }
    std::sort(image.segs.begin(), image.segs.end(),
              [](const auto &a, const auto &b) { return a.start < b.start; });
    for (size_t i = 1; i < image.segs.size(); ++i)
        if (image.segs[i - 1].end > image.segs[i].start)
            throw std::runtime_error("overlapping sections");
    const auto directories = word(optional + 108, 4);
    if (directories > 1)
    {
        if (optional_size < 128)
            throw std::runtime_error("truncated import directory entry");
        imports =
            warbird::read_pe_imports(image, base, word(optional + 120, 4), word(optional + 124, 4));
    }
    return image;
}
}
int main(int argc, char **argv)
{
    if (argc != 4 && argc != 6 && argc != 7)
    {
        std::cerr
            << "usage: warbird_corpus ci.dll ClipSp.sys PEAuth.sys [profile_index hex_key [milliseconds] | --milliseconds value]\n";
        return 2;
    }
    try
    {
        unsigned selected = 0;
        uint64_t selected_key = 0;
        warbird::Limits limits;
        auto parse = [](const std::string &s, auto &value, int base)
        {
            const auto result = std::from_chars(s.data(), s.data() + s.size(), value, base);
            if (result.ec != std::errc{} || result.ptr != s.data() + s.size())
                throw std::runtime_error("invalid filter argument");
        };
        const bool filter = argc >= 6 && std::string(argv[4]) != "--milliseconds";
        if (argc == 6 && !filter)
        {
            unsigned ms = 0;
            parse(argv[5], ms, 10);
            if (!ms || ms > 60000)
                throw std::runtime_error("invalid time quota");
            limits.time = std::chrono::milliseconds(ms);
        }
        if (filter)
        {
            parse(argv[4], selected, 10);
            if (selected >= 3)
                throw std::runtime_error("invalid profile index");
            std::string key = argv[5];
            if (key.rfind("0x", 0) == 0 || key.rfind("0X", 0) == 0)
                key.erase(0, 2);
            parse(key, selected_key, 16);
            if (argc == 7)
            {
                unsigned ms = 0;
                parse(argv[6], ms, 10);
                if (!ms || ms > 60000)
                    throw std::runtime_error("invalid time quota");
                limits.time = std::chrono::milliseconds(ms);
            }
        }
        for (unsigned n = 0; n < 3; ++n)
        {
            if (filter && n != selected)
                continue;
            uint64_t base = 0;
            std::vector<warbird::ImportBinding> imports;
            auto image = read_pe(argv[n + 1], base, imports);
            auto admission = warbird::admit(image, base, warbird::profiles()[n]);
            if (!admission.valid())
                throw std::runtime_error(admission.rejection);
            warbird::bind_imports(image, admission, std::move(imports));
            const auto keys =
                filter ? std::vector<uint64_t>{selected_key} : warbird::profiles()[n].entry_keys;
            for (auto key : keys)
            {
                warbird::Lease lease;
                lease.database = 1;
                lease.key = key;
                lease.base = base;
                std::atomic_bool cancel{false};
                auto report = warbird::explore(image, admission, lease, limits, cancel);
                if (!report.recovery || !report.recovery->valid() ||
                    !report.recovery->lease.matches(report.lease) ||
                    report.recovery->exploration_complete != report.exploration_complete())
                    throw std::runtime_error("invalid retained recovery artifact");
                std::cout << report.json() << std::endl;
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
