#include "imports.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace chernobog::warbird
{
namespace
{
constexpr size_t max_imports = 4096;
constexpr size_t max_name = 512;
uint64_t add(uint64_t a, uint64_t b)
{
    if (a > std::numeric_limits<uint64_t>::max() - b)
        throw std::runtime_error("import address overflow");
    return a + b;
}
uint64_t read(const hybrid::ProgramImage &image, uint64_t address, size_t size)
{
    add(address, size);
    const auto bytes = image.loaded_view(address, size);
    if (bytes.size != size || !image.readable(address))
        throw std::runtime_error("unloaded import metadata");
    uint64_t value = 0;
    for (size_t i = 0; i < size; ++i)
        value |= uint64_t(bytes.data[i]) << (i * 8);
    return value;
}
bool name_ok(const std::string &s)
{
    return !s.empty() && s.size() <= max_name &&
           std::all_of(s.begin(), s.end(), [](unsigned char c) { return c >= 33 && c <= 126; });
}
std::string name(const hybrid::ProgramImage &image, uint64_t address)
{
    std::string out;
    for (size_t n = 0; n <= max_name; ++n)
    {
        const auto c = read(image, add(address, n), 1);
        if (!c)
        {
            if (!name_ok(out))
                throw std::runtime_error("invalid import name");
            return out;
        }
        out.push_back(char(c));
    }
    throw std::runtime_error("import name quota");
}
}
void validate_imports(const hybrid::ProgramImage &image, std::vector<ImportBinding> &imports)
{
    if (imports.size() > max_imports)
        throw std::runtime_error("import count quota");
    for (auto &i : imports)
    {
        if (!name_ok(i.module) || (!i.symbol.empty() && !name_ok(i.symbol)) ||
            (i.symbol.empty() ? i.ordinal == 0 || i.ordinal > 65535 : i.ordinal != 0))
            throw std::runtime_error("invalid import identity");
        add(i.slot, 8);
        i.loaded_mask = 0;
        i.snapshot_value = 0;
        const auto *segment = image.segment_at(i.slot);
        if (!segment || segment->end - i.slot < 8 || !image.readable(i.slot))
            throw std::runtime_error("import slot outside readable image");
        for (unsigned n = 0; n < 8; ++n)
        {
            const auto byte = image.loaded_view(i.slot + n, 1);
            if (byte.size == 1)
            {
                i.loaded_mask |= uint8_t(1u << n);
                i.snapshot_value |= uint64_t(byte.data[0]) << (n * 8);
            }
        }
        for (char &c : i.module)
            if (c >= 'A' && c <= 'Z')
                c += 'a' - 'A';
        // IDA's PE loader omits this extension in the imported module name.
        if (i.module == "ntoskrnl")
            i.module = "ntoskrnl.exe";
    }
    std::sort(imports.begin(), imports.end(),
              [](const auto &a, const auto &b) { return a.slot < b.slot; });
    for (size_t n = 1; n < imports.size(); ++n)
        if (imports[n - 1].slot > std::numeric_limits<uint64_t>::max() - 8 ||
            imports[n].slot < imports[n - 1].slot + 8)
            throw std::runtime_error("overlapping import slots");
}
std::vector<ImportBinding> read_pe_imports(const hybrid::ProgramImage &image, uint64_t base,
                                           uint32_t rva, uint32_t size)
{
    std::vector<ImportBinding> imports;
    if (!rva && !size)
        return imports;
    if (!rva || size < 20 || size > 65536)
        throw std::runtime_error("invalid import directory bounds");
    const uint64_t start = add(base, rva);
    add(start, size);
    for (uint64_t offset = 0; offset + 20 <= size; offset += 20)
    {
        const auto descriptor = add(start, offset);
        const auto lookup = read(image, descriptor, 4);
        const auto stamp = read(image, add(descriptor, 4), 4);
        const auto forward = read(image, add(descriptor, 8), 4);
        const auto module = read(image, add(descriptor, 12), 4);
        const auto iat = read(image, add(descriptor, 16), 4);
        if (!(lookup | stamp | forward | module | iat))
        {
            validate_imports(image, imports);
            return imports;
        }
        if (!module || !iat || offset / 20 >= 256)
            throw std::runtime_error("invalid import descriptor");
        const auto module_name = name(image, add(base, module));
        const auto table = add(base, lookup ? lookup : iat);
        for (size_t n = 0;; ++n)
        {
            if (n > max_imports)
                throw std::runtime_error("unterminated import lookup table");
            const auto value = read(image, add(table, n * 8), 8);
            if (!value)
                break;
            if (imports.size() >= max_imports)
                throw std::runtime_error("import count quota");
            ImportBinding binding{add(add(base, iat), n * 8), module_name, {}, 0};
            read(image, binding.slot, 8);
            if (value & (uint64_t(1) << 63))
            {
                if (value & 0x7fffffffffff0000ULL)
                    throw std::runtime_error("invalid import ordinal");
                binding.ordinal = value & 65535;
            }
            else
            {
                if (value > UINT32_MAX)
                    throw std::runtime_error("bound import lookup table unsupported");
                const auto hint = add(base, value);
                read(image, hint, 2);
                binding.symbol = name(image, add(hint, 2));
            }
            imports.push_back(std::move(binding));
        }
    }
    throw std::runtime_error("unterminated import directory");
}
const ImportBinding *find_import(const std::vector<ImportBinding> &imports, uint64_t slot)
{
    auto it = std::lower_bound(imports.begin(), imports.end(), slot,
                               [](const auto &i, uint64_t s) { return i.slot < s; });
    return it != imports.end() && it->slot == slot ? &*it : nullptr;
}
}
