#pragma once
#include "../../hybrid/program_model.hpp"
#include <string>
#include <vector>

namespace chernobog::warbird
{
struct ImportBinding
{
    uint64_t slot = 0;
    std::string module;
    std::string symbol;
    uint64_t ordinal = 0;
    uint8_t loaded_mask = 0;
    uint64_t snapshot_value = 0;
    bool operator==(const ImportBinding &o) const
    {
        return slot == o.slot && module == o.module && symbol == o.symbol && ordinal == o.ordinal &&
               loaded_mask == o.loaded_mask && snapshot_value == o.snapshot_value;
    }
};
// Canonicalize only module case. Export names remain case-sensitive. Duplicate
// slots, malformed metadata and quota overflow are rejected. IDA can retain an
// import identity while intentionally leaving its IAT bytes unloaded.
void validate_imports(const hybrid::ProgramImage &, std::vector<ImportBinding> &);
// Development PE reader: directory coordinates come from the PE32+ header.
// It never mistakes file IAT name RVAs for loaded executable pointers.
std::vector<ImportBinding> read_pe_imports(const hybrid::ProgramImage &, uint64_t image_base,
                                           uint32_t directory_rva, uint32_t directory_size);
const ImportBinding *find_import(const std::vector<ImportBinding> &, uint64_t slot);
}
