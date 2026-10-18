#pragma once
#include "../../hybrid/program_model.hpp"
#include "imports.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <memory>
#include <vector>

namespace chernobog::warbird
{
struct Recovery;
constexpr uint32_t model_version = 10;
constexpr size_t context_bytes = 448;
struct Profile
{
    const char *name;
    const char *sha256;
    uint64_t table_rva;
    uint64_t dispatcher_rva;
    uint64_t dispatch_rva;
    uint32_t table_count;
    std::array<unsigned, 4> argument_slots;
    std::array<unsigned, 2> stack_slots;
    unsigned return_slot;
    bool copies_fifth_argument;
    std::vector<uint64_t> entry_keys;
    uint64_t setup_rva = 0;
    std::vector<uint8_t> setup_bytes;
    // 56 means absent. A lower value requires a matching first AND [RBP+d],0
    // instruction in the validated native setup, with context base RBP+16.
    unsigned zero_slot = context_bytes / 8;
    bool stack_maintenance = false;
    std::vector<uint8_t> frame_bytes; // exact dispatcher entry through setup_rva
};
const std::vector<Profile> &profiles();
struct Limits
{
    size_t states = 4096;
    size_t instructions = 65536;
    size_t operations = 1000000;
    size_t bytes = 256 * 1024 * 1024;
    std::chrono::milliseconds time{60000};
    unsigned call_depth = 32;
    uint64_t stack_bytes = 0x10000;
    size_t recovery_bytes = 32 * 1024 * 1024;
};
struct Dependency
{
    uint64_t address = 0;
    uint32_t permissions = 0;
    std::vector<uint8_t> bytes;
};
struct Admission
{
    const Profile *profile = nullptr;
    uint64_t image_base = 0;
    std::vector<uint64_t> handlers;
    std::vector<Dependency> dependencies;
    std::vector<ImportBinding> imports;
    std::vector<unsigned> zero_slots;
    bool stack_maintenance = false;
    unsigned context_stack_gap = 0;
    uint64_t dispatch_pointer = 0, dispatch_target = 0, handler_return = 0;
    bool dispatch_pointer_writable = false;
    bool abstract_handler_abi = false; // Explicitly selected by standalone control fixtures only.
    std::string rejection;
    bool valid() const { return profile != nullptr && rejection.empty(); }
};
// RVA/byte/permission evidence, never a filename-only or hash-only admission.
Admission admit(const hybrid::ProgramImage &, uint64_t image_base, const Profile &);
void bind_imports(const hybrid::ProgramImage &, Admission &, std::vector<ImportBinding>);
bool dependencies_match(const hybrid::ProgramImage &, const std::vector<Dependency> &);

struct Lease
{
    int64_t database = -1;
    uint64_t generation = 0;
    uint64_t image_hash = 0;
    uint64_t base = 0;
    uint64_t key = 0;
    uint32_t model = model_version;
    uint32_t smir_abi = 1;
    // A caller increments revision for types, function ownership and undo,
    // independently of byte changes; close invalidates the database identity.
    uint64_t revision = 0;
    bool matches(const Lease &) const;
};
struct Frontier
{
    uint64_t key = 0;
    uint64_t native = 0;
    std::string reason;
};
struct Edge
{
    uint64_t key = 0;
    uint64_t next = 0;
    uint64_t native_return = 0;
    std::string condition;
};
struct Report
{
    Lease lease;
    Limits limits;
    std::string profile;
    size_t instructions = 0;
    size_t initialization_instructions = 0;
    size_t initialization_copy_bytes = 0;
    size_t operations = 0;
    size_t states = 0;
    size_t key_splits = 0;
    size_t key_queries = 0;
    size_t return_splits = 0;
    size_t external_calls = 0;
    size_t vector_operations = 0;
    size_t alias_queries = 0;
    size_t write_guard_splits = 0;
    size_t private_writes_isolated = 0;
    std::vector<unsigned> context_zero_slots;
    size_t stack_growth_paths = 0;
    bool stack_maintenance = false;
    unsigned context_stack_gap = 0;
    uint64_t dispatch_pointer = 0, dispatch_target = 0, handler_return = 0;
    bool abstract_handler_abi = false;
    std::vector<uint64_t> keys;
    std::vector<Edge> edges;
    std::vector<Frontier> frontiers;
    std::vector<Dependency> dependencies;
    std::vector<ImportBinding> imports;
    bool cancelled = false;
    std::shared_ptr<const Recovery> recovery;
    // Structural exploration is not semantic equivalence or display admission.
    bool exploration_complete() const { return !cancelled && frontiers.empty(); }
    std::string json() const;
};
// One worker per process. The worker accepts immutable snapshots only; it
// cannot access the IDB. No process-global Z3 context or guest host pointers.
Report explore(const hybrid::ProgramImage &, const Admission &, const Lease &, const Limits &,
               const std::atomic_bool &cancel);
} // namespace chernobog::warbird
