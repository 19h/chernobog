/*
 * program_model.hpp — a plain-data snapshot of the analyzed database.
 *
 * All IDA database reads happen in program_model.cpp on the MAIN THREAD and are
 * distilled into POD structures that carry no IDA types. The resulting
 * ProgramImage can then be handed to the (IDA-free) emulation driver. Addresses
 * are plain uint64_t here precisely so this header stays free of <pro.h>; the
 * IDA side casts to/from ea_t (which is uint64 under __EA64__).
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "hybrid_config.hpp"

namespace chernobog::hybrid {

// Architectures the program model can identify. Individual decoder/emulator
// backends capability-gate this list independently; others are UNSUPPORTED.
enum class HybridArch
{
  UNSUPPORTED = 0,
  X86_16,
  X86_32,
  X86_64,
  ARM64,
  ARM32,
  RISCV64,
  CORTEX_M,
  HEXAGON,
};

// Entry execution state that is not implied by HybridArch alone. AArch32 can
// enter either A32 or T32; UNKNOWN deliberately disables concrete execution
// instead of guessing. DEFAULT is used by every architecture without this
// ambiguity.
enum class HybridEntryMode : uint8_t
{
  DEFAULT = 0,
  ARM,
  THUMB,
  UNKNOWN,
};

// Portable mirrors of IDA's SEGPERM_* bits. Keeping the values here lets the
// IDA-free emulation/analysis side ask permission questions without including
// an SDK header.
enum class HybridSegPerm : uint32_t
{
  EXEC  = 1u,
  WRITE = 2u,
  READ  = 4u,
};

enum class HybridSegmentKind : uint8_t
{
  NORMAL = 0,
  EXTERNAL,
};

// One mapped segment's bytes plus an initialized-byte bitmap (1 bit per byte;
// bit set => the byte was loaded, i.e. not .bss). Uninitialized bytes are left
// out of the emulator image and read back as engine zero-fill.
struct SegImage
{
  uint64_t start = 0;
  uint64_t end   = 0;
  uint32_t perm  = 0;   // SEGPERM_* bits (1=exec,2=write,4=read)
  uint8_t  bitness = 0; // 0=16,1=32,2=64
  HybridSegmentKind kind = HybridSegmentKind::NORMAL;
  std::vector<uint8_t> bytes; // size == end-start
  std::vector<uint8_t> mask;  // size == (end-start+7)/8, 1 bit per byte

  bool contains(uint64_t ea) const;
  bool byte_loaded(uint64_t ea) const;
  bool has_perm(HybridSegPerm required) const;
};

enum class HybridFunctionFlavor : uint8_t
{
  NATIVE = 0,
  OBJC_INSTANCE,
  OBJC_CLASS,
};

struct HybridFunctionProfile
{
  HybridFunctionFlavor flavor = HybridFunctionFlavor::NATIVE;
  std::string name;
  std::string objc_selector;
  size_t explicit_arguments = 0;
  bool explicit_arguments_known = false;

  size_t implicit_arguments() const
  {
    return flavor == HybridFunctionFlavor::NATIVE ? 0 : 2;
  }
  size_t total_arguments() const
  {
    return implicit_arguments() + explicit_arguments;
  }
};

// A half-open function chunk [start,end). The first chunk in FuncRange::chunks
// is the entry chunk; subsequent chunks are IDA function tails.
struct FuncChunk
{
  uint64_t start = 0;
  uint64_t end   = 0;

  bool contains(uint64_t ea) const { return ea >= start && ea < end; }
  uint64_t size() const { return end > start ? end - start : 0; }
};

// Version of hybrid_function_byte_hash(). Persisted consumers should store this
// beside a hash so a future algorithm change cannot be mistaken for new bytes.
constexpr uint32_t CHERNOBOG_RAX_FUNCTION_HASH_VERSION = 3;

// A function entry plus every chunk that IDA assigns to it. `start` and `end`
// deliberately retain their old meanings (entry and end of the PRIMARY chunk)
// so existing callers remain source- and behavior-compatible. New code should
// use contains()/chunks when it needs the complete function.
struct FuncRange
{
  uint64_t start = 0;
  uint64_t end   = 0;
  std::vector<FuncChunk> chunks;
  HybridEntryMode entry_mode = HybridEntryMode::DEFAULT;
  HybridFunctionProfile profile;

  // Deterministic hash of entry execution mode, chunk topology,
  // initialized-byte state, and bytes.
  // The hash is rebase-stable: chunk locations are represented relative to the
  // function entry. See hybrid_function_byte_hash().
  uint64_t byte_hash = 0;

  // ProgramImage generation in which the current byte_hash was first observed.
  // Re-snapshotting unchanged bytes preserves this value; a content/topology
  // change advances it to the new ProgramImage::generation.
  uint64_t generation = 0;

  bool contains(uint64_t ea) const;
  uint64_t byte_size() const;
};

struct ProgramImage
{
  HybridArch  arch = HybridArch::UNSUPPORTED;
  bool     big_endian = false;
  uint64_t lo = 0;      // min segment start (image lower bound)
  uint64_t hi = 0;      // max segment end   (image upper bound)
  std::vector<SegImage>  segs;
  std::vector<FuncRange> entries; // functions to emulate

  // Rebase-stable identity of segment topology, permissions, initialized-byte
  // state and bytes. Used to invalidate cached emulation when code or any
  // concrete global data visible to a function changes.
  uint64_t content_hash = 0;

  // Monotonic snapshot generation (within this ProgramImage instance).
  uint64_t generation = 0;

  const SegImage *segment_at(uint64_t ea) const;
  bool contains(uint64_t ea) const { return segment_at(ea) != nullptr; }
  bool byte_loaded(uint64_t ea) const;
  bool has_perm(uint64_t ea, HybridSegPerm required, bool allow_unknown = false) const;
  bool executable(uint64_t ea, bool allow_unknown = false) const
  {
    return has_perm(ea, HybridSegPerm::EXEC, allow_unknown);
  }
  bool writable(uint64_t ea, bool allow_unknown = false) const
  {
    return has_perm(ea, HybridSegPerm::WRITE, allow_unknown);
  }
  bool readable(uint64_t ea, bool allow_unknown = false) const
  {
    return has_perm(ea, HybridSegPerm::READ, allow_unknown);
  }

  const FuncRange *function_at(uint64_t ea) const;
};

// Stable, IDA-independent identity for a function's current bytes in `img`.
// It includes entry execution mode, every chunk, holes/uninitialized bytes,
// and relative chunk topology, but not absolute addresses (so rebasing does
// not change the hash).
uint64_t hybrid_function_byte_hash(const ProgramImage &img, const FuncRange &func);
uint64_t hybrid_program_content_hash(const ProgramImage &img);

// Parse IDA's canonical Objective-C function spelling (`-[Class selector:]`
// or `+[Class selector:]`). Native names remain NATIVE with unknown arity;
// the IDA-side snapshot supplements their arity from type information.
HybridFunctionProfile hybrid_function_profile_from_name(const std::string &name);

// Detect the target architecture/endianness from the open database. Returns
// false (out set to UNSUPPORTED) for anything hybrid cannot identify safely.
bool hybrid_detect_arch(HybridArch &arch_out, bool &big_endian_out);

enum class ProgramSnapshotStage : uint8_t
{
  SEGMENTS = 0,
  FUNCTIONS,
  COMPLETE,
};

struct ProgramSnapshotStats
{
  size_t segments_total = 0;
  size_t segments_visited = 0;
  size_t segments_copied = 0;
  size_t segments_invalid = 0;
  size_t segments_read_failed = 0;
  size_t functions_total = 0;
  size_t functions_visited = 0;
  size_t functions_included = 0;
  size_t functions_null = 0;
  size_t functions_library_or_thunk = 0;
  size_t functions_excluded_by_limit = 0;
  size_t chunks_included = 0;
  uint64_t image_bytes_requested = 0;
  uint64_t image_bytes_copied = 0;
  bool complete = false;
  std::string diagnostic;
};

struct ProgramSnapshotProgress
{
  ProgramSnapshotStage stage = ProgramSnapshotStage::SEGMENTS;
  ProgramSnapshotStats stats;
};

using ProgramSnapshotProgressCallback =
    std::function<void(const ProgramSnapshotProgress &)>;

// Snapshot the mapped image plus exactly the function containing
// `function_address`. No API exists here for enumerating every function.
// Main thread only. The optional callback receives monotonic counters and must
// not mutate the IDB. `complete` is false on unsupported architecture, missing
// function, byte-cap violation, or segment read failure.
ProgramSnapshotStats hybrid_snapshot_function(
    ProgramImage &img, const HybridConfig &cfg, uint64_t function_address,
    const ProgramSnapshotProgressCallback &progress = {});

} // namespace chernobog::hybrid
