/*
 * program_model.cpp — read the analyzed program out of the IDA database.
 *
 * Main-thread only (touches the database). Produces a ProgramImage that the
 * IDA-free emulation driver consumes.
 */
#include "program_model.hpp"

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <segregs.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>

#include <algorithm>
#include <limits>
#include <unordered_map>

namespace chernobog::hybrid {

static_assert(static_cast<uint32_t>(HybridSegPerm::EXEC) == SEGPERM_EXEC,
              "HybridSegPerm must mirror IDA SEGPERM_EXEC");
static_assert(static_cast<uint32_t>(HybridSegPerm::WRITE) == SEGPERM_WRITE,
              "HybridSegPerm must mirror IDA SEGPERM_WRITE");
static_assert(static_cast<uint32_t>(HybridSegPerm::READ) == SEGPERM_READ,
              "HybridSegPerm must mirror IDA SEGPERM_READ");

namespace {

bool procname_is(const qstring &name, const char *candidate)
{
  return strieq(name.c_str(), candidate);
}

bool sdk_cortex_m_id(int id)
{
#if defined(PLFM_CORTEXM)
  if ( id == PLFM_CORTEXM )
    return true;
#endif
#if defined(PLFM_CORTEX_M)
  if ( id == PLFM_CORTEX_M )
    return true;
#endif
  (void)id;
  return false;
}

bool sdk_hexagon_id(int id)
{
#if defined(PLFM_QDSP6)
  if ( id == PLFM_QDSP6 )
    return true;
#endif
#if defined(PLFM_HEXAGON)
  if ( id == PLFM_HEXAGON )
    return true;
#endif
  (void)id;
  return false;
}

HybridEntryMode entry_mode_at(HybridArch architecture, ea_t address)
{
  if ( architecture != HybridArch::ARM32 )
    return HybridEntryMode::DEFAULT;
  const int t_register = str2reg("T");
  if ( t_register < 0 )
    return HybridEntryMode::UNKNOWN;
  const sel_t state = get_sreg(address, t_register);
  if ( state == BADSEL )
    return HybridEntryMode::UNKNOWN;
  return state == 0 ? HybridEntryMode::ARM : HybridEntryMode::THUMB;
}

} // namespace

bool hybrid_detect_arch(HybridArch &arch_out, bool &big_endian_out)
{
  arch_out = HybridArch::UNSUPPORTED;
  big_endian_out = inf_is_be();

  const int id = PH.id;
  const uint bits = inf_get_app_bitness(); // 16 / 32 / 64
  const bool is64 = inf_is_64bit();

  // Some SDKs expose these as dedicated processor ids. IDA 9.3's bundled
  // Hexagon has the stable short name QDSP6 when no public processor constant
  // is available; recognize that name without embedding a numeric value. Cortex-M
  // normally shares PLFM_ARM today, so only a dedicated id/name is treated as
  // CORTEX_M -- generic all-Thumb ARM firmware is not sufficient proof.
  const qstring procname = inf_get_procname();
  if ( sdk_cortex_m_id(id)
    || procname_is(procname, "Cortex-M")
    || procname_is(procname, "CortexM") )
  {
    arch_out = HybridArch::CORTEX_M;
    return true;
  }
  if ( sdk_hexagon_id(id)
    || procname_is(procname, "QDSP6")
    || procname_is(procname, "Hexagon") )
  {
    arch_out = HybridArch::HEXAGON;
    return true;
  }

  switch ( id )
  {
    case PLFM_386:
      arch_out = bits == 64 ? HybridArch::X86_64
               : bits == 32 ? HybridArch::X86_32
                            : HybridArch::X86_16;
      break;
    case PLFM_ARM:
      arch_out = is64 ? HybridArch::ARM64 : HybridArch::ARM32;
      break;
#if defined(PLFM_RISCV)
    case PLFM_RISCV:
      // The companion rax C ABI currently exposes RV64, not RV32.
      arch_out = bits == 64 ? HybridArch::RISCV64 : HybridArch::UNSUPPORTED;
      break;
#endif
    default:
      arch_out = HybridArch::UNSUPPORTED;
      break;
  }
  return arch_out != HybridArch::UNSUPPORTED;
}

ProgramSnapshotStats hybrid_snapshot_function(
    ProgramImage &img, const HybridConfig &cfg, uint64_t function_address,
    const ProgramSnapshotProgressCallback &progress)
{
  ProgramSnapshotProgress snapshot_progress;
  auto report = [&]
  {
    if ( progress )
      progress(snapshot_progress);
  };

  // Keep prior content generations so an incremental caller can distinguish an
  // unchanged function from one whose bytes or chunk topology changed.
  struct PriorIdentity { uint64_t hash = 0, generation = 0; };
  std::unordered_map<uint64_t, PriorIdentity> prior;
  prior.reserve(img.entries.size());
  for ( const FuncRange &func : img.entries )
    prior[func.start] = PriorIdentity{ func.byte_hash, func.generation };

  if ( img.generation != std::numeric_limits<uint64_t>::max() )
    ++img.generation;

  // Reset so a repeated call does not accumulate duplicate buffers or entries.
  img.segs.clear();
  img.entries.clear();
  img.content_hash = 0;
  img.lo = img.hi = 0;

  if ( !hybrid_detect_arch(img.arch, img.big_endian) )
  {
    snapshot_progress.stats.diagnostic = "unsupported processor architecture";
    report();
    return snapshot_progress.stats;
  }

  // ---- segments -----------------------------------------------------------
  const int nsegs = get_segm_qty();
  snapshot_progress.stage = ProgramSnapshotStage::SEGMENTS;
  snapshot_progress.stats.segments_total =
      nsegs <= 0 ? 0 : static_cast<size_t>(nsegs);
  report();

  // Preflight before allocating: one malformed or unusually large database
  // cannot amplify memory without the explicit CHERNOBOG_RAX_MAX_IMAGE_BYTES
  // override. All mapped segments are retained because global data and import
  // state are legitimate context for the selected function.
  for ( int i = 0; i < nsegs; ++i )
  {
    if ( user_cancelled() )
    {
      snapshot_progress.stats.diagnostic = "snapshot cancelled";
      report();
      return snapshot_progress.stats;
    }
    const segment_t *segment = getnseg(i);
    if ( segment == nullptr || segment->end_ea <= segment->start_ea )
      continue;
    const uint64_t length = uint64_t(segment->end_ea - segment->start_ea);
    if ( length > std::numeric_limits<uint64_t>::max()
                - snapshot_progress.stats.image_bytes_requested )
    {
      snapshot_progress.stats.diagnostic = "mapped image size overflow";
      report();
      return snapshot_progress.stats;
    }
    snapshot_progress.stats.image_bytes_requested += length;
    if ( snapshot_progress.stats.image_bytes_requested > cfg.max_image_bytes )
    {
      snapshot_progress.stats.diagnostic = "mapped image exceeds configured byte cap";
      report();
      return snapshot_progress.stats;
    }
  }

  bool have_bounds = false;
  for ( int i = 0; i < nsegs; ++i )
  {
    if ( user_cancelled() )
    {
      snapshot_progress.stats.diagnostic = "snapshot cancelled";
      img.segs.clear();
      report();
      return snapshot_progress.stats;
    }
    ++snapshot_progress.stats.segments_visited;
    segment_t *s = getnseg(i);
    if ( s == nullptr || s->end_ea <= s->start_ea )
    {
      ++snapshot_progress.stats.segments_invalid;
      report();
      continue;
    }

    SegImage si;
    si.start   = (uint64_t)s->start_ea;
    si.end     = (uint64_t)s->end_ea;
    si.perm    = (uint32_t)s->perm;
    si.bitness = (uint8_t)s->bitness;

    const size_t len = (size_t)(s->end_ea - s->start_ea);
    si.bytes.assign(len, 0);
    si.mask.assign((len + 7) / 8, 0);

    // GMB_READALL: fill what is loaded, mark the rest in `mask`. A -1 result
    // means the user cancelled a (non-existent here) wait box; treat as empty.
    ssize_t got = get_bytes(si.bytes.data(), (ssize_t)len, s->start_ea,
                            GMB_READALL, si.mask.data());
    if ( got < 0 )
    {
      ++snapshot_progress.stats.segments_read_failed;
      report();
      continue;
    }

    snapshot_progress.stats.image_bytes_copied += uint64_t(len);

    if ( !have_bounds )
    {
      img.lo = si.start;
      img.hi = si.end;
      have_bounds = true;
    }
    else
    {
      if ( si.start < img.lo ) img.lo = si.start;
      if ( si.end   > img.hi ) img.hi = si.end;
    }
    img.segs.push_back(std::move(si));
    ++snapshot_progress.stats.segments_copied;
    report();
  }
  std::sort(img.segs.begin(), img.segs.end(),
            [](const SegImage &a, const SegImage &b) { return a.start < b.start; });
  img.content_hash = hybrid_program_content_hash(img);

  // ---- function entries ---------------------------------------------------
  constexpr size_t nfuncs = 1;
  snapshot_progress.stage = ProgramSnapshotStage::FUNCTIONS;
  snapshot_progress.stats.functions_total = nfuncs;
  report();
  img.entries.reserve(1);
  ++snapshot_progress.stats.functions_visited;
  func_t *pfn = get_func(ea_t(function_address));
  if ( pfn == nullptr )
  {
    ++snapshot_progress.stats.functions_null;
    snapshot_progress.stats.diagnostic = "selected address is not in a function";
    report();
    return snapshot_progress.stats;
  }

  {
    FuncRange func;
    func.start = (uint64_t)pfn->start_ea;
    func.end   = (uint64_t)pfn->end_ea; // compatibility: primary chunk end
    func.entry_mode = entry_mode_at(img.arch, pfn->start_ea);

    func_tail_iterator_t chunks(pfn);
    for ( bool ok = chunks.main(); ok; ok = chunks.next() )
    {
      const range_t &chunk = chunks.chunk();
      if ( chunk.end_ea > chunk.start_ea )
        func.chunks.push_back(FuncChunk{ (uint64_t)chunk.start_ea, (uint64_t)chunk.end_ea });
    }
    // A valid function always has its entry chunk, but retain a defensive
    // fallback so downstream complete-function membership never becomes empty.
    if ( func.chunks.empty() && func.end > func.start )
      func.chunks.push_back(FuncChunk{ func.start, func.end });
    snapshot_progress.stats.chunks_included += func.chunks.size();

    func.byte_hash = hybrid_function_byte_hash(img, func);
    const auto old = prior.find(func.start);
    if ( old != prior.end() && old->second.hash == func.byte_hash
      && old->second.generation != 0 )
    {
      func.generation = old->second.generation;
    }
    else
    {
      func.generation = img.generation;
    }
    img.entries.push_back(std::move(func));
    ++snapshot_progress.stats.functions_included;
    report();
  }
  std::sort(img.entries.begin(), img.entries.end(),
            [](const FuncRange &a, const FuncRange &b) { return a.start < b.start; });
  snapshot_progress.stage = ProgramSnapshotStage::COMPLETE;
  snapshot_progress.stats.complete =
      snapshot_progress.stats.segments_read_failed == 0
      && snapshot_progress.stats.functions_included == 1;
  if ( !snapshot_progress.stats.complete
    && snapshot_progress.stats.diagnostic.empty() )
    snapshot_progress.stats.diagnostic = "one or more mapped segments could not be read";
  report();
  return snapshot_progress.stats;
}

} // namespace chernobog::hybrid
