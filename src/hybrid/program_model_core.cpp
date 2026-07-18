/*
 * program_model_core.cpp — IDA-free ProgramImage queries and identities.
 *
 * Keep this translation unit free of SDK headers: worker-side code and pure
 * verification targets can use the exact same model/hash implementation as
 * the plugin without linking libida or substituting test-only definitions.
 */
#include "program_model.hpp"

#include <algorithm>
#include <iterator>
#include <limits>

namespace chernobog::hybrid {

bool SegImage::contains(uint64_t ea) const
{
  return ea >= start && ea < end;
}

bool SegImage::byte_loaded(uint64_t ea) const
{
  if ( !contains(ea) )
    return false;
  const uint64_t off = ea - start;
  return off / 8 < mask.size() && (mask[off / 8] & (1u << (off & 7))) != 0;
}

bool SegImage::has_perm(HybridSegPerm required) const
{
  const uint32_t bits = static_cast<uint32_t>(required);
  return (perm & bits) == bits;
}

bool FuncRange::contains(uint64_t ea) const
{
  if ( chunks.empty() )
    return ea >= start && ea < end; // compatibility for manually-built old-style ranges
  for ( const FuncChunk &chunk : chunks )
    if ( chunk.contains(ea) )
      return true;
  return false;
}

uint64_t FuncRange::byte_size() const
{
  if ( chunks.empty() )
    return end > start ? end - start : 0;
  uint64_t total = 0;
  for ( const FuncChunk &chunk : chunks )
  {
    const uint64_t n = chunk.size();
    if ( n > std::numeric_limits<uint64_t>::max() - total )
      return std::numeric_limits<uint64_t>::max();
    total += n;
  }
  return total;
}

const SegImage *ProgramImage::segment_at(uint64_t ea) const
{
  // hybrid_snapshot() keeps segments sorted. The binary search also behaves
  // correctly for hand-built images that follow that documented invariant.
  size_t first = 0;
  size_t last = segs.size();
  while ( first < last )
  {
    const size_t mid = first + (last - first) / 2;
    if ( segs[mid].start <= ea )
      first = mid + 1;
    else
      last = mid;
  }
  if ( first == 0 )
    return nullptr;
  const SegImage &candidate = segs[first - 1];
  return candidate.contains(ea) ? &candidate : nullptr;
}

bool ProgramImage::byte_loaded(uint64_t ea) const
{
  const SegImage *seg = segment_at(ea);
  return seg != nullptr && seg->byte_loaded(ea);
}

bool ProgramImage::has_perm(uint64_t ea, HybridSegPerm required, bool allow_unknown) const
{
  const SegImage *seg = segment_at(ea);
  if ( seg == nullptr )
    return false;
  return (allow_unknown && seg->perm == 0) || seg->has_perm(required);
}

const FuncRange *ProgramImage::function_at(uint64_t ea) const
{
  // Entry lookups are the hot path (one per emulation run). Snapshot entries are
  // ordered by start, so resolve those in O(log n); fall back to a full scan only
  // for an address that may live in a non-contiguous/shared tail chunk.
  auto it = std::lower_bound(entries.begin(), entries.end(), ea,
                             [](const FuncRange &func, uint64_t value)
                             { return func.start < value; });
  if ( it != entries.end() && it->start == ea )
    return &*it;
  if ( it != entries.begin() )
  {
    const FuncRange &candidate = *std::prev(it);
    if ( candidate.contains(ea) )
      return &candidate;
  }
  for ( const FuncRange &func : entries )
    if ( func.contains(ea) )
      return &func;
  return nullptr;
}

namespace {

constexpr uint64_t kFnvOffset = 14695981039346656037ull;
constexpr uint64_t kFnvPrime  = 1099511628211ull;

void hash_byte(uint64_t &hash, uint8_t value)
{
  hash ^= value;
  hash *= kFnvPrime;
}

void hash_u64(uint64_t &hash, uint64_t value)
{
  // Fixed byte order makes the result host-independent.
  for ( unsigned shift = 0; shift != 64; shift += 8 )
    hash_byte(hash, static_cast<uint8_t>(value >> shift));
}

void hash_string(uint64_t &hash, const std::string &value)
{
  hash_u64(hash, uint64_t(value.size()));
  for ( char byte : value )
    hash_byte(hash, static_cast<uint8_t>(static_cast<unsigned char>(byte)));
}

void hash_chunk_bytes(uint64_t &hash, const ProgramImage &img,
                      const FuncRange &func, const FuncChunk &chunk)
{
  hash_u64(hash, chunk.start - func.start); // relative => stable across rebases
  hash_u64(hash, chunk.size());

  uint64_t ea = chunk.start;
  while ( ea < chunk.end )
  {
    const SegImage *seg = img.segment_at(ea);
    if ( seg == nullptr )
    {
      // Function chunks should normally be mapped. Encode an unmapped run as a
      // distinct marker+length rather than hashing a potentially huge hole byte
      // by byte.
      uint64_t next = chunk.end;
      for ( const SegImage &candidate : img.segs )
      {
        if ( candidate.start > ea )
        {
          next = std::min(next, candidate.start);
          break;
        }
      }
      hash_byte(hash, 0); // unmapped-run marker
      hash_u64(hash, next - ea);
      ea = next;
      continue;
    }

    const uint64_t run_end = std::min(chunk.end, seg->end);
    const uint64_t off = ea - seg->start;
    for ( uint64_t i = 0, count = run_end - ea; i < count; ++i )
    {
      const uint64_t seg_off = off + i;
      const bool loaded = seg_off / 8 < seg->mask.size()
                       && (seg->mask[seg_off / 8] & (1u << (seg_off & 7))) != 0;
      hash_byte(hash, loaded ? 2 : 1); // distinguish unloaded from loaded zero
      if ( loaded )
      {
        const uint8_t value = seg_off < seg->bytes.size() ? seg->bytes[seg_off] : 0;
        hash_byte(hash, value);
      }
    }
    ea = run_end;
  }
}

} // namespace

uint64_t hybrid_function_byte_hash(const ProgramImage &img, const FuncRange &func)
{
  uint64_t hash = kFnvOffset;
  hash_u64(hash, CHERNOBOG_RAX_FUNCTION_HASH_VERSION);
  hash_byte(hash, static_cast<uint8_t>(func.entry_mode));
  hash_byte(hash, static_cast<uint8_t>(func.profile.flavor));
  hash_byte(hash, func.profile.explicit_arguments_known ? 1 : 0);
  hash_u64(hash, uint64_t(func.profile.explicit_arguments));
  hash_string(hash, func.profile.name);
  hash_string(hash, func.profile.objc_selector);
  const size_t nchunks = func.chunks.empty() ? 1 : func.chunks.size();
  hash_u64(hash, static_cast<uint64_t>(nchunks));
  if ( func.chunks.empty() )
  {
    hash_chunk_bytes(hash, img, func, FuncChunk{ func.start, func.end });
  }
  else
  {
    for ( const FuncChunk &chunk : func.chunks )
      hash_chunk_bytes(hash, img, func, chunk);
  }
  return hash;
}

uint64_t hybrid_program_content_hash(const ProgramImage &img)
{
  uint64_t hash = kFnvOffset;
  hash_u64(hash, uint64_t(img.arch));
  hash_byte(hash, img.big_endian ? 1 : 0);
  hash_u64(hash, uint64_t(img.segs.size()));
  for ( const SegImage &segment : img.segs )
  {
    hash_u64(hash, segment.start >= img.lo ? segment.start - img.lo : segment.start);
    hash_u64(hash, segment.end > segment.start ? segment.end - segment.start : 0);
    hash_u64(hash, segment.perm);
    hash_byte(hash, segment.bitness);
    hash_byte(hash, static_cast<uint8_t>(segment.kind));
    hash_u64(hash, uint64_t(segment.bytes.size()));
    hash_u64(hash, uint64_t(segment.mask.size()));
    for ( uint8_t byte : segment.mask )
      hash_byte(hash, byte);
    for ( uint8_t byte : segment.bytes )
      hash_byte(hash, byte);
  }
  return hash;
}

HybridFunctionProfile hybrid_function_profile_from_name(const std::string &name)
{
  HybridFunctionProfile profile;
  profile.name = name;
  if ( name.size() < 5 || (name[0] != '-' && name[0] != '+')
    || name[1] != '[' || name.back() != ']' )
    return profile;

  const size_t separator = name.find(' ', 2);
  if ( separator == std::string::npos || separator + 1 >= name.size() - 1 )
    return profile;
  profile.flavor = name[0] == '-'
                 ? HybridFunctionFlavor::OBJC_INSTANCE
                 : HybridFunctionFlavor::OBJC_CLASS;
  profile.objc_selector = name.substr(separator + 1,
                                      name.size() - separator - 2);
  profile.explicit_arguments = size_t(std::count(
      profile.objc_selector.begin(), profile.objc_selector.end(), ':'));
  profile.explicit_arguments_known = true;
  return profile;
}

} // namespace chernobog::hybrid
