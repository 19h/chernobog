#include "hybrid/program_model.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <random>
#include <string>

using namespace chernobog::hybrid;

namespace {
uint64_t reference_content_hash(const ProgramImage &image)
{
  uint64_t hash = 14695981039346656037ull;
  auto byte = [&](uint8_t value) { hash = (hash ^ value) * 1099511628211ull; };
  auto word = [&](uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
    { byte(static_cast<uint8_t>(value)); value >>= 8; }
  };
  word(static_cast<uint64_t>(image.arch));
  byte(image.big_endian ? 1 : 0);
  word(image.segs.size());
  for (const auto &segment : image.segs)
  {
    word(segment.start >= image.lo ? segment.start - image.lo : segment.start);
    word(segment.end > segment.start ? segment.end - segment.start : 0);
    word(segment.perm);
    byte(segment.bitness);
    byte(static_cast<uint8_t>(segment.kind));
    word(segment.bytes.size());
    word(segment.mask.size());
    for (uint8_t value : segment.mask) byte(value);
    for (uint8_t value : segment.bytes) byte(value);
  }
  return hash;
}

void verify_content(const ProgramImage &image)
{
  if (hybrid_program_content_hash(image) != reference_content_hash(image))
  {
    std::cerr << "program content hash differs from bytewise reference\n";
    std::exit(1);
  }
}

// Independent reference: serialize the version-3 identity using linear segment
// lookup. Small randomized images keep this deliberately simple oracle cheap.
uint64_t reference_hash(const ProgramImage &image, const FuncRange &function)
{
  uint64_t hash = 14695981039346656037ull;
  auto byte = [&](uint8_t value) { hash = (hash ^ value) * 1099511628211ull; };
  auto word = [&](uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
    { byte(static_cast<uint8_t>(value)); value >>= 8; }
  };
  auto string = [&](const std::string &value) {
    word(value.size());
    for (char ch : value) byte(static_cast<uint8_t>(static_cast<unsigned char>(ch)));
  };
  word(CHERNOBOG_RAX_FUNCTION_HASH_VERSION);
  byte(static_cast<uint8_t>(function.entry_mode));
  byte(static_cast<uint8_t>(function.profile.flavor));
  byte(function.profile.explicit_arguments_known ? 1 : 0);
  word(function.profile.explicit_arguments);
  string(function.profile.name);
  string(function.profile.objc_selector);
  auto chunks = function.chunks;
  if (chunks.empty()) chunks.push_back({function.start, function.end});
  word(chunks.size());
  for (const auto &chunk : chunks)
  {
    word(chunk.start - function.start);
    word(chunk.size());
    for (uint64_t address = chunk.start; address < chunk.end;)
    {
      const SegImage *mapped = nullptr;
      uint64_t next = chunk.end;
      for (const auto &seg : image.segs)
      {
        if (seg.start <= address && address < seg.end) mapped = &seg;
        if (seg.start > address) next = std::min(next, seg.start);
      }
      if (!mapped)
      {
        byte(0); word(next - address); address = next;
        continue;
      }
      const uint64_t offset = address - mapped->start;
      const bool loaded = offset / 8 < mapped->mask.size()
          && ((mapped->mask[offset / 8] >> (offset % 8)) & 1) != 0;
      byte(loaded ? 2 : 1);
      if (loaded) byte(offset < mapped->bytes.size() ? mapped->bytes[offset] : 0);
      ++address;
    }
  }
  return hash;
}

void verify(const ProgramImage &image, const FuncRange &function)
{
  if (hybrid_function_byte_hash(image, function) != reference_hash(image, function))
  {
    std::cerr << "function hash differs from version-3 reference\n";
    std::exit(1);
  }
}

void regressions()
{
  std::mt19937_64 rng(0xc4e2b09);
  for (unsigned trial = 0; trial < 2000; ++trial)
  {
    ProgramImage image;
    image.arch = static_cast<HybridArch>(rng() % 9);
    image.big_endian = rng() % 2 != 0;
    uint64_t address = rng() % 16;
    const uint64_t count = rng() % 32;
    for (uint64_t i = 0; i < count; ++i)
    {
      SegImage seg;
      seg.start = address;
      seg.end = address + 1 + rng() % 24;
      seg.perm = static_cast<uint32_t>(rng() % 8);
      seg.bitness = static_cast<uint8_t>(rng() % 3);
      seg.kind = static_cast<HybridSegmentKind>(rng() % 2);
      seg.bytes.resize(static_cast<size_t>(seg.end - seg.start));
      seg.mask.resize((seg.bytes.size() + 7) / 8);
      for (auto &value : seg.bytes) value = static_cast<uint8_t>(rng());
      for (auto &value : seg.mask) value = static_cast<uint8_t>(rng());
      // Preserve the existing fallback for truncated manually-built images.
      if (trial % 7 == 0) seg.bytes.resize(seg.bytes.size() / 2);
      if (trial % 11 == 0) seg.mask.clear();
      address = seg.end + rng() % 16;
      image.segs.push_back(std::move(seg));
    }
    verify_content(image);
    FuncRange function;
    function.start = rng() % (address + 1);
    function.end = function.start + rng() % (address + 1);
    function.profile = hybrid_function_profile_from_name("-[Example value:]");
    verify(image, function);
    function.chunks = {{0, address + 10}, {function.start, function.end},
                       {address, address}, {address + 1, address}};
    verify(image, function);
    // Translate both image and function; relative topology and bytes persist.
    const uint64_t original = hybrid_function_byte_hash(image, function);
    const uint64_t original_content = hybrid_program_content_hash(image);
    constexpr uint64_t delta = uint64_t(1) << 63;
    image.lo += delta;
    for (auto &seg : image.segs) { seg.start += delta; seg.end += delta; }
    function.start += delta; function.end += delta;
    for (auto &chunk : function.chunks) { chunk.start += delta; chunk.end += delta; }
    verify(image, function);
    verify_content(image);
    if (hybrid_program_content_hash(image) != original_content) std::exit(1);
    if (hybrid_function_byte_hash(image, function) != original) std::exit(1);
  }
  ProgramImage empty;
  FuncRange huge;
  huge.end = std::numeric_limits<uint64_t>::max();
  verify(empty, huge); // A maximal unmapped hole must not iterate over addresses.
  SegImage last;
  last.start = huge.end - 1; last.end = huge.end;
  last.bytes = {42}; last.mask = {1};
  empty.segs.push_back(last);
  verify(empty, huge); // No overflow when the last mapped byte is visited.
}

void content_regressions()
{
  ProgramImage image;
  verify_content(image);
  image.segs.resize(1);
  auto &segment = image.segs.front();
  // Every short length, tail size, and nonzero position, in both serialized
  // vectors. The vectors are intentionally independent: hashing may not infer
  // byte contents from the loaded mask, even for a manually constructed image.
  for (size_t size = 0; size <= 257; ++size)
  {
    segment.end = size;
    for (auto *buffer : {&segment.bytes, &segment.mask})
    {
      buffer->assign(size, 0);
      verify_content(image);
      for (size_t index = 0; index < size; ++index)
      {
        (*buffer)[index] = static_cast<uint8_t>(1 + index % 255);
        verify_content(image);
        (*buffer)[index] = 0;
      }
      buffer->clear();
    }
  }
  std::mt19937_64 rng(0x198cff);
  for (unsigned trial = 0; trial < 1000; ++trial)
  {
    segment.bytes.resize(static_cast<size_t>(rng() % 8193));
    segment.mask.resize(static_cast<size_t>(rng() % 1025));
    for (auto *buffer : {&segment.bytes, &segment.mask})
      for (auto &value : *buffer)
        value = rng() % 4 == 0 ? static_cast<uint8_t>(rng()) : 0;
    verify_content(image);
  }
  // Exercise every exponent bit and the word/tail boundaries around powers of
  // two. A nonzero sentinel on either side catches lost or duplicated bytes.
  segment.mask.clear();
  for (size_t power = 8; power <= 1024 * 1024; power *= 2)
    for (size_t size : {power - 1, power, power + 1})
    {
      segment.bytes.assign(size, 0);
      verify_content(image);
      segment.bytes.front() = 0x81;
      verify_content(image);
      segment.bytes.back() = 0xff;
      verify_content(image);
    }
}

#ifndef CHERNOBOG_LEGACY_MODEL
void view_regressions()
{
  auto verify = [](const SegImage &segment, uint64_t address, size_t maximum) {
    size_t expected = 0;
    if (segment.contains(address))
    {
      const uint64_t offset = address - segment.start;
      while (expected < maximum && expected < segment.end - address
             && offset < segment.bytes.size()
             && expected < segment.bytes.size() - static_cast<size_t>(offset))
      {
        const uint64_t current = offset + expected;
        if (current / 8 >= segment.mask.size()
            || (segment.mask[current / 8] & (1u << (current % 8))) == 0)
          break;
        ++expected;
      }
    }
    const LoadedByteView actual = segment.loaded_view(address, maximum);
    const uint8_t *pointer = expected == 0 ? nullptr
        : segment.bytes.data() + static_cast<size_t>(address - segment.start);
    if (actual.size != expected || actual.data != pointer)
    {
      std::cerr << "loaded byte view differs from bounded bytewise reference\n";
      std::exit(1);
    }
  };
  SegImage segment;
  segment.start = 17; segment.end = 41;
  segment.bytes.assign(24, 0x90);
  for (unsigned mask = 0; mask < 256; ++mask)
  {
    segment.mask = {255, static_cast<uint8_t>(mask), 255};
    for (uint64_t address = 16; address <= 42; ++address)
      for (size_t maximum = 0; maximum <= 32; ++maximum)
        verify(segment, address, maximum);
  }
  for (size_t byte_count = 0; byte_count <= 24; ++byte_count)
    for (size_t mask_count = 0; mask_count <= 4; ++mask_count)
    {
      segment.bytes.resize(byte_count);
      segment.mask.assign(mask_count, 255);
      for (uint64_t address = 16; address <= 42; ++address)
        verify(segment, address, std::numeric_limits<size_t>::max());
    }
  segment.start = std::numeric_limits<uint64_t>::max() - 24;
  segment.end = std::numeric_limits<uint64_t>::max();
  for (uint64_t offset = 0; offset <= 24; ++offset)
    verify(segment, segment.start + offset, std::numeric_limits<size_t>::max());

  ProgramImage image;
  if (image.loaded_view(0, 1).size != 0) std::exit(1);
  segment.start = 0; segment.end = 24;
  image.segs.push_back(segment);
  segment.start = 24; segment.end = 48;
  image.segs.push_back(segment);
  const auto last_byte = image.loaded_view(23, 16);
  if (last_byte.size != 1 || last_byte.data != image.segs[0].bytes.data() + 23)
    std::exit(1); // Views never cross even adjacent segment boundaries.
}
#endif

void content_benchmark()
{
  constexpr size_t size = 8 * 1024 * 1024;
  constexpr unsigned repeats = 20;
  volatile uint64_t sink = 0;
  for (const std::string pattern : {"zero", "random", "mixed", "sparse"})
  {
    ProgramImage image;
    image.segs.resize(1);
    auto &segment = image.segs.front();
    segment.end = size;
    segment.bytes.resize(size);
    segment.mask.assign(size / 8, pattern == "zero" ? 0 : 255);
    std::mt19937_64 rng(0x94c4);
    for (size_t i = 0; i < size; ++i)
    {
      const uint8_t value = static_cast<uint8_t>(rng());
      if (pattern == "random" || (pattern == "mixed" && (i / 4096) % 2 == 0)
          || (pattern == "sparse" && i % 8 == 7))
        segment.bytes[i] = value;
    }
    verify_content(image);
    const auto begin = std::chrono::steady_clock::now();
    for (unsigned i = 0; i < repeats; ++i)
      sink = hybrid_program_content_hash(image);
    const double seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - begin).count() / repeats;
    std::cout << pattern << ": " << size << " data bytes, " << segment.mask.size()
              << " mask bytes: " << seconds << " s/hash; hash=" << sink << '\n';
  }
}

void benchmark()
{
  volatile uint64_t sink = 0;
  for (size_t count : {1000u, 4000u, 16000u})
  {
    ProgramImage image;
    for (size_t i = 0; i < count; ++i)
    {
      SegImage seg;
      seg.start = i * 2 + 1; seg.end = seg.start + 1;
      seg.bytes = {42}; seg.mask = {1};
      image.segs.push_back(std::move(seg));
    }
    FuncRange function;
    function.end = count * 2 + 1;
    constexpr unsigned repeats = 20;
    const auto begin = std::chrono::steady_clock::now();
    for (unsigned i = 0; i < repeats; ++i)
      sink = hybrid_function_byte_hash(image, function);
    const double seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - begin).count() / repeats;
    std::cout << count << " segments: " << seconds << " s/hash; hash=" << sink << '\n';
  }
}
} // namespace

int main(int argc, char **argv)
{
  regressions();
  content_regressions();
#ifndef CHERNOBOG_LEGACY_MODEL
  view_regressions();
#endif
  std::cout << "program model identity regressions passed\n";
  if (argc == 2 && std::string(argv[1]) == "--benchmark") benchmark();
  if (argc == 2 && std::string(argv[1]) == "--content-benchmark") content_benchmark();
}
