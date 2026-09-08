// Counted Hex-Rays surface for the production block-merge detector tests.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

inline uint64_t instruction_link_reads = 0;
struct minsn_t;
struct counted_next_t
{
  minsn_t *pointer = nullptr;
  operator minsn_t *() const { ++instruction_link_reads; return pointer; }
};
constexpr int m_goto = 1;
struct minsn_t
{
  counted_next_t next;
  int opcode = 0;
};
struct mblock_t
{
  minsn_t *head = nullptr;
  minsn_t *tail = nullptr;
  std::vector<int> successors;
  int predecessors = 0;
  int nsucc() const { return int(successors.size()); }
  int succ(int index) const { return successors.at(size_t(index)); }
  int npred() const { return predecessors; }
};
struct mbl_array_t
{
  int qty = 0;
  std::vector<mblock_t *> blocks;
  mutable uint64_t block_lookups = 0;
  bool bad_sp = false;
  bool bad_call_sp = false;
  bool has_bad_sp() const { return bad_sp; }
  bool bad_call_sp_detected() const { return bad_call_sp; }
  mblock_t *get_mblock(int index) const
  {
    ++block_lookups;
    return index >= 0 && size_t(index) < blocks.size() ? blocks[size_t(index)] : nullptr;
  }
  bool merge_blocks() { return false; }
  void mark_chains_dirty() {}
};
struct deobf_ctx_t { int blocks_merged = 0; };
namespace deobf { inline void log(const char *, ...) {} }

class block_merge_handler_t
{
public:
  static bool detect_split_blocks(mbl_array_t *);
  static int run(mbl_array_t *, deobf_ctx_t *);
private:
  static int count_insns(mblock_t *);
  static bool has_single_goto_succ(mblock_t *);
};

bool reference_detect_split_blocks(mbl_array_t *);
