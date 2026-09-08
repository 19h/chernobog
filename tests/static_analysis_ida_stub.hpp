// Minimal IDA surface used only by run_static_analysis_tests.py. Production
// static_analysis.cpp is compiled unchanged against these counted operations.
#pragma once

#include <cstdint>

using ea_t = uint64_t;
using flags64_t = uint64_t;
using sel_t = uint64_t;
constexpr ea_t BADADDR = UINT64_MAX;
constexpr sel_t BADSEL = UINT64_MAX;
constexpr int UA_MAXOP = 8;
constexpr int o_void = 0;
constexpr int o_near = 1;
constexpr int o_far = 2;
constexpr int XREF_CODE = 1;
constexpr int fl_F = 1;
constexpr uint32_t CF_CALL = 1;
constexpr uint32_t CF_JUMP = 2;
constexpr uint32_t CF_STOP = 4;
constexpr int PH = 0;

struct op_t { int type = o_void; };
struct insn_t
{
  uint16_t size = 0;
  op_t ops[UA_MAXOP]{};
  uint32_t get_canon_feature(int) const { return 0; }
};
struct xrefblk_t
{
  int type = fl_F;
  ea_t to = BADADDR;
  bool first_from(ea_t, int);
  bool next_from() { return false; }
};

inline bool is_call_insn(const insn_t &) { return false; }
inline bool is_ret_insn(const insn_t &) { return false; }
inline bool is_code(flags64_t flags) { return (flags & 1) != 0; }
inline bool is_head(flags64_t flags) { return (flags & 2) != 0; }
inline int str2reg(const char *) { return 0; }
inline sel_t get_sreg(ea_t, int) { return 0; }

flags64_t get_flags(ea_t);
ea_t next_head(ea_t, ea_t);
int decode_insn(insn_t *, ea_t);
bool user_cancelled();
