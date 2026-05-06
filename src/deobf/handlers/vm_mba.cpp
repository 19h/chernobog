#include "vm_mba.h"
#include "../analysis/mop_utils.h"
#include "../analysis/z3_solver.h"
#include "../analysis/chain_simplify.h"
#include "../../common/simd.h"
#include "../../common/compat.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>

static void vm_debug(const char *fmt, ...)
{
#ifndef _WIN32
    qstring env;
    if ( !qgetenv("CHERNOBOG_VM_DEBUG", &env) || env.empty() || env[0] == '0' )
        return;
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    int len = qvsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    int fd = open("/tmp/chernobog_vm_debug.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if ( fd >= 0 )
    {
        write(fd, buf, len);
        close(fd);
    }
#else
    (void)fmt;
#endif
}

bool vm_mba_handler_t::initialized_ = false;
std::unordered_set<ea_t> vm_mba_handler_t::candidates_;
std::map<ea_t, vm_mba_handler_t::handler_summary_t> vm_mba_handler_t::summaries_;
std::map<uint32_t, int> vm_mba_handler_t::carrier_hits_;
std::unordered_set<uint64_t> vm_mba_handler_t::pair_no_compact_cache_;

static const std::vector<uint32_t> &carrier_pool()
{
    static bool loaded = false;
    static std::vector<uint32_t> pool;
    if ( loaded )
        return pool;

    loaded = true;
    qstring env;
    if ( !qgetenv("CHERNOBOG_VM_CARRIER_POOL", &env) || env.empty() )
        return pool;

    const char *p = env.c_str();
    while ( p && *p )
    {
        while ( *p == ',' || *p == ';' || std::isspace((unsigned char)*p) )
            ++p;
        if ( !*p )
            break;
        char *end = nullptr;
        uint64_t value = strtoull(p, &end, 0);
        if ( end != p )
        {
            pool.push_back((uint32_t)value);
            p = end;
        }
        else
        {
            ++p;
        }
    }
    return pool;
}

static std::string clean_microcode_text(const qstring &text)
{
    std::string out;
    out.reserve(text.length());
    for ( const char *p = text.c_str(); p && *p; ++p )
    {
        unsigned char c = (unsigned char)*p;
        if ( c >= 0x20 )
            out.push_back((char)c);
    }
    return out;
}

static std::string clean_insn_text(const minsn_t *ins)
{
    if ( !ins )
        return std::string();
    qstring s;
    ins->print(&s);
    return clean_microcode_text(s);
}

static const char *skip_text_spaces(const char *p)
{
    while ( p && *p && std::isspace((unsigned char)*p) )
        ++p;
    return p;
}

static std::string trim_copy(const std::string &s)
{
    size_t first = 0;
    while ( first < s.size() && std::isspace((unsigned char)s[first]) )
        ++first;
    size_t last = s.size();
    while ( last > first && std::isspace((unsigned char)s[last - 1]) )
        --last;
    return s.substr(first, last - first);
}

static std::string strip_outer_parens(std::string s)
{
    s = trim_copy(s);
    bool changed = true;
    while ( changed && s.size() >= 2 && s.front() == '(' && s.back() == ')' )
    {
        changed = false;
        int depth = 0;
        bool wraps = true;
        for ( size_t i = 0; i < s.size(); ++i )
        {
            if ( s[i] == '(' )
                ++depth;
            else if ( s[i] == ')' )
            {
                --depth;
                if ( depth == 0 && i + 1 != s.size() )
                {
                    wraps = false;
                    break;
                }
            }
        }
        if ( wraps )
        {
            s = trim_copy(s.substr(1, s.size() - 2));
            changed = true;
        }
    }
    return s;
}

static bool is_mcode_mnemonic(const std::string &tok)
{
    static const char *mnemonics[] = {
        "mov", "ldx", "stx", "xdu", "xds", "low", "high",
        "or", "xor", "and", "add", "sub", "mul", "shl", "shr", "sar",
        "bnot", "neg", "call", "icall", "goto", "setz", "setnz",
    };
    for ( const char *m : mnemonics )
    {
        if ( tok == m )
            return true;
    }
    return false;
}

static std::string extract_first_cvtsi32_arg(const std::string &text)
{
    const char needle[] = "fast:\"unsigned int\"";
    size_t p = text.find(needle);
    if ( p == std::string::npos )
        return std::string();
    p += sizeof(needle) - 1;
    while ( p < text.size() && std::isspace((unsigned char)text[p]) )
        ++p;

    int angle_depth = 0;
    int paren_depth = 0;
    size_t end = p;
    for ( ; end < text.size(); ++end )
    {
        char c = text[end];
        if ( c == '<' )
            ++angle_depth;
        else if ( c == '>' )
        {
            if ( angle_depth == 0 )
                break;
            --angle_depth;
        }
        else if ( c == '(' )
            ++paren_depth;
        else if ( c == ')' && paren_depth > 0 )
            --paren_depth;
        if ( angle_depth == 0 && paren_depth == 0
          && end + 1 < text.size() && text[end] == '>' )
            break;
    }
    return strip_outer_parens(text.substr(p, end - p));
}

static qstring classify_primitive_from_expr(const std::string &raw)
{
    std::string s = strip_outer_parens(raw);
    if ( s.empty() )
        return qstring("opaque");

    const struct { const char *prefix; const char *primitive; } opcode_prefixes[] = {
        { "or ", "or" }, { "xor ", "xor" }, { "and ", "and" },
        { "add ", "add" }, { "sub ", "sub" }, { "shl ", "shl" },
        { "shr ", "shr" }, { "sar ", "shr" },
    };
    for ( const auto &entry : opcode_prefixes )
    {
        size_t n = strlen(entry.prefix) - 1;
        if ( s.size() >= n
          && strncmp(s.c_str(), entry.prefix, n) == 0
          && (s.size() == n || std::isspace((unsigned char)s[n])) )
            return qstring(entry.primitive);
    }

    auto top_level_contains = [&](char op) -> bool {
        int depth = 0;
        for ( size_t i = 0; i < s.size(); ++i )
        {
            char c = s[i];
            if ( c == '(' || c == '[' || c == '<' )
                ++depth;
            else if ( c == ')' || c == ']' || c == '>' )
            {
                if ( depth > 0 )
                    --depth;
            }
            else if ( depth == 0 && c == op )
            {
                if ( op == '-' )
                {
                    if ( i == 0 || s[i - 1] == '#' || s[i - 1] == 'x' || s[i - 1] == 'X' )
                        continue;
                }
                return true;
            }
        }
        return false;
    };

    if ( top_level_contains('|') ) return qstring("or");
    if ( top_level_contains('^') ) return qstring("xor");
    if ( top_level_contains('&') ) return qstring("and");
    if ( top_level_contains('+') ) return qstring("add");
    if ( top_level_contains('-') ) return qstring("sub");
    if ( s.find("==") != std::string::npos || s.find("setz") != std::string::npos )
        return qstring("cmp");
    if ( s.find("<<") != std::string::npos )
        return qstring("shl");
    if ( s.find(">>") != std::string::npos )
        return qstring("shr");
    if ( s.find("call ") == std::string::npos )
        return qstring("mov");
    return qstring("opaque");
}

static std::vector<std::string> split_top_level_operands(const std::string &text)
{
    std::vector<std::string> parts;
    size_t semi = text.find(" ;");
    std::string body = semi == std::string::npos ? text : text.substr(0, semi);
    body = trim_copy(body);

    size_t first_space = body.find_first_of(" \t");
    if ( first_space == std::string::npos )
        return parts;
    body = trim_copy(body.substr(first_space + 1));

    size_t opcode_space = body.find_first_of(" \t");
    if ( opcode_space != std::string::npos )
    {
        std::string maybe_opcode = body.substr(0, opcode_space);
        if ( is_mcode_mnemonic(maybe_opcode) )
            body = trim_copy(body.substr(opcode_space + 1));
    }

    int paren_depth = 0;
    int bracket_depth = 0;
    int angle_depth = 0;
    size_t start = 0;
    for ( size_t i = 0; i < body.size(); ++i )
    {
        char c = body[i];
        if ( c == '(' )
            ++paren_depth;
        else if ( c == ')' && paren_depth > 0 )
            --paren_depth;
        else if ( c == '[' )
            ++bracket_depth;
        else if ( c == ']' && bracket_depth > 0 )
            --bracket_depth;
        else if ( c == '<' )
            ++angle_depth;
        else if ( c == '>' && angle_depth > 0 )
            --angle_depth;
        else if ( c == ',' && paren_depth == 0 && bracket_depth == 0 && angle_depth == 0 )
        {
            parts.push_back(trim_copy(body.substr(start, i - start)));
            start = i + 1;
        }
    }
    if ( start < body.size() )
        parts.push_back(trim_copy(body.substr(start)));
    return parts;
}

static std::string extract_dest_text(const minsn_t *ins)
{
    if ( !ins )
        return std::string();
    std::vector<std::string> parts = split_top_level_operands(clean_insn_text(ins));
    if ( parts.empty() )
        return std::string();
    return parts.back();
}

static std::string extract_expr_text(const minsn_t *ins)
{
    if ( !ins )
        return std::string();
    std::vector<std::string> parts = split_top_level_operands(clean_insn_text(ins));
    if ( parts.empty() )
        return std::string();

    const char *op = nullptr;
    switch ( ins->opcode )
    {
        case m_or:  op = "or"; break;
        case m_xor: op = "xor"; break;
        case m_and: op = "and"; break;
        case m_add: op = "add"; break;
        case m_sub: op = "sub"; break;
        case m_mul: op = "mul"; break;
        case m_shl: op = "shl"; break;
        case m_shr:
        case m_sar: op = "shr"; break;
        case m_mov:
        case m_xdu:
        case m_low:
            return parts[0];
        default:
            return parts[0];
    }

    if ( parts.size() >= 2 )
        return std::string(op) + " " + parts[0] + ", " + parts[1];
    return std::string(op) + " " + parts[0];
}

static qstring classify_accumulator_store_primitive(
    const minsn_t *ins,
    const std::map<std::string, std::string> &defs)
{
    std::string text = clean_insn_text(ins);
    std::string arg = extract_first_cvtsi32_arg(text);
    if ( arg.empty() )
        arg = extract_expr_text(ins);
    std::string resolved = arg;

    // Follow a short chain of temp definitions. The summary is diagnostic IR,
    // so this textual fallback is preferable to reporting every packed temp as
    // a trivial move when the defining microcode is still in the same segment.
    for ( int i = 0; i < 4; ++i )
    {
        auto it = defs.find(resolved);
        if ( it == defs.end() || it->second.empty() || it->second == resolved )
            break;
        resolved = it->second;
    }

    qstring primitive = classify_primitive_from_expr(resolved);
    if ( primitive == "mov" && resolved != arg )
        primitive = classify_primitive_from_expr(arg);
    return primitive;
}

void vm_mba_handler_t::initialize()
{
    if ( initialized_ )
        return;
    initialized_ = true;
    msg("[chernobog:vm] VM MBA handler initialized (%zu carrier constants)\n",
        carrier_pool().size());
}

void vm_mba_handler_t::clear()
{
    candidates_.clear();
    summaries_.clear();
    carrier_hits_.clear();
    pair_no_compact_cache_.clear();
}

bool vm_mba_handler_t::enabled()
{
    qstring env;
    if ( qgetenv("CHERNOBOG_VM", &env) && !env.empty() && env[0] == '0' )
        return false;
    return true;
}

bool vm_mba_handler_t::is_prog_bb_name(const qstring &name)
{
    const char *s = name.c_str();
    const char prefix[] = "prog_bb_";
    if ( strncmp(s, prefix, sizeof(prefix) - 1) != 0 )
        return false;
    s += sizeof(prefix) - 1;
    if ( *s == '\0' )
        return false;
    while ( *s )
    {
        if ( !std::isdigit((unsigned char)*s) )
            return false;
        ++s;
    }
    return true;
}

bool vm_mba_handler_t::name_matches(ea_t ea, qstring *out_name)
{
    qstring name;
    if ( get_func_name(&name, ea) <= 0 )
        return false;
    if ( out_name )
        *out_name = name;
    return is_prog_bb_name(name);
}

bool vm_mba_handler_t::detect(mbl_array_t *mba)
{
    if ( !mba || !enabled() )
        return false;
    initialize();

    qstring name;
    if ( !name_matches(mba->entry_ea, &name) )
        return false;

    handler_summary_t summary = summarize(mba);
    vm_debug("[vm] detect %a %s packs=%d ip=%d reads=%d succ=%zu stride=%d%s%s\n",
             mba->entry_ea, name.c_str(), summary.pack_writes,
             summary.ip_advances, summary.bytecode_reads, summary.successors.size(),
             summary.stride,
             summary.threads_a2 ? " threads_a2" : "",
             summary.fused_superblock ? " fused" : "");
    bool candidate = summary.ip_advances >= 1
                  && summary.bytecode_reads >= 4
                  && (summary.pack_writes >= 1 || !summary.successors.empty()
                      || summary.ip_advances >= 2);

    if ( candidate )
    {
        candidates_.insert(mba->entry_ea);
        summaries_[mba->entry_ea] = summary;
        rebuild_graph_metadata();
        persist_summary(summaries_[mba->entry_ea]);
        deobf::log("[chernobog:vm] detected %s: packs=%d ip_adv=%d reads=%d stride=%d succ=%zu\n",
                   summary.name.c_str(), summary.pack_writes, summary.ip_advances,
                   summary.bytecode_reads, summary.stride, summary.successors.size());
    }

    return candidate;
}

bool vm_mba_handler_t::is_candidate(ea_t ea)
{
    return candidates_.find(ea) != candidates_.end();
}

bool vm_mba_handler_t::get_summary(ea_t ea, handler_summary_t *out)
{
    auto it = summaries_.find(ea);
    if ( it == summaries_.end() )
        return false;
    if ( out )
        *out = it->second;
    return true;
}

int vm_mba_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx || !enabled() )
        return 0;

    initialize();
    bool candidate = is_candidate(mba->entry_ea) || detect(mba);
    if ( !candidate )
        return 0;

    int changes = 0;
    changes += operand_pool_constant_pass(mba, ctx);

    const int max_iters = 4;
    for ( int i = 0; i < max_iters; ++i )
    {
        int iter_changes = carrier_constant_eliminator(mba, ctx);
        if ( iter_changes == 0 )
            break;
        changes += iter_changes;
    }

    for ( int i = 0; i < mba->qty; ++i )
    {
        mblock_t *blk = mba->get_mblock(i);
        changes += simplify_block(blk, ctx);
    }

    handler_summary_t summary = summarize(mba);
    summaries_[mba->entry_ea] = summary;
    rebuild_graph_metadata();
    persist_summary(summaries_[mba->entry_ea]);

    if ( changes > 0 )
    {
        ctx->expressions_simplified += changes;
        ctx->mba_simplified += changes;
        mba->mark_chains_dirty();
        mba->verify(false);
    }

    deobf::log("[chernobog:vm] %s summary: stride=%d micro_ops=%zu packs=%d reads=%d changes=%d%s%s\n",
               summary.name.c_str(), summary.stride, summary.micro_ops.size(),
               summary.pack_writes, summary.bytecode_reads, changes,
               summary.threads_a2 ? " threads_a2" : "",
               summary.fused_superblock ? " fused_superblock" : "");

    return changes;
}

int vm_mba_handler_t::simplify_insn(mblock_t *blk, minsn_t *ins, deobf_ctx_t *ctx)
{
    if ( !blk || !blk->mba || !ins || !enabled() )
        return 0;

    if ( !is_candidate(blk->mba->entry_ea) && !name_matches(blk->mba->entry_ea) )
        return 0;

    int changes = 0;
    changes += chernobog::chain::chain_simplify_handler_t::simplify_insn(blk, ins, ctx);
    changes += simplify_killed_or_cap(ins);
    changes += simplify_loword_killed_or_cap(ins);
    changes += simplify_masked_bitwise_carriers(ins);
    changes += simplify_nested_constant_ops(ins);
    changes += simplify_local_identities(ins);
    changes += simplify_hikari_pair_mba(ins);
    changes += simplify_single_var_residual(ins);
    changes += simplify_pack_idiom_marker(ins);
    changes += split_scalar_pack_store(blk, ins);

    if ( ins->l.t == mop_d && ins->l.d )
        changes += simplify_insn(blk, ins->l.d, ctx);
    if ( ins->r.t == mop_d && ins->r.d )
        changes += simplify_insn(blk, ins->r.d, ctx);
    if ( ins->d.t == mop_d && ins->d.d )
        changes += simplify_insn(blk, ins->d.d, ctx);

    if ( changes > 0 && ctx )
    {
        ctx->expressions_simplified += changes;
        ctx->mba_simplified += changes;
    }

    return changes;
}

int vm_mba_handler_t::simplify_block(mblock_t *blk, deobf_ctx_t *ctx)
{
    if ( !blk )
        return 0;

    int changes = 0;
    for ( minsn_t *ins = blk->head; ins; ins = ins->next )
        changes += simplify_insn(blk, ins, ctx);
    return changes;
}

uint64_t vm_mba_handler_t::mask_for_size(int size)
{
    if ( size <= 0 || size >= 8 )
        return UINT64_MAX;
    return (1ULL << (size * 8)) - 1;
}

bool vm_mba_handler_t::get_const(const mop_t &mop, uint64_t *out)
{
    if ( mop.t != mop_n || !mop.nnn )
        return false;
    if ( out )
        *out = mop.nnn->value & mask_for_size(mop.size);
    return true;
}

bool vm_mba_handler_t::is_carrier_constant(uint64_t value, int size)
{
    uint64_t mask = mask_for_size(size > 0 ? size : 4);
    uint64_t v = value & mask;
    for ( uint32_t k : carrier_pool() )
    {
        if ( (k & mask) == v )
            return true;
    }
    return false;
}

bool vm_mba_handler_t::mops_same(const mop_t &a, const mop_t &b)
{
    return chernobog::mop::equal_ignore_size(a, b);
}

static bool split_bin_const(mcode_t op, mop_t *lhs, mop_t *rhs,
                            mop_t **nonconst, uint64_t *konst, int *ksize)
{
    (void)op;
    if ( !lhs || !rhs )
        return false;
    if ( lhs->t == mop_n && lhs->nnn )
    {
        if ( nonconst ) *nonconst = rhs;
        if ( konst ) *konst = lhs->nnn->value;
        if ( ksize ) *ksize = lhs->size;
        return true;
    }
    if ( rhs->t == mop_n && rhs->nnn )
    {
        if ( nonconst ) *nonconst = lhs;
        if ( konst ) *konst = rhs->nnn->value;
        if ( ksize ) *ksize = rhs->size;
        return true;
    }
    return false;
}

int vm_mba_handler_t::simplify_killed_or_cap(minsn_t *ins)
{
    if ( !ins || ins->opcode != m_and )
        return 0;

    uint64_t mask = 0;
    mop_t *expr = nullptr;
    if ( !split_bin_const(m_and, &ins->l, &ins->r, &expr, &mask, nullptr) )
        return 0;
    if ( !expr || expr->t != mop_d || !expr->d || expr->d->opcode != m_or )
        return 0;

    uint64_t cap = 0;
    int cap_size = 4;
    mop_t *payload = nullptr;
    if ( !split_bin_const(m_or, &expr->d->l, &expr->d->r, &payload, &cap, &cap_size) )
        return 0;
    if ( !payload || !is_carrier_constant(cap, cap_size) )
        return 0;
    if ( (cap & mask_for_size(cap_size) & mask) != 0 )
        return 0;

    *expr = *payload;
    carrier_hits_[(uint32_t)(cap & 0xFFFFFFFFU)]++;
    return 1;
}

int vm_mba_handler_t::simplify_loword_killed_or_cap(minsn_t *ins)
{
    if ( !ins || ins->opcode != m_xdu || ins->l.t != mop_d || !ins->l.d )
        return 0;

    minsn_t *inner = ins->l.d;
    if ( inner->opcode != m_and )
        return 0;

    uint64_t mask = 0;
    mop_t *expr = nullptr;
    if ( !split_bin_const(m_and, &inner->l, &inner->r, &expr, &mask, nullptr) )
        return 0;
    if ( !expr || expr->t != mop_d || !expr->d || expr->d->opcode != m_or )
        return 0;

    uint64_t cap = 0;
    int cap_size = 2;
    mop_t *payload = nullptr;
    if ( !split_bin_const(m_or, &expr->d->l, &expr->d->r, &payload, &cap, &cap_size) )
        return 0;
    if ( !payload || !is_carrier_constant(cap, cap_size) )
        return 0;
    if ( (cap & mask_for_size(cap_size) & mask) != 0 )
        return 0;

    *expr = *payload;
    carrier_hits_[(uint32_t)(cap & 0xFFFFFFFFU)]++;
    return 1;
}

int vm_mba_handler_t::simplify_masked_bitwise_carriers(minsn_t *ins)
{
    if ( !ins || ins->opcode != m_and )
        return 0;

    uint64_t mask = 0;
    mop_t *expr = nullptr;
    if ( !split_bin_const(m_and, &ins->l, &ins->r, &expr, &mask, nullptr) )
        return 0;
    if ( !expr )
        return 0;

    int size = ins->d.size > 0 ? ins->d.size : expr->size;
    if ( size <= 0 || size > 8 )
        return 0;

    return strip_masked_or_caps(expr, mask & mask_for_size(size), size, 0);
}

int vm_mba_handler_t::strip_masked_or_caps(mop_t *mop, uint64_t live_mask, int size, int depth)
{
    if ( !mop || mop->t != mop_d || !mop->d || depth > 16 )
        return 0;

    minsn_t *ins = mop->d;
    int changes = 0;

    if ( ins->opcode == m_or )
    {
        uint64_t cap = 0;
        int cap_size = size;
        mop_t *payload = nullptr;
        if ( split_bin_const(m_or, &ins->l, &ins->r, &payload, &cap, &cap_size)
          && payload != nullptr
          && is_carrier_constant(cap, cap_size)
          && ((cap & mask_for_size(cap_size) & live_mask) == 0) )
        {
            mop_t replacement(*payload);
            replacement.size = mop->size > 0 ? mop->size : payload->size;
            mop->swap(replacement);
            carrier_hits_[(uint32_t)(cap & 0xFFFFFFFFU)]++;
            return 1;
        }
    }

    switch ( ins->opcode )
    {
        case m_or:
        case m_xor:
        case m_mov:
        case m_bnot:
        case m_low:
        case m_xdu:
            changes += strip_masked_or_caps(&ins->l, live_mask, size, depth + 1);
            changes += strip_masked_or_caps(&ins->r, live_mask, size, depth + 1);
            break;

        case m_and:
        {
            uint64_t inner_mask = 0;
            mop_t *inner_expr = nullptr;
            if ( split_bin_const(m_and, &ins->l, &ins->r, &inner_expr, &inner_mask, nullptr)
              && inner_expr != nullptr )
            {
                changes += strip_masked_or_caps(inner_expr,
                                                live_mask & inner_mask & mask_for_size(size),
                                                size, depth + 1);
            }
            else
            {
                changes += strip_masked_or_caps(&ins->l, live_mask, size, depth + 1);
                changes += strip_masked_or_caps(&ins->r, live_mask, size, depth + 1);
            }
            break;
        }

        default:
            break;
    }

    return changes;
}

int vm_mba_handler_t::simplify_pack_idiom_marker(minsn_t *ins)
{
    if ( !ins || ins->opcode != m_stx )
        return 0;

    mop_t lo;
    mop_t hi;
    if ( !match_pack_idiom(ins->l, &lo, &hi) )
        return 0;

    ea_t ea = ins->ea;

    minsn_t lo_xdu(ea);
    lo_xdu.opcode = m_xdu;
    lo_xdu.l = lo;
    lo_xdu.l.size = lo.size > 0 ? lo.size : 4;
    lo_xdu.d.size = 8;
    mop_t lo64;
    lo64.create_from_insn(&lo_xdu);

    minsn_t hi_xdu(ea);
    hi_xdu.opcode = m_xdu;
    hi_xdu.l = hi;
    hi_xdu.l.size = hi.size > 0 ? hi.size : 4;
    hi_xdu.d.size = 8;
    mop_t hi64;
    hi64.create_from_insn(&hi_xdu);

    minsn_t shl(ea);
    shl.opcode = m_shl;
    shl.l = hi64;
    shl.r.make_number(32, 8);
    shl.d.size = 8;
    mop_t shifted_hi;
    shifted_hi.create_from_insn(&shl);

    minsn_t pack(ea);
    pack.opcode = m_or;
    pack.l = shifted_hi;
    pack.r = lo64;
    pack.d.size = 8;
    mop_t packed;
    packed.create_from_insn(&pack);

    ins->l.swap(packed);
    return 1;
}

bool vm_mba_handler_t::is_helper_call(const minsn_t *ins, const char *needle)
{
    return ins != nullptr
        && ins->opcode == m_call
        && needle != nullptr
        && contains_helper(ins->l, needle);
}

bool vm_mba_handler_t::match_cvtsi32_operand(const mop_t &mop, mop_t *out)
{
    if ( mop.t != mop_d || !mop.d || !is_helper_call(mop.d, "_mm_cvtsi32_si128") )
        return false;
    if ( mop.d->d.t != mop_f || mop.d->d.f == nullptr || mop.d->d.f->args.empty() )
        return false;
    if ( out )
    {
        *out = mop.d->d.f->args[0];
        if ( out->size <= 0 )
            out->size = 4;
    }
    return true;
}

bool vm_mba_handler_t::match_load_si128_low32(const mop_t &mop, mop_t *out)
{
    if ( mop.t != mop_d || !mop.d || !is_helper_call(mop.d, "_mm_load_si128") )
        return false;
    if ( mop.d->d.t != mop_f || mop.d->d.f == nullptr || mop.d->d.f->args.empty() )
        return false;

    uint64_t addr_value = 0;
    if ( !get_const(mop.d->d.f->args[0], &addr_value) || addr_value == BADADDR )
        return false;

    uint32_t low = 0;
    if ( get_bytes(&low, sizeof(low), (ea_t)addr_value) != sizeof(low) )
        return false;

    if ( out )
        out->make_number(low, 4);
    return true;
}

bool vm_mba_handler_t::match_pack_idiom(const mop_t &mop, mop_t *lo, mop_t *hi)
{
    const minsn_t *pack = nullptr;
    if ( mop.t == mop_d && mop.d )
    {
        if ( mop.d->opcode == m_low && mop.d->l.t == mop_d && mop.d->l.d )
            pack = mop.d->l.d;
        else
            pack = mop.d;
    }
    if ( !is_helper_call(pack, "_mm_unpacklo_epi32") )
        return false;
    if ( pack->d.t != mop_f || pack->d.f == nullptr || pack->d.f->args.size() < 2 )
        return false;

    mop_t pack_lo;
    mop_t pack_hi;
    if ( !match_cvtsi32_operand(pack->d.f->args[0], &pack_lo)
      && !match_load_si128_low32(pack->d.f->args[0], &pack_lo) )
        return false;
    if ( !match_cvtsi32_operand(pack->d.f->args[1], &pack_hi)
      && !match_load_si128_low32(pack->d.f->args[1], &pack_hi) )
        return false;

    if ( lo ) *lo = pack_lo;
    if ( hi ) *hi = pack_hi;
    return true;
}

bool vm_mba_handler_t::match_zext32_to_64(const mop_t &mop, mop_t *out)
{
    if ( mop.t != mop_d || !mop.d || mop.d->opcode != m_xdu )
        return false;
    if ( mop.size != 8 && mop.d->d.size != 8 )
        return false;

    mop_t src(mop.d->l);
    int src_size = src.size;
    if ( src_size <= 0 )
        src_size = 4;
    if ( src_size > 4 )
        return false;

    if ( out )
    {
        if ( src_size == 4 )
        {
            *out = src;
            out->size = 4;
        }
        else
        {
            minsn_t zext(mop.d->ea);
            zext.opcode = m_xdu;
            zext.l = src;
            zext.l.size = src_size;
            zext.d.size = 4;
            out->create_from_insn(&zext);
        }
    }
    return true;
}

bool vm_mba_handler_t::match_shl32_hi(const mop_t &mop, mop_t *hi)
{
    if ( mop.t != mop_d || !mop.d || mop.d->opcode != m_shl )
        return false;

    uint64_t shift = 0;
    if ( !get_const(mop.d->r, &shift) || shift != 32 )
        return false;
    return match_zext32_to_64(mop.d->l, hi);
}

bool vm_mba_handler_t::match_scalar_pack_expr(const mop_t &mop, mop_t *lo, mop_t *hi)
{
    if ( mop.t != mop_d || !mop.d || mop.d->opcode != m_or )
        return false;
    if ( mop.size != 8 && mop.d->d.size != 8 )
        return false;

    mop_t pack_lo;
    mop_t pack_hi;
    if ( match_zext32_to_64(mop.d->l, &pack_lo)
      && match_shl32_hi(mop.d->r, &pack_hi) )
    {
        if ( lo ) *lo = pack_lo;
        if ( hi ) *hi = pack_hi;
        return true;
    }

    if ( match_zext32_to_64(mop.d->r, &pack_lo)
      && match_shl32_hi(mop.d->l, &pack_hi) )
    {
        if ( lo ) *lo = pack_lo;
        if ( hi ) *hi = pack_hi;
        return true;
    }

    return false;
}

bool vm_mba_handler_t::make_accumulator_half_dst(const mop_t &dst, uint64_t old_off,
                                                 uint64_t new_off, mop_t *out)
{
    if ( dst.t != mop_d || !dst.d || dst.d->opcode != m_add || !out )
        return false;

    uint64_t left_const = 0;
    uint64_t right_const = 0;
    bool left_is_const = get_const(dst.d->l, &left_const);
    bool right_is_const = get_const(dst.d->r, &right_const);

    mop_t base;
    int const_size = 8;
    if ( left_is_const && left_const == old_off )
    {
        base = dst.d->r;
        const_size = dst.d->l.size > 0 ? dst.d->l.size : 8;
    }
    else if ( right_is_const && right_const == old_off )
    {
        base = dst.d->l;
        const_size = dst.d->r.size > 0 ? dst.d->r.size : 8;
    }
    else
    {
        return false;
    }

    minsn_t add(dst.d->ea);
    add.opcode = m_add;
    add.l = base;
    add.r.make_number(new_off, const_size);
    add.d.size = dst.size > 0 ? dst.size : (base.size > 0 ? base.size : const_size);
    out->create_from_insn(&add);
    return true;
}

int vm_mba_handler_t::split_scalar_pack_store(mblock_t *blk, minsn_t *ins)
{
    if ( !blk || !ins || ins->opcode != m_stx )
        return 0;
    if ( !is_accumulator_store(ins) )
        return 0;

    mop_t lo;
    mop_t hi;
    if ( !match_scalar_pack_expr(ins->l, &lo, &hi) )
        return 0;

    mop_t hi_dst;
    if ( !make_accumulator_half_dst(ins->d, 8, 12, &hi_dst) )
        return 0;

    lo.size = 4;
    hi.size = 4;

    minsn_t *hi_store = new minsn_t(ins->ea);
    hi_store->opcode = m_stx;
    hi_store->l = hi;
    hi_store->r = ins->r;
    hi_store->d = hi_dst;

    ins->l = lo;
    blk->insert_into_block(hi_store, ins);
    blk->mark_lists_dirty();
    return 1;
}

int vm_mba_handler_t::simplify_nested_constant_ops(minsn_t *ins)
{
    if ( !ins || ins->d.size <= 0 || ins->d.size > 8 )
        return 0;

    uint64_t outer_const = 0;
    mop_t *outer_expr = nullptr;
    if ( !split_bin_const(ins->opcode, &ins->l, &ins->r,
                          &outer_expr, &outer_const, nullptr) )
        return 0;
    if ( !outer_expr || outer_expr->t != mop_d || !outer_expr->d )
        return 0;

    minsn_t *inner = outer_expr->d;
    uint64_t inner_const = 0;
    mop_t *payload = nullptr;
    uint64_t mask = mask_for_size(ins->d.size);
    mcode_t out_op = ins->opcode;
    uint64_t combined = 0;

    switch ( ins->opcode )
    {
        case m_xor:
            if ( inner->opcode != m_xor
              || !split_bin_const(m_xor, &inner->l, &inner->r,
                                  &payload, &inner_const, nullptr) )
                return 0;
            combined = (inner_const ^ outer_const) & mask;
            break;

        case m_and:
            if ( inner->opcode != m_and
              || !split_bin_const(m_and, &inner->l, &inner->r,
                                  &payload, &inner_const, nullptr) )
                return 0;
            combined = (inner_const & outer_const) & mask;
            break;

        case m_or:
            if ( inner->opcode != m_or
              || !split_bin_const(m_or, &inner->l, &inner->r,
                                  &payload, &inner_const, nullptr) )
                return 0;
            combined = (inner_const | outer_const) & mask;
            break;

        case m_add:
            if ( inner->opcode != m_add
              || !split_bin_const(m_add, &inner->l, &inner->r,
                                  &payload, &inner_const, nullptr) )
                return 0;
            combined = (inner_const + outer_const) & mask;
            break;

        case m_sub:
            if ( get_const(ins->l, nullptr) )
                return 0;
            if ( inner->opcode == m_add
              && split_bin_const(m_add, &inner->l, &inner->r,
                                 &payload, &inner_const, nullptr) )
            {
                out_op = m_add;
                combined = (inner_const - outer_const) & mask;
            }
            else if ( inner->opcode == m_sub
                   && !get_const(inner->l, nullptr)
                   && get_const(inner->r, &inner_const) )
            {
                payload = &inner->l;
                out_op = m_sub;
                combined = (inner_const + outer_const) & mask;
            }
            else
            {
                return 0;
            }
            break;

        default:
            return 0;
    }

    if ( !payload )
        return 0;
    return replace_with_simple_expr(ins, out_op, *payload, combined) ? 1 : 0;
}

bool vm_mba_handler_t::replace_with_operand(minsn_t *ins, const mop_t &src)
{
    if ( !ins || src.t == mop_z )
        return false;

    int size = ins->d.size > 0 ? ins->d.size : src.size;
    if ( size <= 0 )
        return false;

    ea_t ea = ins->ea;
    mop_t dst = ins->d;
    dst.size = size;
    mop_t tmp(src);
    tmp.size = size;

    ins->opcode = m_mov;
    ins->l.swap(tmp);
    ins->r.erase();
    ins->d = dst;
    ins->ea = ea;
    return true;
}

bool vm_mba_handler_t::replace_with_constant(minsn_t *ins, uint64_t value, int size)
{
    if ( !ins )
        return false;

    if ( size <= 0 )
        size = ins->d.size;
    if ( size <= 0 )
        size = ins->l.size > 0 ? ins->l.size : ins->r.size;
    if ( size <= 0 || size > 8 )
        return false;

    ea_t ea = ins->ea;
    mop_t dst = ins->d;
    dst.size = size;
    ins->opcode = m_mov;
    ins->l.make_number(value & mask_for_size(size), size);
    ins->r.erase();
    ins->d = dst;
    ins->ea = ea;
    return true;
}

bool vm_mba_handler_t::replace_with_and_not(minsn_t *ins, const mop_t &value,
                                            const mop_t &mask)
{
    if ( !ins || value.t == mop_z || mask.t == mop_z )
        return false;

    int size = ins->d.size > 0 ? ins->d.size : value.size;
    if ( size <= 0 || size > 8 )
        return false;
    if ( (value.size > 0 && value.size != size) || (mask.size > 0 && mask.size != size) )
        return false;

    mop_t and_l(value);
    and_l.size = size;
    mop_t and_r;

    if ( mask.t == mop_d && mask.d && mask.d->opcode == m_bnot )
    {
        and_r = mask.d->l;
        and_r.size = size;
    }
    else
    {
        minsn_t bnot(ins->ea);
        bnot.opcode = m_bnot;
        bnot.l = mask;
        bnot.l.size = size;
        bnot.d.size = size;
        and_r.create_from_insn(&bnot);
    }

    return replace_with_binary_expr(ins, m_and, and_l, and_r);
}

bool vm_mba_handler_t::match_and_with_operand(const mop_t &mop, const mop_t &value,
                                              mop_t *other)
{
    if ( mop.t != mop_d || !mop.d || mop.d->opcode != m_and )
        return false;
    if ( mops_same(mop.d->l, value) )
    {
        if ( other )
            *other = mop.d->r;
        return true;
    }
    if ( mops_same(mop.d->r, value) )
    {
        if ( other )
            *other = mop.d->l;
        return true;
    }
    return false;
}

bool vm_mba_handler_t::match_add_const(const mop_t &mop, mop_t *value, uint64_t *constant)
{
    if ( mop.t != mop_d || !mop.d || mop.d->opcode != m_add )
        return false;

    uint64_t k = 0;
    if ( get_const(mop.d->l, &k) )
    {
        if ( value )
            *value = mop.d->r;
        if ( constant )
            *constant = k;
        return true;
    }
    if ( get_const(mop.d->r, &k) )
    {
        if ( value )
            *value = mop.d->l;
        if ( constant )
            *constant = k;
        return true;
    }
    return false;
}

bool vm_mba_handler_t::match_sub_operands(const mop_t &mop, mop_t *left, mop_t *right)
{
    if ( mop.t != mop_d || !mop.d || mop.d->opcode != m_sub )
        return false;
    if ( left )
        *left = mop.d->l;
    if ( right )
        *right = mop.d->r;
    return true;
}

bool vm_mba_handler_t::match_pair_mba_core(const mop_t &mop, mop_t *x, mop_t *y,
                                           uint64_t *constant)
{
    if ( mop.t != mop_d || !mop.d || mop.d->opcode != m_and )
        return false;

    auto try_match = [&](const mop_t &a, const mop_t &b) -> bool {
        mop_t add_x;
        mop_t add_delta;
        uint64_t c1 = 0, c2 = 0;
        if ( !match_add_const(a, &add_x, &c1) || !match_add_const(b, &add_delta, &c2) )
            return false;
        if ( c1 != c2 )
            return false;

        mop_t sub_l;
        mop_t sub_r;
        if ( !match_sub_operands(add_delta, &sub_l, &sub_r) )
            return false;
        if ( !mops_same(sub_r, add_x) )
            return false;

        if ( x )
            *x = add_x;
        if ( y )
            *y = sub_l;
        if ( constant )
            *constant = c1;
        return true;
    };

    return try_match(mop.d->l, mop.d->r) || try_match(mop.d->r, mop.d->l);
}

bool vm_mba_handler_t::eval_const_insn(const minsn_t *ins, uint64_t *out, int *out_size)
{
    if ( !ins )
        return false;

    uint64_t lv = 0, rv = 0;
    bool has_l = get_const(ins->l, &lv);
    bool has_r = get_const(ins->r, &rv);
    int size = ins->d.size > 0 ? ins->d.size : std::max(ins->l.size, ins->r.size);
    if ( size <= 0 || size > 8 )
        return false;
    uint64_t mask = mask_for_size(size);
    uint64_t result = 0;

    switch ( ins->opcode )
    {
        case m_mov:
        case m_xdu:
        case m_low:
            if ( !has_l ) return false;
            result = lv;
            break;
        case m_bnot:
            if ( !has_l ) return false;
            result = ~lv;
            break;
        case m_neg:
            if ( !has_l ) return false;
            result = -lv;
            break;
        case m_add:
            if ( !has_l || !has_r ) return false;
            result = lv + rv;
            break;
        case m_sub:
            if ( !has_l || !has_r ) return false;
            result = lv - rv;
            break;
        case m_mul:
            if ( !has_l || !has_r ) return false;
            result = lv * rv;
            break;
        case m_and:
            if ( !has_l || !has_r ) return false;
            result = lv & rv;
            break;
        case m_or:
            if ( !has_l || !has_r ) return false;
            result = lv | rv;
            break;
        case m_xor:
            if ( !has_l || !has_r ) return false;
            result = lv ^ rv;
            break;
        case m_shl:
            if ( !has_l || !has_r || rv >= 64 ) return false;
            result = lv << rv;
            break;
        case m_shr:
            if ( !has_l || !has_r || rv >= 64 ) return false;
            result = lv >> rv;
            break;
        default:
            return false;
    }

    if ( out )
        *out = result & mask;
    if ( out_size )
        *out_size = size;
    return true;
}

int vm_mba_handler_t::simplify_local_identities(minsn_t *ins)
{
    if ( !ins || ins->d.size <= 0 )
        return 0;
    if ( ins->opcode == m_mov )
        return 0;

    uint64_t folded = 0;
    int folded_size = 0;
    if ( eval_const_insn(ins, &folded, &folded_size) )
        return replace_with_constant(ins, folded, folded_size) ? 1 : 0;

    uint64_t lc = 0, rc = 0;
    bool lconst = get_const(ins->l, &lc);
    bool rconst = get_const(ins->r, &rc);
    uint64_t full = mask_for_size(ins->d.size);

    switch ( ins->opcode )
    {
        case m_or:
        {
            mop_t ignored;
            if ( match_and_with_operand(ins->r, ins->l, &ignored) )
                return replace_with_operand(ins, ins->l) ? 1 : 0;
            if ( match_and_with_operand(ins->l, ins->r, &ignored) )
                return replace_with_operand(ins, ins->r) ? 1 : 0;
            if ( rconst && (rc & full) == 0 )
                return replace_with_operand(ins, ins->l) ? 1 : 0;
            if ( lconst && (lc & full) == 0 )
                return replace_with_operand(ins, ins->r) ? 1 : 0;
            break;
        }
        case m_xor:
        {
            mop_t other;
            if ( match_and_with_operand(ins->r, ins->l, &other) )
                return replace_with_and_not(ins, ins->l, other) ? 1 : 0;
            if ( match_and_with_operand(ins->l, ins->r, &other) )
                return replace_with_and_not(ins, ins->r, other) ? 1 : 0;
            if ( rconst && (rc & full) == 0 )
                return replace_with_operand(ins, ins->l) ? 1 : 0;
            if ( lconst && (lc & full) == 0 )
                return replace_with_operand(ins, ins->r) ? 1 : 0;
            break;
        }
        case m_sub:
        {
            mop_t other;
            if ( match_and_with_operand(ins->r, ins->l, &other) )
                return replace_with_and_not(ins, ins->l, other) ? 1 : 0;
            if ( rconst && (rc & full) == 0 )
                return replace_with_operand(ins, ins->l) ? 1 : 0;
            if ( mops_same(ins->l, ins->r) )
                return replace_with_constant(ins, 0, ins->d.size) ? 1 : 0;
            break;
        }
        case m_and:
            if ( rconst && (rc & full) == full )
                return replace_with_operand(ins, ins->l) ? 1 : 0;
            if ( lconst && (lc & full) == full )
                return replace_with_operand(ins, ins->r) ? 1 : 0;
            if ( (rconst && (rc & full) == 0) || (lconst && (lc & full) == 0) )
                return replace_with_constant(ins, 0, ins->d.size) ? 1 : 0;
            break;
        case m_add:
            if ( rconst && (rc & full) == 0 )
                return replace_with_operand(ins, ins->l) ? 1 : 0;
            if ( lconst && (lc & full) == 0 )
                return replace_with_operand(ins, ins->r) ? 1 : 0;
            break;
        case m_mul:
            if ( rconst && (rc & full) == 1 )
                return replace_with_operand(ins, ins->l) ? 1 : 0;
            if ( lconst && (lc & full) == 1 )
                return replace_with_operand(ins, ins->r) ? 1 : 0;
            if ( (rconst && (rc & full) == 0) || (lconst && (lc & full) == 0) )
                return replace_with_constant(ins, 0, ins->d.size) ? 1 : 0;
            break;
        case m_shl:
        case m_shr:
        case m_sar:
            if ( rconst && (rc & full) == 0 )
                return replace_with_operand(ins, ins->l) ? 1 : 0;
            break;
        case m_xdu:
        case m_low:
            if ( ins->l.size == ins->d.size && ins->l.t != mop_z )
                return replace_with_operand(ins, ins->l) ? 1 : 0;
            break;
        default:
            break;
    }

    if ( (ins->opcode == m_xor || ins->opcode == m_or || ins->opcode == m_and)
      && mops_same(ins->l, ins->r) )
    {
        if ( ins->opcode == m_xor )
            return replace_with_constant(ins, 0, ins->d.size) ? 1 : 0;
        return replace_with_operand(ins, ins->l) ? 1 : 0;
    }

    return 0;
}

bool vm_mba_handler_t::is_pure_expr(const minsn_t *ins)
{
    if ( !ins )
        return false;
    switch ( ins->opcode )
    {
        case m_add: case m_sub: case m_mul:
        case m_and: case m_or:  case m_xor:
        case m_bnot: case m_neg:
        case m_shl: case m_shr: case m_sar:
        case m_xdu: case m_xds: case m_low: case m_high:
        case m_mov:
            break;
        default:
            return false;
    }

    auto mop_pure = [](const mop_t &mop) -> bool {
        switch ( mop.t )
        {
            case mop_z:
            case mop_n:
            case mop_r:
            case mop_l:
            case mop_S:
                return true;
            case mop_d:
                return mop.d != nullptr && is_pure_expr(mop.d);
            default:
                return false;
        }
    };

    return mop_pure(ins->l) && mop_pure(ins->r);
}

int vm_mba_handler_t::expr_op_count(const minsn_t *ins)
{
    if ( !ins )
        return 0;
    int count = 1;
    if ( ins->l.t == mop_d && ins->l.d )
        count += expr_op_count(ins->l.d);
    if ( ins->r.t == mop_d && ins->r.d )
        count += expr_op_count(ins->r.d);
    if ( ins->d.t == mop_d && ins->d.d )
        count += expr_op_count(ins->d.d);
    return count;
}

void vm_mba_handler_t::collect_free_mops(const minsn_t *ins, std::vector<mop_t> *out)
{
    if ( !ins || !out )
        return;
    collect_free_mops(ins->l, out);
    collect_free_mops(ins->r, out);
}

void vm_mba_handler_t::collect_free_mops(const mop_t &mop, std::vector<mop_t> *out)
{
    if ( !out )
        return;
    if ( mop.t == mop_d && mop.d )
    {
        collect_free_mops(mop.d, out);
        return;
    }
    if ( mop.t != mop_r && mop.t != mop_l && mop.t != mop_S )
        return;
    for ( const mop_t &existing : *out )
    {
        if ( mops_same(existing, mop) )
            return;
    }
    out->push_back(mop);
}

bool vm_mba_handler_t::replace_with_simple_expr(minsn_t *ins, mcode_t op,
                                                const mop_t &var, uint64_t constant)
{
    if ( !ins )
        return false;

    int size = ins->d.size > 0 ? ins->d.size : var.size;
    if ( size <= 0 || (var.size > 0 && var.size != size) )
        return false;

    uint64_t mask = mask_for_size(size);
    constant &= mask;
    std::string before = clean_insn_text(ins);

    if ( op != m_mov && constant == 0 && (op == m_add || op == m_sub || op == m_xor) )
        op = m_mov;
    if ( op == m_and && constant == mask )
        op = m_mov;

    ea_t ea = ins->ea;
    mop_t dst = ins->d;
    dst.size = size;
    ins->opcode = op;
    ins->l = var;
    ins->l.size = size;
    ins->r.erase();
    if ( op != m_mov )
        ins->r.make_number(constant, size);
    ins->d = dst;
    ins->ea = ea;
    vm_debug("[vm:z3] rewrite %a op=%d size=%d var_size=%d const=0x%llx before=%s\n",
             ea, (int)op, size, var.size, (unsigned long long)constant, before.c_str());
    return true;
}

bool vm_mba_handler_t::replace_with_binary_expr(minsn_t *ins, mcode_t op,
                                                const mop_t &left, const mop_t &right)
{
    if ( !ins )
        return false;

    int size = ins->d.size > 0 ? ins->d.size : left.size;
    if ( size <= 0 || size > 8 )
        return false;
    if ( (left.size > 0 && left.size != size) || (right.size > 0 && right.size != size) )
        return false;

    std::string before = clean_insn_text(ins);
    ea_t ea = ins->ea;
    mop_t dst = ins->d;
    dst.size = size;
    mop_t l(left);
    mop_t r(right);
    l.size = size;
    r.size = size;

    ins->opcode = op;
    ins->l.swap(l);
    ins->r.swap(r);
    ins->d = dst;
    ins->ea = ea;
    vm_debug("[vm:z3] binary rewrite %a op=%d size=%d before=%s\n",
             ea, (int)op, size, before.c_str());
    return true;
}

bool vm_mba_handler_t::replace_with_binary_const_expr(minsn_t *ins, mcode_t base_op,
                                                      const mop_t &left, const mop_t &right,
                                                      mcode_t outer_op, uint64_t constant)
{
    if ( !ins )
        return false;

    int size = ins->d.size > 0 ? ins->d.size : left.size;
    if ( size <= 0 || size > 8 )
        return false;
    if ( (left.size > 0 && left.size != size) || (right.size > 0 && right.size != size) )
        return false;

    uint64_t mask = mask_for_size(size);
    constant &= mask;
    if ( constant == 0 && (outer_op == m_xor || outer_op == m_add || outer_op == m_sub) )
        return replace_with_binary_expr(ins, base_op, left, right);

    minsn_t inner(ins->ea);
    inner.opcode = base_op;
    inner.l = left;
    inner.l.size = size;
    inner.r = right;
    inner.r.size = size;
    inner.d.size = size;
    mop_t inner_mop;
    inner_mop.create_from_insn(&inner);

    std::string before = clean_insn_text(ins);
    mop_t dst = ins->d;
    dst.size = size;
    ins->opcode = outer_op;
    ins->l = inner_mop;
    ins->r.make_number(constant, size);
    ins->d = dst;
    vm_debug("[vm:pair] rewrite %a base=%d outer=%d const=0x%llx before=%s\n",
             ins->ea, (int)base_op, (int)outer_op,
             (unsigned long long)constant, before.c_str());
    return true;
}

static bool z3_eval_uint64(z3_solver::z3_context_t &ctx,
                           const z3::expr &expr,
                           const z3::expr &var,
                           uint64_t value,
                           uint64_t *out)
{
    ctx.solver().reset();
    ctx.solver().add(var == ctx.ctx().bv_val(value, var.get_sort().bv_size()));
    if ( ctx.solver().check() != z3::sat )
        return false;
    z3::expr val = ctx.solver().get_model().eval(expr, true);
    if ( !val.is_numeral() )
        return false;
    if ( out )
        *out = val.get_numeral_uint64();
    return true;
}

static bool z3_equiv(z3_solver::z3_context_t &ctx,
                     const z3::expr &a,
                     const z3::expr &b)
{
    ctx.solver().reset();
    ctx.solver().add(a != b);
    return ctx.solver().check() == z3::unsat;
}

int vm_mba_handler_t::simplify_hikari_pair_mba(minsn_t *ins)
{
    if ( !ins || ins->opcode != m_xor || ins->d.size != 4 )
        return 0;

    mop_t *core = nullptr;
    uint64_t outer_const = 0;
    if ( !split_bin_const(m_xor, &ins->l, &ins->r, &core, &outer_const, nullptr) )
        return 0;
    if ( !core )
        return 0;

    mop_t x;
    mop_t y;
    uint64_t add_const = 0;
    if ( !match_pair_mba_core(*core, &x, &y, &add_const) )
        return 0;
    if ( x.size > 0 && x.size != 4 )
        return 0;
    if ( y.size > 0 && y.size != 4 )
        return 0;
    x.size = 4;
    y.size = 4;

    uint64_t cache_key = chernobog::simd::hash_combine(hash_insn(ins), outer_const);
    cache_key = chernobog::simd::hash_combine(cache_key, add_const);
    if ( pair_no_compact_cache_.find(cache_key) != pair_no_compact_cache_.end() )
        return 0;

    try
    {
        z3_solver::z3_context_t zctx;
        zctx.set_timeout(100);
        z3_solver::mcode_translator_t translator(zctx);
        z3::expr expr = translator.translate_insn(ins);
        z3::expr zx = translator.translate_operand(x, 4);
        z3::expr zy = translator.translate_operand(y, 4);
        z3::expr zero = zctx.ctx().bv_val(0, 32);
        auto bv32 = [&](const z3::expr &e) -> z3::expr {
            unsigned bits = e.get_sort().bv_size();
            if ( bits == 32 )
                return e;
            if ( bits > 32 )
                return e.extract(31, 0);
            return z3::zext(e, 32 - bits);
        };
        expr = bv32(expr);
        zx = bv32(zx);
        zy = bv32(zy);

        auto eval_at_zero = [&](const z3::expr &candidate, uint64_t *out) -> bool {
            zctx.solver().reset();
            zctx.solver().add(zx == zero);
            zctx.solver().add(zy == zero);
            if ( zctx.solver().check() != z3::sat )
                return false;
            z3::expr val = zctx.solver().get_model().eval(candidate, true);
            return Z3_get_numeral_uint64(zctx.ctx(), val, out);
        };

        auto try_candidate = [&](mcode_t base_op,
                                 const mop_t &left_mop,
                                 const mop_t &right_mop,
                                 const z3::expr &base_expr) -> bool {
            z3::expr base = bv32(base_expr);
            uint64_t c = 0;
            if ( eval_at_zero(expr ^ base, &c)
              && z3_equiv(zctx, expr, base ^ zctx.ctx().bv_val(c, 32)) )
                return replace_with_binary_const_expr(ins, base_op, left_mop, right_mop, m_xor, c);
            if ( eval_at_zero(expr - base, &c)
              && z3_equiv(zctx, expr, base + zctx.ctx().bv_val(c, 32)) )
                return replace_with_binary_const_expr(ins, base_op, left_mop, right_mop, m_add, c);
            if ( eval_at_zero(base - expr, &c)
              && z3_equiv(zctx, expr, base - zctx.ctx().bv_val(c, 32)) )
                return replace_with_binary_const_expr(ins, base_op, left_mop, right_mop, m_sub, c);
            return false;
        };

        if ( try_candidate(m_and, x, y, zx & zy) )
            return 1;
        if ( try_candidate(m_or, x, y, zx | zy) )
            return 1;
        if ( try_candidate(m_xor, x, y, zx ^ zy) )
            return 1;
        if ( try_candidate(m_add, x, y, zx + zy) )
            return 1;
        if ( try_candidate(m_sub, x, y, zx - zy) )
            return 1;
        if ( try_candidate(m_sub, y, x, zy - zx) )
            return 1;

        vm_debug("[vm:pair] no compact form at %a C=0x%llx K=0x%llx\n",
                 ins->ea, (unsigned long long)add_const, (unsigned long long)outer_const);
        pair_no_compact_cache_.insert(cache_key);
    }
    catch ( const z3::exception &e )
    {
        vm_debug("[vm:pair] z3 exception at %a: %s\n", ins->ea, e.msg());
    }
    catch ( ... )
    {
        vm_debug("[vm:pair] exception at %a\n", ins->ea);
    }

    return 0;
}

int vm_mba_handler_t::simplify_single_var_residual(minsn_t *ins)
{
    qstring env;
    if ( !qgetenv("CHERNOBOG_VM_Z3", &env) || env.empty() || env[0] != '1' )
        return 0;

    if ( !ins || ins->d.size <= 0 || ins->d.size > 4 )
        return 0;
    if ( ins->opcode == m_mov )
        return 0;
    int op_count = expr_op_count(ins);
    if ( !is_pure_expr(ins) || op_count <= 1 || op_count > 8 )
        return 0;

    std::vector<mop_t> vars;
    collect_free_mops(ins, &vars);
    if ( vars.empty() || vars.size() > 4 )
        return 0;
    for ( const mop_t &v : vars )
    {
        if ( v.size != ins->d.size )
            return 0;
    }

    try
    {
        z3_solver::z3_context_t zctx;
        zctx.set_timeout(75);
        z3_solver::mcode_translator_t translator(zctx);
        z3::expr expr = translator.translate_insn(ins);
        int bits = ins->d.size * 8;
        uint64_t mask = mask_for_size(ins->d.size);
        if ( (int)expr.get_sort().bv_size() != bits )
            return 0;

        std::vector<z3::expr> zvars;
        zvars.reserve(vars.size());
        for ( const mop_t &v : vars )
        {
            z3::expr zv = translator.translate_operand(v, v.size);
            if ( (int)zv.get_sort().bv_size() != bits )
                return 0;
            zvars.push_back(zv);
        }

        if ( vars.size() == 2 && op_count <= 5 )
        {
            const mcode_t ops[] = { m_xor, m_add, m_sub, m_and, m_or };
            for ( size_t i = 0; i < vars.size(); ++i )
            {
                for ( size_t j = 0; j < vars.size(); ++j )
                {
                    if ( i == j )
                        continue;
                    for ( mcode_t op : ops )
                    {
                        z3::expr cand = zvars[i] ^ zvars[j];
                        switch ( op )
                        {
                            case m_xor: cand = zvars[i] ^ zvars[j]; break;
                            case m_add: cand = zvars[i] + zvars[j]; break;
                            case m_sub: cand = zvars[i] - zvars[j]; break;
                            case m_and: cand = zvars[i] & zvars[j]; break;
                            case m_or:  cand = zvars[i] | zvars[j]; break;
                            default: break;
                        }
                        if ( z3_equiv(zctx, expr, cand) )
                            return replace_with_binary_expr(ins, op, vars[i], vars[j]) ? 1 : 0;
                    }
                }
            }
        }

        if ( vars.size() != 1 )
            return 0;

        z3::expr var = zvars[0];

        if ( z3_equiv(zctx, expr, var) )
            return replace_with_simple_expr(ins, m_mov, vars[0], 0) ? 1 : 0;

        uint64_t at_zero = 0;
        if ( !z3_eval_uint64(zctx, expr, var, 0, &at_zero) )
            return 0;
        at_zero &= mask;

        z3::expr c0 = zctx.ctx().bv_val(at_zero, bits);
        if ( z3_equiv(zctx, expr, var ^ c0) )
            return replace_with_simple_expr(ins, m_xor, vars[0], at_zero) ? 1 : 0;
        if ( z3_equiv(zctx, expr, var + c0) )
            return replace_with_simple_expr(ins, m_add, vars[0], at_zero) ? 1 : 0;

        uint64_t sub_const = ((~at_zero) + 1) & mask;
        z3::expr csub = zctx.ctx().bv_val(sub_const, bits);
        if ( z3_equiv(zctx, expr, var - csub) )
            return replace_with_simple_expr(ins, m_sub, vars[0], sub_const) ? 1 : 0;

        uint64_t at_ones = 0;
        if ( z3_eval_uint64(zctx, expr, var, mask, &at_ones) )
        {
            at_ones &= mask;
            z3::expr cand = var & zctx.ctx().bv_val(at_ones, bits);
            if ( z3_equiv(zctx, expr, cand) )
                return replace_with_simple_expr(ins, m_and, vars[0], at_ones) ? 1 : 0;
        }
    }
    catch ( ... )
    {
        return 0;
    }

    return 0;
}

int vm_mba_handler_t::carrier_constant_eliminator(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    (void)ctx;
    if ( !mba )
        return 0;

    int changes = 0;
    for ( int i = 0; i < mba->qty; ++i )
    {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk )
            continue;
        for ( minsn_t *ins = blk->head; ins; ins = ins->next )
            changes += simplify_killed_or_cap(ins);
    }
    return changes;
}

int vm_mba_handler_t::operand_pool_constant_pass(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    (void)mba;
    (void)ctx;
    // Hex-Rays already folds read-only .rodata constants in the provided IDB.
    // Keep this as a separate pass hook so future movdqa/trunc cases can be
    // implemented without disturbing the VM detector.
    return 0;
}

bool vm_mba_handler_t::contains_text(const minsn_t *ins, const char *needle)
{
    if ( !ins || !needle )
        return false;
    std::string s = clean_insn_text(ins);
    return strstr(s.c_str(), needle) != nullptr;
}

bool vm_mba_handler_t::contains_text(const mop_t &mop, const char *needle)
{
    if ( mop.t == mop_d && mop.d )
        return contains_text(mop.d, needle);
    if ( mop.t == mop_h && mop.helper && needle )
        return strstr(mop.helper, needle) != nullptr;
    return false;
}

bool vm_mba_handler_t::contains_helper(const minsn_t *ins, const char *needle)
{
    if ( !ins )
        return false;
    return contains_helper(ins->l, needle)
        || contains_helper(ins->r, needle)
        || contains_helper(ins->d, needle)
        || contains_text(ins, needle);
}

bool vm_mba_handler_t::contains_helper(const mop_t &mop, const char *needle)
{
    if ( mop.t == mop_h && mop.helper )
        return strstr(mop.helper, needle) != nullptr;
    if ( mop.t == mop_d && mop.d )
        return contains_helper(mop.d, needle);
    if ( mop.t == mop_a && mop.a )
        return contains_helper(*mop.a, needle);
    return false;
}

bool vm_mba_handler_t::contains_pack_idiom(const minsn_t *ins)
{
    return contains_helper(ins, "_mm_unpacklo_epi32")
        || contains_helper(ins, "unpckl")
        || contains_text(ins, "_mm_unpacklo_epi32");
}

bool vm_mba_handler_t::contains_pack_idiom(const mop_t &mop)
{
    return contains_helper(mop, "_mm_unpacklo_epi32")
        || contains_helper(mop, "unpckl")
        || contains_text(mop, "_mm_unpacklo_epi32");
}

bool vm_mba_handler_t::is_accumulator_store(const minsn_t *ins)
{
    if ( !ins || ins->opcode != m_stx )
        return false;
    std::string s = clean_insn_text(ins);
    bool writes_acc_slot = strstr(s.c_str(), "+#8.8") != nullptr
                        || strstr(s.c_str(), "+ #8.8") != nullptr
                        || strstr(s.c_str(), "+8.8") != nullptr;
    if ( !writes_acc_slot )
        return false;
    if ( contains_pack_idiom(ins->l) )
        return true;
    if ( ins->l.t == mop_n )
        return false;

    // After T5 pack canonicalization the accumulator write no longer contains
    // the SSE helper call. Keep recognizing the scalar 64-bit expression so
    // segmentation remains stable after simplification.
    return ins->l.size == 8 || ins->d.size == 8;
}

bool vm_mba_handler_t::parse_ip_offset_text(const char *text, int *offset)
{
    if ( !text )
        return false;

    const char *p = text;
    while ( (p = strchr(p, '+')) != nullptr )
    {
        ++p;
        p = skip_text_spaces(p);
        if ( !p || *p != '#' )
            continue;
        ++p;
        p = skip_text_spaces(p);
        int base = 10;
        if ( p[0] == '0' && (p[1] == 'x' || p[1] == 'X') )
        {
            base = 16;
            p += 2;
        }
        char *end = nullptr;
        long v = strtol(p, &end, base);
        if ( end != p && v > 0 && v < 0x10000 )
        {
            if ( offset )
                *offset = (int)v;
            return true;
        }
        p = end ? end : p + 1;
    }

    return false;
}

bool vm_mba_handler_t::is_ip_advance_store(const minsn_t *ins, int *delta)
{
    if ( !ins || ins->opcode != m_stx )
        return false;
    std::string s = clean_insn_text(ins);
    const char *text = s.c_str();
    if ( strstr(text, "_mm_unpacklo_epi32") != nullptr )
        return false;
    if ( strstr(text, ", a1.") == nullptr && strstr(text, ", rdi.") == nullptr )
        return false;
    return parse_ip_offset_text(text, delta);
}

bool vm_mba_handler_t::is_tailcall_to_handler(const minsn_t *ins, ea_t *target)
{
    if ( !ins )
        return false;

    if ( ins->opcode == m_call && ins->l.t == mop_v )
    {
        qstring direct_name;
        if ( get_func_name(&direct_name, ins->l.g) > 0 && is_prog_bb_name(direct_name) )
        {
            if ( target )
                *target = ins->l.g;
            return true;
        }
    }

    if ( ins->l.t == mop_d && ins->l.d && is_tailcall_to_handler(ins->l.d, target) )
        return true;
    if ( ins->r.t == mop_d && ins->r.d && is_tailcall_to_handler(ins->r.d, target) )
        return true;
    if ( ins->d.t == mop_d && ins->d.d && is_tailcall_to_handler(ins->d.d, target) )
        return true;

    std::string s = clean_insn_text(ins);
    const char *p = strstr(s.c_str(), "prog_bb_");
    if ( !p )
        return false;

    std::string name;
    while ( *p && (std::isalnum((unsigned char)*p) || *p == '_') )
        name.push_back(*p++);

    ea_t ea = get_name_ea(BADADDR, name.c_str());
    if ( ea != BADADDR )
    {
        if ( target )
            *target = ea;
        return true;
    }

    if ( target )
        *target = BADADDR;
    return true;
}

void vm_mba_handler_t::collect_bytecode_reads(const mop_t &mop,
                                              std::map<int, int> *offset_widths)
{
    if ( !offset_widths )
        return;
    if ( mop.t == mop_d && mop.d )
        collect_bytecode_reads(mop.d, offset_widths);
    else if ( mop.t == mop_a && mop.a )
        collect_bytecode_reads(*mop.a, offset_widths);
}

void vm_mba_handler_t::collect_bytecode_reads(const minsn_t *ins,
                                              std::map<int, int> *offset_widths)
{
    if ( !ins || !offset_widths )
        return;

    std::string s = clean_insn_text(ins);
    const char *text = s.c_str();
    const char *p = text;
    while ( (p = strchr(p, '+')) != nullptr )
    {
        const char *scan = text;
        const char *last_lbr = nullptr;
        const char *last_rbr = nullptr;
        while ( scan < p )
        {
            if ( *scan == '[' )
                last_lbr = scan;
            else if ( *scan == ']' )
                last_rbr = scan;
            ++scan;
        }
        if ( last_lbr == nullptr || (last_rbr != nullptr && last_rbr > last_lbr) )
        {
            ++p;
            continue;
        }

        ++p;
        p = skip_text_spaces(p);
        if ( !p || *p != '#' )
            continue;
        ++p;
        p = skip_text_spaces(p);
        int base = 10;
        if ( p[0] == '0' && (p[1] == 'x' || p[1] == 'X') )
        {
            base = 16;
            p += 2;
        }
        char *end = nullptr;
        long v = strtol(p, &end, base);
        if ( end != p && v > 0 && v < 0x4000 )
        {
            const char *closing = strchr(end, ']');
            if ( closing == nullptr )
            {
                p = end ? end : p + 1;
                continue;
            }
            int width = 0;
            const char *nearby = closing;
            if ( nearby && strstr(nearby, "].1") == nearby )
                width = 8;
            else if ( nearby && strstr(nearby, "].2") == nearby )
                width = 16;
            else if ( nearby && strstr(nearby, "].4") == nearby )
                width = 32;
            if ( width == 0 && (ins->opcode == m_ldx || ins->opcode == m_xdu || ins->opcode == m_low) )
                width = ins->d.size > 0 ? ins->d.size * 8 : 0;
            if ( width == 0 )
                width = 16;
            (*offset_widths)[(int)v] = width;
        }
        p = end ? end : p + 1;
    }

    collect_bytecode_reads(ins->l, offset_widths);
    collect_bytecode_reads(ins->r, offset_widths);
    collect_bytecode_reads(ins->d, offset_widths);
}

vm_mba_handler_t::handler_summary_t vm_mba_handler_t::summarize(mbl_array_t *mba)
{
    handler_summary_t summary;
    if ( !mba )
        return summary;

    summary.ea = mba->entry_ea;
    name_matches(mba->entry_ea, &summary.name);

    std::map<int, int> operands;
    std::map<int, int> segment_operands;
    std::map<std::string, std::string> segment_defs;
    micro_op_t pending_accumulator;
    bool has_pending_accumulator = false;
    int current_delta = 0;

    for ( int i = 0; i < mba->qty; ++i )
    {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk )
            continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next )
        {
            std::map<int, int> ins_operands;
            collect_bytecode_reads(ins, &ins_operands);
            for ( const auto &kv : ins_operands )
            {
                operands[kv.first] = kv.second;
                segment_operands[kv.first] = kv.second;
            }
            summary.structural_hash = chernobog::simd::hash_combine(summary.structural_hash, hash_insn(ins));

            if ( is_accumulator_store(ins) )
            {
                summary.pack_writes++;
                pending_accumulator = micro_op_t();
                pending_accumulator.ea = ins->ea;
                pending_accumulator.writes_accumulator = true;
                pending_accumulator.primitive =
                    classify_accumulator_store_primitive(ins, segment_defs);
                pending_accumulator.ip_delta = current_delta;
                has_pending_accumulator = true;
            }

            int delta = 0;
            if ( is_ip_advance_store(ins, &delta) )
            {
                summary.ip_advances++;
                current_delta = delta;
                if ( delta > summary.stride )
                    summary.stride = delta;

                micro_op_t op = has_pending_accumulator
                              ? pending_accumulator
                              : micro_op_t();
                op.ip_delta = delta;
                op.input_count = (int)segment_operands.size();
                for ( const auto &kv : segment_operands )
                {
                    op.input_offsets.push_back(kv.first);
                    op.input_widths.push_back(kv.second);
                }
                if ( !has_pending_accumulator )
                {
                    op.ea = ins->ea;
                    op.primitive = "skip";
                }
                summary.micro_ops.push_back(op);

                segment_operands.clear();
                segment_defs.clear();
                pending_accumulator = micro_op_t();
                has_pending_accumulator = false;
            }

            ea_t succ = BADADDR;
            if ( is_tailcall_to_handler(ins, &succ) )
            {
                summary.successors.push_back(succ);
                std::string s = clean_insn_text(ins);
                summary.threads_a2 = strstr(s.c_str(), "a2.") != nullptr
                                  || strstr(s.c_str(), "rsi.") != nullptr;
                summary.consumes_a2 = summary.threads_a2
                                    && strstr(s.c_str(), "a2.8+#") == nullptr
                                    && strstr(s.c_str(), "a2.8+ #") == nullptr
                                    && strstr(s.c_str(), "a2.8+") == nullptr
                                    && strstr(s.c_str(), "rsi.8+#") == nullptr
                                    && strstr(s.c_str(), "rsi.8+ #") == nullptr
                                    && strstr(s.c_str(), "rsi.8+") == nullptr;
            }

            if ( ins->opcode != m_stx && ins->opcode != m_call && ins->opcode != m_icall )
            {
                std::string dst = extract_dest_text(ins);
                std::string expr = extract_expr_text(ins);
                if ( !dst.empty() && !expr.empty() )
                    segment_defs[dst] = expr;
            }
        }
    }

    for ( const auto &kv : operands )
    {
        summary.operand_offsets.push_back(kv.first);
        summary.operand_widths.push_back(kv.second);
    }
    summary.bytecode_reads = (int)operands.size();
    summary.fused_superblock = summary.pack_writes >= 20 || summary.stride >= 1024;
    summary.is_entry = !contains_text(mba->get_mblock(1) ? mba->get_mblock(1)->head : nullptr, "(a1.8+#8.8)");
    summary.is_terminal = summary.successors.empty();

    return summary;
}

void vm_mba_handler_t::persist_summary(const handler_summary_t &summary)
{
    if ( summary.ea == BADADDR )
        return;

    netnode node("$ chernobog vm mba", 0, true);
    if ( node == BADNODE )
        return;

    std::string json = summary_to_json(summary);
    node.supset_ea(summary.ea, json.c_str(), json.size() + 1, 'V');
    node.altset_ea(summary.ea, 1, 'C');
    for ( size_t i = 0; i < summary.successors.size(); ++i )
        node.easet((summary.ea << 8) + (ea_t)i, summary.successors[i], 'E');

#ifndef _WIN32
    qstring dump_env;
    if ( qgetenv("CHERNOBOG_VM_DUMP_JSON", &dump_env)
      && !dump_env.empty() && dump_env[0] == '1' )
    {
        char path[128];
        qsnprintf(path, sizeof(path), "/tmp/chernobog_vm_summary_%llX.json",
                  (unsigned long long)summary.ea);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if ( fd >= 0 )
        {
            write(fd, json.c_str(), json.size());
            write(fd, "\n", 1);
            close(fd);
        }
    }
#endif
}

void vm_mba_handler_t::rebuild_graph_metadata()
{
    if ( summaries_.empty() )
        return;

    std::map<ea_t, int> incoming;
    for ( const auto &kv : summaries_ )
    {
        for ( ea_t succ : kv.second.successors )
        {
            if ( succ != BADADDR )
                incoming[succ]++;
        }
    }

    for ( auto &kv : summaries_ )
    {
        handler_summary_t &summary = kv.second;
        summary.is_entry = incoming.find(summary.ea) == incoming.end();
        summary.is_terminal = summary.successors.empty();
        summary.fused_superblock = summary.pack_writes >= 20 || summary.stride >= 1024;
    }

    netnode node("$ chernobog vm mba", 0, true);
    if ( node == BADNODE )
        return;

    for ( const auto &kv : summaries_ )
    {
        std::string json = summary_to_json(kv.second);
        node.supset_ea(kv.first, json.c_str(), json.size() + 1, 'V');
    }
}

std::string vm_mba_handler_t::summary_to_json(const handler_summary_t &summary)
{
    std::ostringstream os;
    os << "{";
    os << "\"ea\":\"0x" << std::hex << std::uppercase << (uint64_t)summary.ea << std::dec << "\",";
    os << "\"name\":\"" << summary.name.c_str() << "\",";
    os << "\"stride\":" << summary.stride << ",";
    os << "\"is_entry\":" << (summary.is_entry ? "true" : "false") << ",";
    os << "\"is_terminal\":" << (summary.is_terminal ? "true" : "false") << ",";
    os << "\"threads_a2\":" << (summary.threads_a2 ? "true" : "false") << ",";
    os << "\"consumes_a2\":" << (summary.consumes_a2 ? "true" : "false") << ",";
    os << "\"fused_superblock\":" << (summary.fused_superblock ? "true" : "false") << ",";
    os << "\"pack_writes\":" << summary.pack_writes << ",";
    os << "\"ip_advances\":" << summary.ip_advances << ",";
    os << "\"operand_offsets\":[";
    for ( size_t i = 0; i < summary.operand_offsets.size(); ++i )
    {
        if ( i ) os << ",";
        os << summary.operand_offsets[i];
    }
    os << "],\"operand_widths\":[";
    for ( size_t i = 0; i < summary.operand_widths.size(); ++i )
    {
        if ( i ) os << ",";
        os << summary.operand_widths[i];
    }
    os << "],\"micro_ops\":[";
    for ( size_t i = 0; i < summary.micro_ops.size(); ++i )
    {
        const micro_op_t &op = summary.micro_ops[i];
        if ( i ) os << ",";
        os << "{\"ea\":\"0x" << std::hex << std::uppercase << (uint64_t)op.ea << std::dec << "\",";
        os << "\"input_offsets\":[";
        for ( size_t j = 0; j < op.input_offsets.size(); ++j )
        {
            if ( j ) os << ",";
            os << op.input_offsets[j];
        }
        os << "],\"input_widths\":[";
        for ( size_t j = 0; j < op.input_widths.size(); ++j )
        {
            if ( j ) os << ",";
            os << op.input_widths[j];
        }
        os << "],\"output_slot\":\"" << (op.writes_accumulator ? "acc_full" : "none") << "\",";
        os << "\"primitive\":\"" << op.primitive.c_str() << "\",";
        os << "\"ip_delta\":" << op.ip_delta << "}";
    }
    os << "],\"structural_hash\":\"0x" << std::hex << std::uppercase << summary.structural_hash << std::dec << "\",";
    os << "\"successors\":[";
    for ( size_t i = 0; i < summary.successors.size(); ++i )
    {
        if ( i ) os << ",";
        os << "\"0x" << std::hex << std::uppercase << (uint64_t)summary.successors[i] << std::dec << "\"";
    }
    os << "]}";
    return os.str();
}

void vm_mba_handler_t::dump_summary(ea_t ea)
{
    handler_summary_t s;
    if ( !get_summary(ea, &s) )
        return;
    msg("[chernobog:vm] %s @ %a stride=%d micro_ops=%zu packs=%d reads=%d succ=%zu%s%s\n",
        s.name.c_str(), s.ea, s.stride, s.micro_ops.size(), s.pack_writes,
        s.bytecode_reads, s.successors.size(),
        s.threads_a2 ? " threads_a2" : "",
        s.fused_superblock ? " fused_superblock" : "");
}

void vm_mba_handler_t::dump_statistics()
{
    if ( summaries_.empty() )
        return;
    msg("[chernobog:vm] summaries=%zu carrier_hits=%zu\n",
        summaries_.size(), carrier_hits_.size());
    for ( const auto &kv : carrier_hits_ )
        msg("[chernobog:vm]   carrier 0x%08X killed %d times\n", kv.first, kv.second);
}

uint64_t vm_mba_handler_t::hash_mop(const mop_t &mop)
{
    return chernobog::mop::hash(mop);
}

uint64_t vm_mba_handler_t::hash_insn(const minsn_t *ins)
{
    if ( !ins )
        return 0;
    uint64_t h = chernobog::simd::hash_u64((uint64_t)ins->opcode);
    h = chernobog::simd::hash_combine(h, hash_mop(ins->l));
    h = chernobog::simd::hash_combine(h, hash_mop(ins->r));
    h = chernobog::simd::hash_combine(h, (uint64_t)ins->d.size);
    return h;
}
