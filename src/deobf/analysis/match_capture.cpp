#include "match_capture.h"

#include <algorithm>
#include <map>
#include <set>

namespace chernobog::ast
{
namespace
{
using mba_diagnostics::CaptureStatus;

class Encoder
{
  public:
    CaptureStatus status = CaptureStatus::Complete;
    std::string data;

    explicit Encoder(size_t bytes, size_t visits = match_capture_visit_limit)
        : byte_limit_(bytes), visit_limit_(visits)
    {
    }

    void put(std::string_view value)
    {
        if (status != CaptureStatus::Complete)
            return;
        if (value.size() > byte_limit_ - bytes_)
        {
            status = CaptureStatus::ByteLimit;
            return;
        }
        bytes_ += value.size();
        data.append(value);
    }

    template <class T> void number(T value) { put(std::to_string(value)); }

    void identifier(std::string_view value)
    {
        if (value.size() > 128 || !std::all_of(value.begin(), value.end(),
                                               [](char c)
                                               {
                                                   return (c >= 'a' && c <= 'z') ||
                                                          (c >= 'A' && c <= 'Z') ||
                                                          (c >= '0' && c <= '9') || c == '_';
                                               }))
        {
            status = CaptureStatus::Malformed;
            return;
        }
        put("\"");
        put(value);
        put("\"");
    }

    bool charge(unsigned depth)
    {
        if (status != CaptureStatus::Complete)
            return false;
        if (depth > match_capture_depth_limit)
            status = CaptureStatus::DepthLimit;
        else if (++visits_ > visit_limit_)
            status = CaptureStatus::VisitLimit;
        return status == CaptureStatus::Complete;
    }

    void text(const char *value)
    {
        if (!value)
        {
            put("null");
            return;
        }
        static constexpr char hex[] = "0123456789abcdef";
        put("\"");
        for (size_t index = 0; index < 4096; ++index)
        {
            const auto byte = static_cast<unsigned char>(value[index]);
            if (byte == 0)
            {
                put("\"");
                return;
            }
            const char pair[] = {hex[byte >> 4], hex[byte & 15]};
            put(std::string_view(pair, 2));
            if (status != CaptureStatus::Complete)
                return;
        }
        status = CaptureStatus::Malformed;
    }

    unsigned owner(const void *value)
    {
        if (!value)
            return 0;
        const auto found = owners_.find(value);
        if (found != owners_.end())
            return found->second;
        const auto token = static_cast<unsigned>(owners_.size() + 1);
        owners_.emplace(value, token);
        return token;
    }

    void operand(const mop_t &value, unsigned depth)
    {
        if (!charge(depth))
            return;
        if (!active_.insert(&value).second)
        {
            status = CaptureStatus::Cycle;
            return;
        }
        put("[");
        number(int(value.t));
        put(",");
        number(value.size);
        put(",");
        number(value.valnum);
        put(",");
        number(value.oprops);
        put(",");
        switch (value.t)
        {
        case mop_z:
            put("0");
            break;
        case mop_r:
            number(value.r);
            break;
        case mop_n:
            if (value.nnn)
                number(value.nnn->value);
            else
                put("null");
            break;
        case mop_S:
            if (!value.s)
                put("null");
            else
            {
                put("[");
                number(owner(value.s->mba));
                put(",");
                number(value.s->off);
                put("]");
            }
            break;
        case mop_l:
            if (!value.l)
                put("null");
            else
            {
                put("[");
                number(owner(value.l->mba));
                put(",");
                number(value.l->idx);
                put(",");
                number(value.l->off);
                put("]");
            }
            break;
        case mop_v:
            number(value.g);
            break;
        case mop_b:
            number(value.b);
            break;
        case mop_d:
            instruction(value.d, depth + 1);
            break;
        case mop_a:
            if (value.a)
                operand(*value.a, depth + 1);
            else
                put("null");
            break;
        case mop_h:
            text(value.helper);
            break;
        case mop_str:
            text(value.cstr);
            break;
        default:
            // mops_equal_strict refuses these payloads unconditionally.
            // Their common metadata and this opaque marker suffice for replay.
            put("0");
            break;
        }
        put("]");
        active_.erase(&value);
    }

    void instruction(const minsn_t *value, unsigned depth)
    {
        if (!value)
        {
            put("null");
            return;
        }
        if (!charge(depth))
            return;
        if (!active_.insert(value).second)
        {
            status = CaptureStatus::Cycle;
            return;
        }
        put("[");
        number(int(value->opcode));
        put(",");
        number(value->iprops);
        put(",");
        number(uint64_t(value->ea));
        put(",");
        operand(value->l, depth + 1);
        put(",");
        operand(value->r, depth + 1);
        put(",");
        operand(value->d, depth + 1);
        put("]");
        active_.erase(value);
    }

    void candidate(const AstBase *value, unsigned depth = 0)
    {
        if (!value)
        {
            put("null");
            return;
        }
        if (!charge(depth))
            return;
        if (!active_.insert(value).second)
        {
            status = CaptureStatus::Cycle;
            return;
        }
        put(value->is_node() ? "[\"n\"," : "[\"v\",");
        number(value->dest_size);
        put(",");
        operand(value->mop, depth + 1);
        if (value->is_node())
        {
            const auto &node = static_cast<const AstNode &>(*value);
            put(",");
            number(int(node.opcode));
            put(",");
            candidate(node.left.get(), depth + 1);
            put(",");
            candidate(node.right.get(), depth + 1);
        }
        put("]");
        active_.erase(value);
    }

    void pattern(const AstBase *value, unsigned depth = 0)
    {
        if (!value)
        {
            put("null");
            return;
        }
        if (!charge(depth))
            return;
        if (!active_.insert(value).second)
        {
            status = CaptureStatus::Cycle;
            return;
        }
        if (value->is_constant())
        {
            const auto &constant = static_cast<const AstConstant &>(*value);
            put("[\"k\",");
            number(constant.value);
            put(",");
            identifier(constant.const_name);
            put("]");
        }
        else if (value->is_leaf())
        {
            put("[\"v\",");
            identifier(static_cast<const AstLeaf &>(*value).name);
            put("]");
        }
        else
        {
            const auto &node = static_cast<const AstNode &>(*value);
            put("[\"n\",");
            number(int(node.opcode));
            put(",");
            pattern(node.left.get(), depth + 1);
            put(",");
            pattern(node.right.get(), depth + 1);
            put("]");
        }
        active_.erase(value);
    }

  private:
    size_t byte_limit_, visit_limit_, bytes_ = 0, visits_ = 0;
    std::set<const void *> active_;
    std::map<const void *, unsigned, std::less<const void *>> owners_;
};

std::string sdk_model()
{
    Encoder out(catalog_capture_byte_limit);
    out.put("{\"mops\":{");
    bool first = true;
    const auto entry = [&](const char *name, int code)
    {
        if (!first)
            out.put(",");
        first = false;
        out.identifier(name);
        out.put(":");
        out.number(code);
    };
#define CAPTURE_MOP(name) entry(#name, mop_##name)
    CAPTURE_MOP(z);
    CAPTURE_MOP(r);
    CAPTURE_MOP(n);
    CAPTURE_MOP(S);
    CAPTURE_MOP(v);
    CAPTURE_MOP(l);
    CAPTURE_MOP(d);
    CAPTURE_MOP(b);
    CAPTURE_MOP(f);
    CAPTURE_MOP(a);
    CAPTURE_MOP(h);
    CAPTURE_MOP(str);
    CAPTURE_MOP(c);
    CAPTURE_MOP(p);
    CAPTURE_MOP(fn);
    CAPTURE_MOP(sc);
#undef CAPTURE_MOP
    out.put("},\"ops\":{");
    first = true;
#define CAPTURE_OP(name) entry(#name, m_##name)
    CAPTURE_OP(nop);
    CAPTURE_OP(mov);
    CAPTURE_OP(ldx);
    CAPTURE_OP(stx);
    CAPTURE_OP(add);
    CAPTURE_OP(sub);
    CAPTURE_OP(mul);
    CAPTURE_OP(and);
    CAPTURE_OP(or);
    CAPTURE_OP(xor);
    CAPTURE_OP(bnot);
    CAPTURE_OP(neg);
    CAPTURE_OP(low);
    CAPTURE_OP(high);
    CAPTURE_OP(xdu);
    CAPTURE_OP(xds);
    CAPTURE_OP(lnot);
    CAPTURE_OP(udiv);
    CAPTURE_OP(sdiv);
    CAPTURE_OP(umod);
    CAPTURE_OP(smod);
    CAPTURE_OP(shl);
    CAPTURE_OP(shr);
    CAPTURE_OP(sar);
    CAPTURE_OP(cfadd);
    CAPTURE_OP(ofadd);
    CAPTURE_OP(sets);
    CAPTURE_OP(seto);
    CAPTURE_OP(setp);
    CAPTURE_OP(setnz);
    CAPTURE_OP(setz);
    CAPTURE_OP(setae);
    CAPTURE_OP(setb);
    CAPTURE_OP(seta);
    CAPTURE_OP(setbe);
    CAPTURE_OP(setg);
    CAPTURE_OP(setge);
    CAPTURE_OP(setl);
    CAPTURE_OP(setle);
#undef CAPTURE_OP
    out.put("}}");
    return out.data;
}
} // namespace

mba_diagnostics::CapturedInput capture_match_input(const AstPtr &candidate, const minsn_t *anchor,
                                                   const minsn_t *block_head, const minsn_t *source)
{
    if (!candidate)
        return {CaptureStatus::NoAst, {}};
    Encoder out(mba_diagnostics::input_byte_limit - 256);
    out.candidate(candidate.get());
    if (out.status != CaptureStatus::Complete)
        return {out.status, {}};
    const std::string root = std::move(out.data);
    out.data.clear();
    out.instruction(anchor, 0);
    const bool enclosing_complete = out.status == CaptureStatus::Complete;
    const std::string enclosing = enclosing_complete ? std::move(out.data) : "null";
    std::vector<std::string> prefix;
    std::string frontier = "missing_anchor";
    if (!enclosing_complete)
        frontier = mba_diagnostics::capture_status_name(out.status);
    else if (anchor && block_head)
    {
        const minsn_t *cursor = anchor;
        std::set<const minsn_t *> seen{anchor};
        frontier = "head_limit";
        while (prefix.size() < match_prefix_head_limit)
        {
            if (cursor == block_head)
            {
                frontier = "block_entry";
                break;
            }
            const auto *previous = cursor->prev;
            if (!previous || previous->next != cursor || !seen.insert(previous).second)
            {
                frontier = "link_error";
                prefix.clear();
                break;
            }
            out.data.clear();
            out.instruction(previous, 0);
            if (out.status != CaptureStatus::Complete)
            {
                frontier = mba_diagnostics::capture_status_name(out.status);
                break; // Retain only complete nearest predecessors, never an internal hole.
            }
            prefix.push_back(std::move(out.data));
            cursor = previous;
        }
        if (cursor == block_head && frontier == "head_limit")
            frontier = "block_entry";
    }
    std::string result = "{\"root\":" + root +
                         ",\"root_iprops\":" + (source ? std::to_string(source->iprops) : "null") +
                         ",\"enclosing\":" + enclosing + ",\"anchor\":" +
                         std::to_string(anchor ? uint64_t(anchor->ea) : UINT64_MAX) +
                         ",\"prefix_status\":\"" + frontier + "\",\"prefix\":[";
    for (auto it = prefix.rbegin(); it != prefix.rend(); ++it)
    {
        if (it != prefix.rbegin())
            result += ',';
        result += *it;
    }
    result += "]}";
    if (result.size() > mba_diagnostics::input_byte_limit)
        return {CaptureStatus::ByteLimit, {}};
    return {CaptureStatus::Complete, std::move(result)};
}

std::string capture_catalog_patterns(const std::vector<std::pair<std::string, AstPtr>> &patterns,
                                     bool initialized)
{
    Encoder out(catalog_capture_byte_limit - 2048, 8192);
    out.put("[");
    for (size_t index = 0; index < patterns.size(); ++index)
    {
        if (index)
            out.put(",");
        out.put("[");
        out.identifier(patterns[index].first);
        out.put(",");
        out.pattern(patterns[index].second.get());
        out.put("]");
    }
    out.put("]");
    const std::string status =
        !initialized ? "not_initialized" : mba_diagnostics::capture_status_name(out.status);
    const std::string data = initialized && out.status == CaptureStatus::Complete ? out.data : "[]";
    return "{\"schema\":1,\"status\":\"" + status + "\",\"model\":" + sdk_model() +
           ",\"patterns\":" + data + "}";
}
} // namespace chernobog::ast
