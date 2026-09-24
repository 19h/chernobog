#include "ida_native_trace.hpp"
#include "native_region.hpp"
#include "native_observations.hpp"
#include "ida_regions.hpp"
#include "../hybrid/emu_driver.hpp"
#include "../hybrid/evidence.hpp"
#include "../hybrid/call_summary_policy.hpp"
#include "../common/inspection_json.hpp"
#include "../common/warn_off.h"
#include <pro.h>
#include <ida.hpp>
#include <funcs.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <idp.hpp>
#include <intel.hpp>
#include <ua.hpp>
#include <parsejson.hpp>
#include <name.hpp>
#include <segment.hpp>
#include "../common/warn_on.h"
#include <atomic>
#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <sstream>

namespace chernobog::vm
{
namespace
{
struct StringLease
{
    uint64_t ticket = 0, context = 0;
    int64_t database = 0;
    int filetype = 0;
    hybrid::ProgramImage image;
    std::string bindings, identity;
};
std::unique_ptr<StringLease> string_lease;

bool same_image(const hybrid::ProgramImage &a, const hybrid::ProgramImage &b)
{
    if (std::tie(a.arch, a.big_endian, a.lo, a.hi) != std::tie(b.arch, b.big_endian, b.lo, b.hi) ||
        a.segs.size() != b.segs.size() || a.entries.size() != b.entries.size())
        return false;
    for (size_t i = 0; i < a.segs.size(); ++i)
    {
        const auto &x = a.segs[i], &y = b.segs[i];
        if (std::tie(x.start, x.end, x.perm, x.bitness, x.kind, x.bytes, x.mask) !=
            std::tie(y.start, y.end, y.perm, y.bitness, y.kind, y.bytes, y.mask))
            return false;
    }
    for (size_t i = 0; i < a.entries.size(); ++i)
    {
        const auto &x = a.entries[i], &y = b.entries[i];
        const auto &p = x.profile, &q = y.profile;
        if (std::tie(x.start, x.end, x.entry_mode, p.flavor, p.name, p.objc_selector,
                     p.explicit_arguments, p.explicit_arguments_known) !=
                std::tie(y.start, y.end, y.entry_mode, q.flavor, q.name, q.objc_selector,
                         q.explicit_arguments, q.explicit_arguments_known) ||
            x.chunks.size() != y.chunks.size())
            return false;
        for (size_t c = 0; c < x.chunks.size(); ++c)
            if (std::tie(x.chunks[c].start, x.chunks[c].end) !=
                std::tie(y.chunks[c].start, y.chunks[c].end))
                return false;
    }
    return true;
}
std::string hex(uint64_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}
std::string bytes(const std::vector<uint8_t> &data)
{
    static const char digits[] = "0123456789abcdef";
    std::string text;
    for (uint8_t byte : data)
    {
        text += digits[byte >> 4];
        text += digits[byte & 15];
    }
    return text;
}
std::string unavailable(const char *reason, bool candidate = false)
{
    return std::string("{\"schema\":1,\"available\":false,\"scope\":") +
           inspection_json_quote(candidate ? "native-candidate-region" : "native-region") +
           ",\"reason\":" + inspection_json_quote(reason) + "}";
}
bool keys(const jobj_t &object, std::initializer_list<const char *> required)
{
    if (object.size() != required.size())
        return false;
    std::set<std::string> seen;
    for (const auto &kv : object)
    {
        if (!seen.insert(kv.key.c_str()).second)
            return false;
        if (std::none_of(required.begin(), required.end(),
                         [&](const char *key) { return kv.key == key; }))
            return false;
    }
    return true;
}
int digit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}
bool parse_input(const std::string &request, hybrid::EmuInput &input)
{
    // Bound bytes and nesting before invoking the SDK parser. Never return parser
    // diagnostics containing input material or paths to the UI.
    if (request.empty() || request.size() > 140000 || request.find('\0') != std::string::npos)
        return false;
    unsigned depth = 0;
    bool quoted = false, escaped = false;
    for (char c : request)
    {
        if (quoted)
        {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == '"')
                quoted = false;
            continue;
        }
        if (c == '"')
            quoted = true;
        else if (c == '[' || c == '{')
        {
            if (++depth > 8)
                return false;
        }
        else if (c == ']' || c == '}')
        {
            if (!depth)
                return false;
            --depth;
        }
    }
    if (depth || quoted)
        return false;
    jvalue_t root;
    if (parse_json_string(&root, request.c_str()) != eOk || root.type() != JT_OBJ ||
        !keys(root.obj(), {"args", "objects"}))
        return false;
    const auto *args = root.obj().get_value("args", JT_ARR);
    const auto *objects = root.obj().get_value("objects", JT_ARR);
    if (!args || !objects || args->arr().values.size() > 32 || objects->arr().values.size() > 16)
        return false;
    for (const auto &arg : args->arr().values)
    {
        if (arg.type() != JT_STR)
            return false;
        const auto &s = arg.qstr();
        if (s.length() < 3 || s.length() > 18 || s[0] != '0' || s[1] != 'x')
            return false;
        uint64_t value = 0;
        for (size_t i = 2; i < s.length(); ++i)
        {
            const int d = digit(s[i]);
            if (d < 0)
                return false;
            value = (value << 4) | unsigned(d);
        }
        input.args.push_back(value);
    }
    size_t total = 0;
    std::set<uint32_t> used;
    for (const auto &object : objects->arr().values)
    {
        if (object.type() != JT_OBJ || !keys(object.obj(), {"argument", "offset", "bytes"}))
            return false;
        const auto *arg = object.obj().get_value("argument", JT_NUM);
        const auto *offset = object.obj().get_value("offset", JT_NUM);
        const auto *data = object.obj().get_value("bytes", JT_STR);
        if (!arg || !offset || !data || arg->num() < 0 ||
            arg->num() >= int64_t(input.args.size()) || offset->num() < 0 || offset->num() > 4095)
            return false;
        hybrid::EmuInput::NativeObject value;
        value.argument = uint32_t(arg->num());
        value.offset = uint32_t(offset->num());
        const auto &s = data->qstr();
        if (s.empty() || s.length() > 8192 || s.length() % 2 || value.offset >= s.length() / 2 ||
            input.args[value.argument] != 0 || !used.insert(value.argument).second)
            return false;
        for (size_t i = 0; i < s.length(); i += 2)
        {
            const int hi = digit(s[i]), lo = digit(s[i + 1]);
            if (hi < 0 || lo < 0)
                return false;
            value.bytes.push_back(uint8_t(hi * 16 + lo));
        }
        total += value.bytes.size();
        if (total > 65536)
            return false;
        input.native_objects.push_back(std::move(value));
    }
    return true;
}
bool read_runtime_shadow(const std::string &path, std::vector<uint8_t> &bytes)
{
    if (path.empty() || path.size() > 4096 || path.find('\0') != std::string::npos)
        return false;
    FILE *stream = qfopen(path.c_str(), "rb");
    if (!stream)
        return false;
    const uint64_t length = qfsize(stream);
    if (!length || length > 65536)
    {
        qfclose(stream);
        return false;
    }
    bytes.resize(size_t(length));
    const ssize_t count = qfread(stream, bytes.data(), size_t(length));
    const int closed = qfclose(stream);
    return count == ssize_t(length) && closed == 0;
}
uint64_t runtime_shadow_fingerprint(const std::vector<uint8_t> &bytes)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    for (uint8_t byte : bytes)
    {
        hash ^= byte;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}
bool decode_native(uint64_t ea, const uint8_t *expected, size_t offered, rax_decoded &out,
                   unsigned mode)
{
    insn_t insn;
    if (decode_insn(&insn, ea_t(ea)) <= 0 || !insn.size || insn.size > offered ||
        (mode == 64 ? !mode64(insn) : !mode32(insn)))
        return false;
    uint8_t actual[15] = {};
    if (insn.size > sizeof(actual) || get_bytes(actual, insn.size, ea_t(ea)) != insn.size ||
        !std::equal(actual, actual + insn.size, expected))
        return false;
    // Segment/privilege transitions are outside the flat user-mode snapshot.
    if (insn.Op1.type == o_far || insn.itype == NN_callfi || insn.itype == NN_jmpfi ||
        insn.itype == NN_retf || insn.itype == NN_retfw || insn.itype == NN_retfd ||
        insn.itype == NN_retfq || insn.itype == NN_iret || insn.itype == NN_iretw ||
        insn.itype == NN_iretd || insn.itype == NN_iretq)
        return false;
    // The 16-bit BSWAP encoding has undefined architectural results. The native
    // capture contract does not choose the emulator's result as hardware truth.
    if (insn.itype == NN_bswap && get_dtype_size(insn.Op1.dtype) != 4 &&
        get_dtype_size(insn.Op1.dtype) != 8)
        return false;
    out = {};
    out.valid = 1;
    out.size = insn.size;
    out.flow = RAX_FLOW_FALLTHROUGH;
    const bool near = insn.Op1.type == o_near;
    if (near)
    {
        out.has_target = 1;
        out.target = to_ea(insn.cs, insn.Op1.addr);
    }
    if (is_call_insn(insn))
    {
        out.flow = near ? RAX_FLOW_CALL : RAX_FLOW_INDIRECT_CALL;
        out.is_indirect = !near;
    }
    else if (is_ret_insn(insn))
        out.flow = RAX_FLOW_RETURN;
    else if (insn.itype == NN_jmp || insn.itype == NN_jmpshort || insn.itype == NN_jmpni)
    {
        out.flow = near ? RAX_FLOW_BRANCH : RAX_FLOW_INDIRECT_JUMP;
        out.is_indirect = !near;
    }
    else if (insn_jcc(insn) || insn.itype == NN_jcxz || insn.itype == NN_jecxz ||
             insn.itype == NN_jrcxz || insn.itype == NN_loop || insn.itype == NN_loopq ||
             insn.itype == NN_loope || insn.itype == NN_loopqe || insn.itype == NN_loopne ||
             insn.itype == NN_loopqne)
    {
        out.flow = near ? RAX_FLOW_COND_BRANCH : RAX_FLOW_UNKNOWN;
        out.fallthrough = ea + insn.size;
    }
    else if (insn.itype == NN_int || insn.itype == NN_int3 || insn.itype == NN_into ||
             insn.itype == NN_syscall || insn.itype == NN_sysenter || insn.itype == NN_sysexit ||
             insn.itype == NN_sysret || insn.itype == NN_xbegin || insn.itype == NN_hlt ||
             insn.itype == NN_ud2 || (insn.get_canon_feature(PH) & (CF_CALL | CF_JUMP | CF_STOP)))
        out.flow = RAX_FLOW_TRAP;
    return true;
}

bool parse_bindings(const std::string &request, std::vector<hybrid::EmuCallSummary> &bindings)
{
    if (request.empty() || request.size() > 8192 || request.find('\0') != std::string::npos)
        return false;
    // Flat array of flat records; reject deep input before entering the parser.
    unsigned depth = 0;
    bool quoted = false, escaped = false;
    for (char c : request)
    {
        if (quoted)
        {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == '"')
                quoted = false;
            continue;
        }
        if (c == '"')
            quoted = true;
        else if (c == '[' || c == '{')
        {
            if (++depth > 2)
                return false;
        }
        else if (c == ']' || c == '}')
        {
            if (!depth)
                return false;
            --depth;
        }
    }
    if (depth || quoted)
        return false;
    jvalue_t root;
    if (parse_json_string(&root, request.c_str()) != eOk || root.type() != JT_ARR ||
        root.arr().values.empty() || root.arr().values.size() > 32)
        return false;
    std::set<uint64_t> addresses;
    for (const auto &value : root.arr().values)
    {
        if (value.type() != JT_OBJ || !keys(value.obj(), {"address", "name"}))
            return false;
        const auto *address = value.obj().get_value("address", JT_STR);
        const auto *name = value.obj().get_value("name", JT_STR);
        if (!address || !name || name->qstr().empty() || name->qstr().length() > 128)
            return false;
        const auto &text = address->qstr();
        uint64_t ea = 0;
        if (text.length() < 3 || text.length() > 18 || text[0] != '0' || text[1] != 'x')
            return false;
        for (size_t i = 2; i < text.length(); ++i)
        {
            const int d = digit(text[i]);
            if (d < 0)
                return false;
            ea = (ea << 4) | unsigned(d);
        }
        qstring actual;
        if (ea == bad_address || !addresses.insert(ea).second || !is_mapped(ea_t(ea)) ||
            get_name(&actual, ea_t(ea)) <= 0 || actual != name->qstr())
            return false;
        const auto kind = hybrid::hybrid_classify_call_summary_name(actual.c_str());
        if (!kind || *kind == hybrid::EmuSummaryKind::UNMODELED)
            return false;
        bindings.push_back({ea, *kind, actual.c_str()});
    }
    return true;
}
}
static std::string trace_native_region_impl(
    uint64_t function, uint64_t seed, const hybrid::EmuInput *explicit_input, bool walk = false,
    bool check = false, const std::vector<hybrid::EmuCallSummary> *bindings = nullptr,
    hybrid::NativeTemporalStringRun *retained = nullptr,
    hybrid::ProgramImage *retained_image = nullptr, bool candidate_entry = false,
    const std::vector<uint8_t> *runtime_shadow = nullptr, bool sample_states = false)
{
    using namespace hybrid;
    if (sample_states && (!candidate_entry || !runtime_shadow || walk || check || bindings))
        return unavailable("invalid runtime shadow state request", candidate_entry);
    const auto *api = rax_load();
    if (!api || !api->decode)
        return unavailable("native decoder/emulator unavailable", candidate_entry);
    if (candidate_entry)
    {
        const auto *segment = getseg(ea_t(function));
        const auto flags = get_flags(ea_t(function));
        if (PH.id != PLFM_386 || function == BADADDR || uint64_t(ea_t(function)) != function ||
            !segment || segment->type == SEG_XTRN || !(segment->perm & SEGPERM_EXEC) ||
            (segment->bitness != 1 && segment->bitness != 2) || !is_data(flags) ||
            !is_head(flags) || has_user_name(flags) || !is_loaded(ea_t(function)) ||
            get_func(ea_t(function)))
            return unavailable("not_unlabeled_executable_data_head", true);
    }
    else
    {
        const auto *owner = get_func(ea_t(function));
        if (!owner || owner->start_ea != function)
            return unavailable("selected function unavailable");
    }
    HybridConfig config;
    config.max_image_bytes = 64ull * 1024 * 1024;
    config.max_insns = 4096;
    config.timeout_ms = sample_states ? 1000 : 250;
    config.want_runtime_strings = false;
    config.want_import_summaries = false;
    config.max_runtime_bytes = 65536;
    ProgramImage image;
    const auto snapshot = candidate_entry ? hybrid_snapshot_image(image, config)
                                          : hybrid_snapshot_function(image, config, function);
    if (!snapshot.complete)
        return unavailable("incomplete or unsupported image snapshot", candidate_entry);
    size_t shadow_changed = 0;
    if (runtime_shadow)
    {
        if (!candidate_entry || image.arch != HybridArch::X86_64 ||
            runtime_shadow->size() > UINT64_MAX - function)
            return unavailable("invalid runtime shadow scope", candidate_entry);
        const uint64_t end = function + runtime_shadow->size();
        auto segment = std::find_if(image.segs.begin(), image.segs.end(),
                                    [&](const SegImage &part)
                                    {
                                        return part.start <= function && end <= part.end &&
                                               part.kind == HybridSegmentKind::NORMAL &&
                                               part.has_perm(HybridSegPerm::EXEC) &&
                                               part.bitness == 2;
                                    });
        if (segment == image.segs.end())
            return unavailable("runtime shadow outside one executable segment", true);
        const size_t offset = size_t(function - segment->start);
        for (size_t index = 0; index < runtime_shadow->size(); ++index)
        {
            if (!segment->byte_loaded(function + index))
                return unavailable("runtime shadow covers unloaded image bytes", true);
            shadow_changed += segment->bytes[offset + index] != (*runtime_shadow)[index];
        }
        std::copy(runtime_shadow->begin(), runtime_shadow->end(), segment->bytes.begin() + offset);
        image.content_hash = hybrid_program_content_hash(image);
    }
    const unsigned mode = image.arch == HybridArch::X86_64 ? 64 : 32;
    if (explicit_input && mode == 32 &&
        std::any_of(explicit_input->args.begin(), explicit_input->args.end(),
                    [](uint64_t value) { return value > UINT32_MAX; }))
        return unavailable("argument exceeds architecture width", candidate_entry);
    const NativeDecoder decoder =
        runtime_shadow ? NativeDecoder{}
                       : NativeDecoder{[mode](uint64_t ea, const uint8_t *data, size_t size,
                                              rax_decoded &decoded)
                                       { return decode_native(ea, data, size, decoded, mode); }};
    auto region = plan_native_region(image, api, function, runtime_shadow ? 16384 : 4096, decoder);
    if (!region.available())
        return unavailable("entry has no admissible native instruction", candidate_entry);
    EmuDriver driver(api, image, true, inf_get_filetype() == f_PE,
                     bindings ? *bindings : std::vector<EmuCallSummary>{});
    EmuInput input = explicit_input ? *explicit_input : EmuInput{};
    input.seed = seed;
    input.run_id = 1;
    EmuEvents events;
    EmuOutcome outcome;
    const uint64_t initial_identity = region.identity();
    const bool ran =
        bindings ? driver.emulate_region_temporal(region, config, events, outcome, decoder, &input)
        : walk   ? driver.emulate_region_walk(region, config, events, outcome, decoder, 64, &input,
                                              check)
        : sample_states ? driver.emulate_region_states(region, config, events, outcome, &input)
                        : driver.emulate_region(region, config, events, outcome, &input);
    static std::atomic<uint64_t> next_capture{1};
    uint64_t capture = next_capture.load();
    while (capture != UINT64_MAX && !next_capture.compare_exchange_weak(capture, capture + 1))
    {
    }
    if (capture == UINT64_MAX)
        return unavailable("capture identity exhausted", candidate_entry);
    NativeObservationView observations;
    if (check && ran)
    {
        std::map<uint64_t, Instruction> instructions;
        if (!decode_native_semantic_heads(region, mode, instructions))
            observations.reason = "semantic decode no longer matches native plan bytes/mode";
        else
            observations =
                project_native_observations(region, instructions, events, outcome, mode, capture,
                                            function, true, int64_t(get_dbctx_id()));
    }
    using Row = std::map<std::string, std::string>;
    std::vector<Row> heads, frontiers, execution, edges, states, data, writes, objects,
        final_registers, arguments, admissions;
    std::vector<Row> models, allocations, uses;
    if (bindings)
        for (const auto &binding : *bindings)
            models.push_back({{"address", hex(binding.address)},
                              {"name", binding.name},
                              {"kind", std::to_string(unsigned(binding.kind))}});
    for (const auto &object : events.allocations)
        allocations.push_back({{"id", hex(object.id)},
                               {"generation", hex(object.generation)},
                               {"address", hex(object.address)},
                               {"size", std::to_string(object.size)},
                               {"site", hex(object.site)},
                               {"context", hex(object.context)},
                               {"allocated", std::to_string(object.allocated)},
                               {"released", std::to_string(object.released)},
                               {"live", object.live ? "true" : "false"}});
    for (const auto &use : events.uses)
        uses.push_back({{"site", hex(use.site)},
                        {"context", hex(use.context)},
                        {"sequence", std::to_string(use.sequence)},
                        {"address", hex(use.address)},
                        {"allocation", hex(use.allocation_id)},
                        {"generation", hex(use.generation)},
                        {"callee", hex(use.callee)},
                        {"argument", std::to_string(use.argument)},
                        {"producer", use_producer_name(use.producer)},
                        {"model_kind", std::to_string(use.model_kind)},
                        {"status", std::to_string(unsigned(use.status))},
                        {"scope", std::to_string(unsigned(use.scope))},
                        {"bytes", bytes(use.bytes)},
                        {"observed_size", std::to_string(use.observed_size)}});
    for (const auto &step : outcome.native_admissions)
        admissions.push_back({{"source", hex(step.source)},
                              {"target", hex(step.target)},
                              {"sequence", std::to_string(step.sequence)},
                              {"before_identity", hex(step.before_identity)},
                              {"after_identity", hex(step.after_identity)},
                              {"added_heads", std::to_string(step.added_heads)},
                              {"admitted", step.admitted ? "true" : "false"},
                              {"reason", step.reason}});
    for (size_t index = 0; index < input.args.size(); ++index)
        arguments.push_back({{"index", std::to_string(index)}, {"value", hex(input.args[index])}});
    for (const auto &object : outcome.native_objects)
        objects.push_back({{"argument", std::to_string(object.argument)},
                           {"offset", std::to_string(object.offset)},
                           {"address", hex(object.address)},
                           {"initial", bytes(object.initial)},
                           {"final", bytes(object.final)},
                           {"readable", object.readable ? "true" : "false"}});
    for (const auto &reg : outcome.native_final_registers)
        final_registers.push_back({{"reg", std::to_string(reg.reg)},
                                   {"width", std::to_string(reg.width)},
                                   {"value", hex(reg.value)}});
    for (const auto &head : region.heads())
        heads.push_back({{"site", hex(head.address)},
                         {"bytes", bytes(head.bytes)},
                         {"size", std::to_string(head.bytes.size())},
                         {"flow", std::to_string(head.flow)}});
    for (const auto &f : region.frontiers())
        frontiers.push_back({{"site", hex(f.site)}, {"reason", f.reason}});
    std::set<uint64_t> ownerless, foreign;
    for (const auto &point : events.execution)
    {
        const auto *actual = get_func(ea_t(point.pc));
        if (!actual)
            ownerless.insert(point.pc);
        else if (actual->start_ea != function)
            foreign.insert(point.pc);
        execution.push_back({{"site", hex(point.pc)},
                             {"size", std::to_string(point.size)},
                             {"sequence", std::to_string(point.sequence)},
                             {"owner", actual ? hex(actual->start_ea) : "none"}});
    }
    for (const auto &edge : events.edges)
        edges.push_back({{"source", hex(edge.from)},
                         {"target", hex(edge.to)},
                         {"sequence", std::to_string(edge.sequence)},
                         {"kind", edge.kind == ExecEdge::Kind::Call     ? "call"
                                  : edge.kind == ExecEdge::Kind::Return ? "return"
                                  : edge.kind == ExecEdge::Kind::Jump   ? "jump"
                                                                        : "unknown"}});
    for (const auto &state : events.states)
    {
        std::string registers;
        for (const auto &reg : state.regs)
        {
            if (!registers.empty())
                registers += ';';
            registers +=
                std::to_string(reg.reg) + ":" + std::to_string(reg.width) + ":" + hex(reg.value);
        }
        states.push_back(
            {{"site", hex(state.pc)},
             {"source", hex(state.source)},
             {"sequence", std::to_string(state.sequence)},
             {"registers", registers},
             {"kind", state.kind == StatePoint::Kind::RegionEntry ? "seeded entry"
                      : state.kind == StatePoint::Kind::NativeInstructionEntry
                          ? "native instruction entry"
                      : state.kind == StatePoint::Kind::TransferTarget ? "transfer target"
                                                                       : "predicate input"}});
    }
    for (const auto &access : events.data)
        data.push_back({{"site", hex(access.from)},
                        {"address", hex(access.addr)},
                        {"size", std::to_string(access.size)},
                        {"value", hex(access.value)},
                        {"sequence", std::to_string(access.sequence)},
                        {"kind", access.kind == RAX_MEM_WRITE ? "write" : "read"}});
    for (const auto &write : events.final_writes)
        writes.push_back({{"address", hex(write.addr)}, {"bytes", bytes(write.bytes)}});
    std::ostringstream out;
    out << "{\"schema\":1,\"available\":true,\"scope\":"
        << inspection_json_quote(candidate_entry ? "native-candidate-region" : "native-region")
        << ",\"capture\":" << capture
        << ",\"database\":" << inspection_json_quote(std::to_string(int64_t(get_dbctx_id())))
        << (candidate_entry ? ",\"root\":" : ",\"function\":")
        << inspection_json_quote(hex(function)) << ",\"seed\":" << inspection_json_quote(hex(seed))
        << ",\"region_identity\":" << inspection_json_quote(hex(region.identity()))
        << ",\"initial_region_identity\":" << inspection_json_quote(hex(initial_identity))
        << ",\"native_walk\":" << (walk ? "true" : "false")
        << ",\"native_walk_stop\":" << inspection_json_quote(outcome.native_walk_stop)
        << ",\"native_state_capture_requested\":"
        << (outcome.native_state_capture_requested ? "true" : "false")
        << ",\"native_state_capture_complete\":"
        << (outcome.native_state_capture_complete ? "true" : "false")
        << ",\"image_hash\":" << inspection_json_quote(hex(region.image_hash()))
        << ",\"generation\":" << inspection_json_quote(hex(region.generation()))
        << ",\"address_bits\":" << (image.arch == HybridArch::X86_64 ? 64 : 32) << ",\"decoder\":"
        << inspection_json_quote(runtime_shadow
                                     ? "RAX x86-64 decoder over caller-supplied shadow bytes"
                                     : "IDA mode-aware native decoder, snapshot bytes checked")
        << ",\"planned_heads\":" << region.heads().size()
        << ",\"plan_truncated\":" << (region.truncated() ? "true" : "false")
        << ",\"ran\":" << (ran ? "true" : "false") << ",\"stop\":"
        << inspection_json_quote(ran ? hybrid_emu_outcome_name(outcome) : "capture-unavailable")
        << ",\"stop_status\":" << outcome.stop_status
        << ",\"stop_pc\":" << inspection_json_quote(hex(outcome.stop_pc))
        << ",\"instruction_count\":" << outcome.instruction_count
        << ",\"entry_sp\":" << inspection_json_quote(hex(outcome.entry_sp))
        << ",\"explicit_input\":" << (explicit_input ? "true" : "false")
        << ",\"sp_valid\":" << (outcome.sp_valid ? "true" : "false")
        << ",\"sp_delta\":" << outcome.sp_delta << ",\"final_registers_complete\":"
        << (outcome.native_final_registers_complete ? "true" : "false")
        << ",\"reached_sentinel\":" << (outcome.returned ? "true" : "false")
        << ",\"region_boundary\":" << (outcome.region_boundary ? "true" : "false")
        << ",\"region_code_changed\":" << (outcome.region_code_changed ? "true" : "false")
        << ",\"boundary_source\":" << inspection_json_quote(hex(outcome.region_boundary_source))
        << ",\"boundary_target\":" << inspection_json_quote(hex(outcome.region_boundary_target))
        << ",\"data_trace_complete\":" << (outcome.data_trace_complete ? "true" : "false")
        << ",\"data_trace_truncated\":" << (outcome.data_trace_truncated ? "true" : "false")
        << ",\"native_temporal_requested\":"
        << (outcome.native_temporal_requested ? "true" : "false")
        << ",\"native_temporal_complete\":" << (outcome.native_temporal_complete ? "true" : "false")
        << ",\"native_temporal_prefix_complete\":"
        << (outcome.native_temporal_prefix_complete ? "true" : "false")
        << ",\"native_temporal_prefix_end\":" << outcome.native_temporal_prefix_end
        << ",\"backend_stop\":"
        << inspection_json_quote(hybrid_rax_stop_reason_name(outcome.stop_reason))
        << ",\"temporal_capture_complete\":"
        << (outcome.temporal_capture_complete ? "true" : "false")
        << ",\"temporal_capture_truncated\":"
        << (outcome.temporal_capture_truncated ? "true" : "false")
        << ",\"environment_model_failure\":"
        << (outcome.environment_model_failure ? "true" : "false")
        << ",\"summarized_calls\":" << outcome.summarized_calls
        << ",\"model_contract\":\"explicit caller-selected name/address bindings; ABI models, not callee implementation proofs\""
        << ",\"ownerless_executed_heads\":" << ownerless.size()
        << ",\"foreign_executed_heads\":" << foreign.size()
        << ",\"function_evidence_published\":false,\"vm_identity_proved\":false"
        << ",\"environment_contract\":\"backend-defined timestamp, randomness, processor and device state; explicit arguments do not establish replay determinism\""
        << ",\"backend_compatibility\":\"32-bit legacy INC/DEC materializes current EFLAGS before backend execution to preserve pending carry\""
        << ",\"contract\":"
        << inspection_json_quote(
               runtime_shadow
                   ? "ephemeral synthetic entry over caller-supplied executable shadow bytes; external runtime provenance is not verified by this API; no function evidence or VM identity"
               : candidate_entry
                   ? "ephemeral synthetic entry at an explicitly selected executable data head; exact fetched instruction bytes; neither observed program reachability nor runtime unpacked contents; no function evidence or VM identity"
                   : "ephemeral seeded native execution; exact fetched instruction bytes; separate from function evidence; logical VM state unknown");
    if (candidate_entry)
        out << ",\"candidate_decode\":true,\"synthetic_entry\":true";
    if (runtime_shadow)
        out << ",\"runtime_shadow\":true,\"shadow_start\":" << inspection_json_quote(hex(function))
            << ",\"shadow_bytes\":" << runtime_shadow->size()
            << ",\"shadow_changed_bytes\":" << shadow_changed << ",\"shadow_fingerprint\":"
            << inspection_json_quote(hex(runtime_shadow_fingerprint(*runtime_shadow)))
            << ",\"shadow_instruction_states\":" << (sample_states ? "true" : "false");
    inspection_json_rows(out, "heads", heads);
    inspection_json_rows(out, "frontiers", frontiers);
    inspection_json_rows(out, "execution", execution);
    inspection_json_rows(out, "edges", edges);
    inspection_json_rows(out, "states", states);
    inspection_json_rows(out, "data", data);
    inspection_json_rows(out, "final_writes", writes);
    inspection_json_rows(out, "input_arguments", arguments);
    inspection_json_rows(out, "input_objects", objects);
    inspection_json_rows(out, "final_registers", final_registers);
    inspection_json_rows(out, "native_admissions", admissions);
    inspection_json_rows(out, "environment_bindings", models);
    inspection_json_rows(out, "allocations", allocations);
    inspection_json_rows(out, "uses", uses);
    if (check)
    {
        out << ",\"native_observations\":{\"available\":"
            << (observations.available ? "true" : "false")
            << ",\"reason\":" << inspection_json_quote(observations.reason)
            << ",\"path_steps\":" << observations.path_steps
            << ",\"path_limited\":" << (observations.path_limited ? "true" : "false")
            << ",\"starts_examined\":" << observations.starts_examined
            << ",\"candidate_visits\":" << observations.candidate_visits
            << ",\"unsupported_path_stops\":" << observations.unsupported_path_stops
            << ",\"recognizer_rejections\":" << observations.recognizer_rejections
            << ",\"path_length_stops\":" << observations.path_length_stops
            << ",\"capture_end_stops\":" << observations.capture_end_stops
            << ",\"omitted\":" << observations.omitted
            << ",\"transition_attempts\":" << observations.transition_attempts
            << ",\"queries\":" << observations.queries;
        inspection_json_rows(out, "records", observations.records);
        out << '}';
    }
    out << '}';
    if (retained)
    {
        retained->capture = capture;
        retained->context = function;
        retained->image_hash = region.image_hash();
        retained->generation = region.generation();
        retained->run_id = input.run_id;
        retained->seed = input.seed;
        retained->ran = ran;
        retained->outcome = std::move(outcome);
        retained->events = std::move(events);
        if (bindings)
            retained->bindings = *bindings;
    }
    if (retained_image)
        *retained_image = std::move(image);
    return out.str();
}
std::string trace_native_region(uint64_t function, uint64_t seed)
{
    return trace_native_region_impl(function, seed, nullptr);
}
std::string trace_native_candidate_region(uint64_t root, uint64_t seed)
{
    return trace_native_region_impl(root, seed, nullptr, false, false, nullptr, nullptr, nullptr,
                                    true);
}
std::string trace_native_candidate_region_input(uint64_t root, uint64_t seed,
                                                const std::string &request)
{
    hybrid::EmuInput input;
    if (!parse_input(request, input))
        return unavailable("invalid bounded native input", true);
    return trace_native_region_impl(root, seed, &input, false, false, nullptr, nullptr, nullptr,
                                    true);
}
std::string trace_native_candidate_shadow(uint64_t root, uint64_t seed, const std::string &path)
{
    std::vector<uint8_t> shadow;
    if (!read_runtime_shadow(path, shadow))
        return unavailable("invalid bounded runtime shadow file", true);
    return trace_native_region_impl(root, seed, nullptr, false, false, nullptr, nullptr, nullptr,
                                    true, &shadow);
}
std::string trace_native_candidate_shadow_states(uint64_t root, uint64_t seed,
                                                 const std::string &path)
{
    std::vector<uint8_t> shadow;
    if (!read_runtime_shadow(path, shadow))
        return unavailable("invalid bounded runtime shadow file", true);
    return trace_native_region_impl(root, seed, nullptr, false, false, nullptr, nullptr, nullptr,
                                    true, &shadow, true);
}
std::string trace_native_region_input(uint64_t function, uint64_t seed, const std::string &request)
{
    hybrid::EmuInput input;
    if (!parse_input(request, input))
        return unavailable("invalid bounded native input");
    return trace_native_region_impl(function, seed, &input);
}
std::string trace_native_region_walk(uint64_t function, uint64_t seed, const std::string &request)
{
    hybrid::EmuInput input;
    if (!parse_input(request, input))
        return unavailable("invalid bounded native input");
    return trace_native_region_impl(function, seed, &input, true);
}
std::string trace_native_region_check(uint64_t function, uint64_t seed, const std::string &request)
{
    hybrid::EmuInput input;
    if (!parse_input(request, input))
        return unavailable("invalid bounded native input");
    return trace_native_region_impl(function, seed, &input, true, true);
}
std::string trace_native_region_temporal(uint64_t function, uint64_t seed,
                                         const std::string &request, const std::string &models)
{
    hybrid::EmuInput input;
    std::vector<hybrid::EmuCallSummary> bindings;
    if (!parse_input(request, input) || !input.native_objects.empty())
        return unavailable("invalid bounded temporal input");
    if (!parse_bindings(models, bindings))
        return unavailable("invalid named environment bindings");
    return trace_native_region_impl(function, seed, &input, true, false, &bindings);
}

void clear_native_temporal_strings() { string_lease.reset(); }

std::string native_temporal_string_state(uint64_t ticket, const std::string &identity)
{
    using namespace hybrid;
    if (!string_lease || !ticket || ticket != string_lease->ticket || identity.size() != 64 ||
        identity != string_lease->identity || string_lease->database != int64_t(get_dbctx_id()) ||
        string_lease->filetype != inf_get_filetype())
        return "{\"available\":false,\"fresh\":false}";
    HybridConfig config;
    config.max_image_bytes = 64ull * 1024 * 1024;
    ProgramImage current;
    std::vector<EmuCallSummary> bindings;
    const bool fresh = parse_bindings(string_lease->bindings, bindings) &&
                       hybrid_snapshot_function(current, config, string_lease->context).complete &&
                       same_image(string_lease->image, current);
    return std::string("{\"available\":true,\"fresh\":") + (fresh ? "true" : "false") +
           ",\"ticket\":" + std::to_string(ticket) +
           ",\"lease\":" + inspection_json_quote(string_lease->identity) +
           ",\"database\":" + inspection_json_quote(std::to_string(string_lease->database)) + "}";
}

static std::string inspect_native_temporal_strings_impl(uint64_t function,
                                                        const std::string &request,
                                                        const std::string &models, bool prefix)
{
    using namespace hybrid;
    clear_native_temporal_strings();
    EmuInput input;
    std::vector<EmuCallSummary> bindings;
    if (!parse_input(request, input) || !input.native_objects.empty())
        return unavailable("invalid bounded temporal input");
    if (!parse_bindings(models, bindings))
        return unavailable("invalid named environment bindings");
    std::vector<NativeTemporalStringRun> runs;
    // Counters and database context IDs can repeat after restarting IDA.
    std::vector<uint8_t> identity(32);
    if (!gen_rand_buf(identity.data(), identity.size()) ||
        std::all_of(identity.begin(), identity.end(), [](uint8_t value) { return value == 0; }))
        return unavailable("capture identity unavailable");
    ProgramImage reference;
    for (uint64_t seed : {UINT64_C(0), UINT64_C(1), UINT64_C(17), UINT64_C(0xc0ffee)})
    {
        NativeTemporalStringRun run;
        ProgramImage current;
        trace_native_region_impl(function, seed, &input, true, false, &bindings, &run, &current);
        if (!run.capture)
            return unavailable("native capture unavailable");
        if (runs.empty())
            reference = std::move(current);
        else if (!same_image(reference, current))
            return unavailable("capture inputs changed between runs");
        runs.push_back(std::move(run));
    }
    std::vector<EmuCallSummary> final_bindings;
    if (!parse_bindings(models, final_bindings))
        return unavailable("model bindings changed during capture");
    const auto projection =
        prefix ? hybrid_native_temporal_prefix_strings(runs) : hybrid_native_temporal_strings(runs);
    auto lease = std::make_unique<StringLease>();
    lease->identity = bytes(identity);
    lease->ticket = runs.back().capture;
    lease->context = function;
    lease->database = int64_t(get_dbctx_id());
    lease->filetype = inf_get_filetype();
    lease->bindings = models;
    lease->image = std::move(reference);
    using Row = std::map<std::string, std::string>;
    std::vector<Row> observations, witnesses, fragments, stops, contracts, arguments;
    for (size_t index = 0; index < input.args.size(); ++index)
        arguments.push_back({{"index", std::to_string(index)}, {"value", hex(input.args[index])}});
    for (const auto &binding : bindings)
        contracts.push_back({{"address", hex(binding.address)},
                             {"name", binding.name},
                             {"kind", std::to_string(unsigned(binding.kind))}});
    for (const auto &run : runs)
        stops.push_back(
            {{"capture", std::to_string(run.capture)},
             {"run", std::to_string(run.run_id)},
             {"seed", hex(run.seed)},
             {"complete", run.outcome.native_temporal_complete ? "true" : "false"},
             {"prefix_complete", run.outcome.native_temporal_prefix_complete ? "true" : "false"},
             {"prefix_end_sequence", std::to_string(run.outcome.native_temporal_prefix_end)},
             {"backend_stop", hybrid_rax_stop_reason_name(run.outcome.stop_reason)},
             {"boundary_source", hex(run.outcome.region_boundary_source)},
             {"boundary_target", hex(run.outcome.region_boundary_target)},
             {"stop", hybrid_emu_outcome_name(run.outcome)},
             {"site", hex(run.outcome.stop_pc)},
             {"instructions", std::to_string(run.outcome.instruction_count)}});
    const size_t count = std::min<size_t>(64, projection.observations.size());
    for (size_t index = 0; index < count; ++index)
    {
        const auto &value = projection.observations[index];
        observations.push_back({{"index", std::to_string(index)},
                                {"value", value.value},
                                {"site", hex(value.use.site)},
                                {"context", hex(value.use.context)},
                                {"producer", use_producer_name(value.use.producer)},
                                {"eligible_runs", std::to_string(value.eligible_runs)},
                                {"truth", "named-model observation"}});
        for (size_t r = 0; r < value.witnesses.size(); ++r)
        {
            const auto &use = value.witnesses[r];
            const bool modeled = use.producer == UseProducer::MODELED_ARGUMENT;
            const std::vector<UseSnapshot> argument =
                modeled ? std::vector<UseSnapshot>{use} : std::vector<UseSnapshot>{};
            const auto &parts = modeled ? argument : value.read_fragments.at(r);
            const auto capture = projection.captures.at({use.run_id, use.seed});
            witnesses.push_back(
                {{"observation", std::to_string(index)},
                 {"capture", std::to_string(capture)},
                 {"run", std::to_string(use.run_id)},
                 {"seed", hex(use.seed)},
                 {"site", hex(use.site)},
                 {"address", hex(use.address)},
                 {"allocation", hex(use.allocation_id)},
                 {"generation", hex(use.generation)},
                 {"object_site", hex(use.object_site)},
                 {"object_callee", hex(use.object_callee)},
                 {"object_occurrence", std::to_string(use.object_occurrence)},
                 {"object_size", std::to_string(use.object_size)},
                 {"offset", std::to_string(use.offset)},
                 {"producer", use_producer_name(use.producer)},
                 {"callee", hex(use.callee)},
                 {"argument", std::to_string(use.argument)},
                 {"model_kind", std::to_string(use.model_kind)},
                 {"first_sequence", std::to_string(parts.front().sequence)},
                 {"last_sequence", std::to_string(parts.back().sequence)},
                 {"read_count", std::to_string(modeled ? 0 : parts.size())},
                 {"snapshot_count", std::to_string(parts.size())},
                 {"observed_bytes", std::to_string(use.observed_size)},
                 {"fragments_omitted", std::to_string(parts.size() > 16 ? parts.size() - 16 : 0)}});
            for (size_t p = 0; p < std::min<size_t>(16, parts.size()); ++p)
            {
                const auto &part = parts[p];
                fragments.push_back(
                    {{"observation", std::to_string(index)},
                     {"capture", std::to_string(capture)},
                     {"site", hex(part.site)},
                     {"address", hex(part.address)},
                     {"sequence", std::to_string(part.sequence)},
                     {"producer", use_producer_name(part.producer)},
                     {"data_sequence", modeled ? "" : std::to_string(part.sequence + 1)},
                     {"bytes", bytes(part.bytes)}});
            }
        }
    }
    std::ostringstream out;
    out << "{\"schema\":1,\"available\":true,\"scope\":"
        << inspection_json_quote(prefix ? "native-region-prefix-strings" : "native-region-strings")
        << ",\"ticket\":" << lease->ticket
        << ",\"lease\":" << inspection_json_quote(lease->identity)
        << ",\"database\":" << inspection_json_quote(std::to_string(lease->database))
        << ",\"function\":" << inspection_json_quote(hex(function))
        << ",\"consensus_available\":" << (projection.available ? "true" : "false")
        << ",\"reason\":" << inspection_json_quote(projection.reason)
        << ",\"observations_omitted\":" << (projection.observations.size() - count)
        << ",\"function_evidence_published\":false,\"vm_identity_proved\":false"
        << ",\"contract\":"
        << inspection_json_quote(
               prefix
                   ? "four seeded runs under explicit named ABI models; only complete event prefixes compared; execution return reported separately; no unique-input or callee-equivalence proof"
                   : "four seeded runs under explicit named ABI models; immutable byte snapshots; no unique-input or callee-equivalence proof");
    inspection_json_rows(out, "observations", observations);
    inspection_json_rows(out, "witnesses", witnesses);
    inspection_json_rows(out, "fragments", fragments);
    inspection_json_rows(out, "runs", stops);
    inspection_json_rows(out, "bindings", contracts);
    inspection_json_rows(out, "input_arguments", arguments);
    out << '}';
    string_lease = std::move(lease);
    return out.str();
}
std::string inspect_native_temporal_strings(uint64_t function, const std::string &request,
                                            const std::string &models)
{
    return inspect_native_temporal_strings_impl(function, request, models, false);
}
std::string inspect_native_temporal_prefix_strings(uint64_t function, const std::string &request,
                                                   const std::string &models)
{
    return inspect_native_temporal_strings_impl(function, request, models, true);
}
} // namespace chernobog::vm
