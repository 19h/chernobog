#include "model.hpp"
#include "key_domain.hpp"
#include "byte_memory.hpp"
#include "pool_model.hpp"
#include <rax.h>
#include <z3++.h>
#include <algorithm>
#include <deque>
#include <map>
#include <set>
#include <stdexcept>

namespace chernobog::warbird
{
namespace
{
constexpr uint64_t context_base = 0x10000000000ULL;
// Win64 function entry follows a pushed 8-byte return address. Call-site
// alignment is 16 bytes; the callee entry RSP is therefore 8 modulo 16.
constexpr uint64_t native_stack = 0x20000010008ULL;
constexpr uint64_t virtual_stack = 0x30000010000ULL;
constexpr uint64_t return_sentinel = 0xfffffffffffff00dULL;
std::atomic_flag running = ATOMIC_FLAG_INIT;
z3::expr resize(const z3::expr &v, unsigned bits, bool sign = false)
{
    unsigned n = v.get_sort().bv_size();
    return n == bits  ? v
           : n > bits ? v.extract(bits - 1, 0)
           : sign     ? z3::sext(v, bits - n)
                      : z3::zext(v, bits - n);
}
bool number(const z3::expr &v, uint64_t &n)
{
    z3::params p(v.ctx());
    p.set("max_steps", 10000u);
    return v.simplify(p).is_numeral_u64(n);
}
struct State
{
    uint64_t key = 0, pc = 0;
    bool table_unchanged = true;
    bool imports_unchanged = true;
    std::vector<z3::expr> registers;
    std::vector<z3::expr> temporary;
    std::vector<z3::expr> vectors;
    std::map<unsigned, z3::expr> vector_temporary;
    std::vector<z3::expr> flags;
    ByteMemory memory;
    PoolState pool;
    z3::expr domain;
    std::vector<uint64_t> calls;
    explicit State(z3::context &c) : memory(c), domain(c.bool_val(true))
    {
        for (unsigned i = 0; i < 36; ++i)
            registers.push_back(c.bv_const(("r" + std::to_string(i)).c_str(), 64));
        for (unsigned i = 0; i < 7; ++i)
            flags.push_back(c.bool_const(("f" + std::to_string(i)).c_str()));
        for (unsigned i = 0; i < 16; ++i)
            vectors.push_back(c.bv_const(("xmm" + std::to_string(i)).c_str(), 128));
    }
};
class Explorer
{
    const hybrid::ProgramImage &image;
    const Admission &admission;
    const Limits &limits;
    const std::atomic_bool &cancel;
    const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    z3::context ctx;
    Report report;
    z3::params simplify_params{ctx};
    std::map<uint64_t, std::pair<rax_smir_instruction, std::vector<rax_smir_op>>> cache;
    std::set<std::vector<unsigned>> seen;
    std::set<uint64_t> keys;
    size_t symbolic_serial = 0;
    size_t identity_bytes = 0;
    z3::expr bv(uint64_t v, unsigned w = 64) { return ctx.bv_val(v, w); }
    z3::expr fresh(unsigned bits = 64)
    {
        return ctx.bv_const(("u" + std::to_string(symbolic_serial++)).c_str(), bits);
    }
    void frontier(const State &s, const std::string &why)
    {
        report.frontiers.push_back({s.key, s.pc, why});
    }
    bool exhausted() const
    {
        return cancel.load() || report.states >= limits.states ||
               report.instructions >= limits.instructions ||
               report.operations >= limits.operations ||
               std::chrono::steady_clock::now() - start >= limits.time;
    }
    z3::expr get(const State &s, const rax_smir_operand &o)
    {
        if (o.kind == 3)
            return bv(o.value);
        if (o.kind == 2 && o.id < s.registers.size())
            return s.registers[o.id];
        if (o.kind == 1 && o.id < s.temporary.size())
            return s.temporary[o.id];
        if (o.kind == 0)
            return bv(0); // absent address component only; validated operands elsewhere
        throw std::runtime_error("invalid SMIR operand");
    }
    void put(State &s, const rax_smir_operand &o, z3::expr v, unsigned width = 64)
    {
        v = resize(v, width);
        if (o.kind == 2 && o.id < s.registers.size())
        {
            if (width < 32)
                v = z3::concat(s.registers[o.id].extract(63, width), v);
            s.registers[o.id] = resize(v, 64).simplify(simplify_params);
        }
        else if (o.kind == 1 && o.id < s.temporary.size())
            s.temporary[o.id] = resize(v, 64).simplify(simplify_params);
        else
            throw std::runtime_error("invalid SMIR destination");
    }
    z3::expr address(State &s, const rax_smir_address &a)
    {
        if ((a.address_bits != 32 && a.address_bits != 64) ||
            (a.scale != 1 && a.scale != 2 && a.scale != 4 && a.scale != 8))
            throw std::runtime_error("invalid SMIR address");
        auto v = get(s, a.base) + get(s, a.index) * bv(a.scale) + bv(a.displacement);
        return (resize(resize(v, a.address_bits), 64) + get(s, a.segment))
            .simplify(simplify_params);
    }
    z3::expr load(State &s, z3::expr at, unsigned width)
    {
        uint64_t n = 0;
        if (number(at, n) && image.readable(n) && !image.writable(n))
        {
            const auto view = image.loaded_view(n, width / 8);
            if (view.size != width / 8)
                throw std::runtime_error("unloaded immutable read");
            const auto *seg = image.segment_at(n);
            report.dependencies.push_back({n, seg->perm, {view.data, view.data + view.size}});
            auto value = bv(view.data[width / 8 - 1], 8);
            for (unsigned i = width / 8 - 1; i > 0; --i)
                value = z3::concat(value, bv(view.data[i - 1], 8));
            return value;
        }
        return s.memory.read(at, width);
    }
    void store(State &s, z3::expr at, z3::expr value, unsigned width)
    {
        uint64_t n = 0;
        const bool concrete = number(at, n);
        const uint64_t table_start = admission.image_base + admission.profile->table_rva;
        const uint64_t table_end = table_start + admission.profile->table_count * 8;
        if (!concrete && !admission.imports.empty())
            s.imports_unchanged = false;
        if (!concrete && image.writable(table_start))
            s.table_unchanged = false;
        if (concrete)
            for (unsigned byte = 0; byte < width / 8; ++byte)
            {
                const uint64_t address = n + byte;
                if (image.contains(address) && !image.writable(address))
                    throw std::runtime_error("write to immutable image");
                if (image.writable(table_start) && address >= table_start && address < table_end)
                    s.table_unchanged = false;
                for (const auto &binding : admission.imports)
                    if (address >= binding.slot && address - binding.slot < 8)
                        s.imports_unchanged = false;
            }
        value = resize(value, width);
        s.memory.write(at, value, width);
        // Bound expression work independently from instruction count.
        if (report.operations > limits.bytes / 1024)
            throw std::runtime_error("symbolic workspace quota");
    }
    z3::expr condition(const State &s, unsigned c)
    {
        const auto &cf = s.flags[0], &zf = s.flags[1], &sf = s.flags[2], &of = s.flags[3],
                   &pf = s.flags[4];
        switch (c)
        {
        case 0:
            return zf;
        case 1:
            return !zf;
        case 2:
            return cf;
        case 3:
            return cf || zf;
        case 4:
            return !cf && !zf;
        case 5:
            return !cf;
        case 6:
            return sf != of;
        case 7:
            return zf || (sf != of);
        case 8:
            return !zf && (sf == of);
        case 9:
            return sf == of;
        case 10:
            return sf;
        case 11:
            return !sf;
        case 12:
            return of;
        case 13:
            return !of;
        case 14:
            return pf;
        case 15:
            return !pf;
        case 16:
            return ctx.bool_val(true);
        default:
            throw std::runtime_error("invalid SMIR condition");
        }
    }
    void arithmetic(State &s, const rax_smir_op &o, const z3::expr &a, const z3::expr &b,
                    const z3::expr &r, bool sub, bool logic, bool preserve = false)
    {
        if (!o.flags_mask)
            return;
        unsigned w = r.get_sort().bv_size();
        auto bit = [&](const z3::expr &v, unsigned i) { return v.extract(i, i) == bv(1, 1); };
        auto parity = bit(r, 0);
        for (unsigned i = 1; i < 8; ++i)
            parity = parity != bit(r, i);
        if (!preserve)
            s.flags[0] = logic ? ctx.bool_val(false) : sub ? z3::ult(a, b) : z3::ult(r, a);
        s.flags[1] = r == bv(0, w);
        s.flags[2] = bit(r, w - 1);
        s.flags[3] = logic ? ctx.bool_val(false) : bit((sub ? (a ^ b) : ~(a ^ b)) & (a ^ r), w - 1);
        s.flags[4] = !parity;
        s.flags[5] = logic ? (fresh(1) == bv(1, 1)) : bit(a ^ b ^ r, 4);
        for (auto &f : s.flags)
            f = f.simplify(simplify_params);
    }
    z3::expr get_vector(const State &s, const rax_smir_operand &operand)
    {
        if (operand.kind == RAX_SMIR_OPERAND_XMM && operand.id < s.vectors.size())
            return s.vectors[operand.id];
        if (operand.kind == 1)
        {
            const auto found = s.vector_temporary.find(operand.id);
            if (found != s.vector_temporary.end())
                return found->second;
        }
        throw std::runtime_error("invalid or undefined vector SMIR operand");
    }
    void put_vector(State &s, const rax_smir_operand &operand, z3::expr value)
    {
        if (value.get_sort().bv_size() != 128)
            throw std::runtime_error("invalid vector SMIR width");
        value = value.simplify(simplify_params);
        if (operand.kind == RAX_SMIR_OPERAND_XMM && operand.id < s.vectors.size())
            s.vectors[operand.id] = value;
        else if (operand.kind == 1 && operand.id < s.temporary.size())
            s.vector_temporary.insert_or_assign(operand.id, value);
        else
            throw std::runtime_error("invalid vector SMIR destination");
    }
    bool vector_operation(State &s, const rax_smir_op &o)
    {
        if (o.opcode < RAX_SMIR_VMOV || o.opcode > RAX_SMIR_VBROADCAST)
            return false;
        if (o.flags_mask != 0)
            throw std::runtime_error("invalid vector flag update");
        if (o.opcode == RAX_SMIR_CHECK_ALIGNMENT)
        {
            if (o.width_bits != 64 || o.source_width_bits || o.condition || !o.auxiliary ||
                o.auxiliary > 128 || (o.auxiliary & (o.auxiliary - 1)))
                throw std::runtime_error("invalid alignment check");
            auto aligned =
                ((address(s, o.address) & bv(o.auxiliary - 1)) == bv(0)).simplify(simplify_params);
            if (!aligned.is_true())
            {
                if (aligned.is_false() || !feasible(s.domain && aligned))
                    throw std::runtime_error("misaligned vector memory address");
                if (feasible(s.domain && !aligned))
                    frontier(s, "possible misaligned vector memory address");
                s.domain = (s.domain && aligned).simplify(simplify_params);
            }
            ++report.vector_operations;
            return true;
        }
        if (o.opcode == RAX_SMIR_X86_MOVDQ)
        {
            if ((o.width_bits != 32 && o.width_bits != 64) || o.auxiliary || o.source_width_bits ||
                o.condition)
                throw std::runtime_error("invalid MOVD/MOVQ width");
            if (o.dst.kind == RAX_SMIR_OPERAND_XMM && o.a.kind != RAX_SMIR_OPERAND_XMM)
                put_vector(s, o.dst, resize(resize(get(s, o.a), o.width_bits), 128));
            else if (o.dst.kind != RAX_SMIR_OPERAND_XMM && o.a.kind == RAX_SMIR_OPERAND_XMM)
                put(s, o.dst, resize(get_vector(s, o.a), o.width_bits), o.width_bits);
            else
                throw std::runtime_error("invalid MOVD/MOVQ operands");
            ++report.vector_operations;
            return true;
        }
        if (o.opcode == RAX_SMIR_VEXTRACT)
        {
            const auto bits = o.source_width_bits;
            if ((bits != 8 && bits != 16 && bits != 32 && bits != 64) ||
                o.auxiliary >= 128 / bits || o.width_bits != 64 || o.condition > 1)
                throw std::runtime_error("invalid vector extract");
            auto value =
                get_vector(s, o.a).extract((o.auxiliary + 1) * bits - 1, o.auxiliary * bits);
            put(s, o.dst, resize(value, 64, o.condition == 1));
            ++report.vector_operations;
            return true;
        }
        if (o.width_bits != 128)
            throw std::runtime_error("invalid vector SMIR width");
        if ((o.opcode == RAX_SMIR_VINSERT || o.opcode == RAX_SMIR_VBROADCAST) && o.condition)
            throw std::runtime_error("invalid vector SMIR condition");
        if (o.opcode != RAX_SMIR_VINSERT && o.opcode != RAX_SMIR_VBROADCAST &&
            (o.auxiliary || o.source_width_bits || o.condition))
            throw std::runtime_error("invalid vector SMIR attributes");
        switch (o.opcode)
        {
        case RAX_SMIR_VMOV:
            put_vector(s, o.dst, get_vector(s, o.a));
            break;
        case RAX_SMIR_VLOAD:
            put_vector(s, o.dst, load(s, address(s, o.address), 128));
            break;
        case RAX_SMIR_VSTORE:
            store(s, address(s, o.address), get_vector(s, o.a), 128);
            break;
        case RAX_SMIR_VXOR:
            put_vector(s, o.dst, get_vector(s, o.a) ^ get_vector(s, o.b));
            break;
        case RAX_SMIR_VINSERT:
        {
            const auto bits = o.source_width_bits, low = o.auxiliary * bits;
            if ((bits != 8 && bits != 16 && bits != 32 && bits != 64) || o.auxiliary >= 128 / bits)
                throw std::runtime_error("invalid vector insert");
            const auto previous = get_vector(s, o.a);
            auto value = resize(get(s, o.b), bits);
            if (low)
                value = z3::concat(value, previous.extract(low - 1, 0));
            if (low + bits < 128)
                value = z3::concat(previous.extract(127, low + bits), value);
            put_vector(s, o.dst, value);
            break;
        }
        case RAX_SMIR_VBROADCAST:
        {
            const auto bits = o.source_width_bits;
            if ((bits != 8 && bits != 16 && bits != 32 && bits != 64) || o.auxiliary > 128 / bits)
                throw std::runtime_error("invalid vector broadcast");
            const auto scalar = resize(resize(get(s, o.a), bits), 128);
            auto value = bv(0, 128);
            for (unsigned lane = 0; lane < o.auxiliary; ++lane)
                value = value | z3::shl(scalar, bv(lane * bits, 128));
            put_vector(s, o.dst, value);
            break;
        }
        default:
            throw std::runtime_error("unsupported vector SMIR operation");
        }
        ++report.vector_operations;
        return true;
    }
    void operation(State &s, const rax_smir_op &o)
    {
        if (o.struct_size != sizeof(o) || o.abi_version != RAX_SMIR_ABI_VERSION)
            throw std::runtime_error("invalid SMIR record");
        if (vector_operation(s, o))
            return;
        if ((o.width_bits != 8 && o.width_bits != 16 && o.width_bits != 32 && o.width_bits != 64))
            throw std::runtime_error("invalid SMIR record");
        unsigned w = o.width_bits;
        auto a = resize(get(s, o.a), w), b = resize(get(s, o.b), w), r = bv(0, w);
        bool write = true;
        const auto old_flags = s.flags;
        switch (o.opcode)
        {
        case RAX_SMIR_MOV:
            r = a;
            break;
        case RAX_SMIR_ADD:
            r = a + b;
            arithmetic(s, o, a, b, r, false, false);
            break;
        case RAX_SMIR_SUB:
            r = a - b;
            arithmetic(s, o, a, b, r, true, false);
            break;
        case RAX_SMIR_ADC:
        case RAX_SMIR_SBB:
        {
            const auto carry = z3::ite(old_flags[0], bv(1, w), bv(0, w));
            const bool subtract = o.opcode == RAX_SMIR_SBB;
            r = subtract ? a - b - carry : a + b + carry;
            arithmetic(s, o, a, b, r, subtract, false);
            if (o.flags_mask)
            {
                const auto wide_a = resize(a, w + 1);
                const auto wide_b = resize(b, w + 1) + resize(carry, w + 1);
                s.flags[0] = subtract ? z3::ult(wide_a, wide_b)
                                      : (wide_a + wide_b).extract(w, w) == bv(1, 1);
            }
            break;
        }
        case RAX_SMIR_CMP:
            write = false;
            r = a - b;
            arithmetic(s, o, a, b, r, true, false);
            break;
        case RAX_SMIR_AND:
            r = a & b;
            arithmetic(s, o, a, b, r, false, true);
            break;
        case RAX_SMIR_OR:
            r = a | b;
            arithmetic(s, o, a, b, r, false, true);
            break;
        case RAX_SMIR_XOR:
            r = a ^ b;
            arithmetic(s, o, a, b, r, false, true);
            break;
        case RAX_SMIR_TEST:
            write = false;
            r = a & b;
            arithmetic(s, o, a, b, r, false, true);
            break;
        case RAX_SMIR_NOT:
            r = ~a;
            break;
        case RAX_SMIR_NEG:
            r = -a;
            arithmetic(s, o, bv(0, w), a, r, true, false);
            break;
        case RAX_SMIR_INC:
            r = a + bv(1, w);
            arithmetic(s, o, a, bv(1, w), r, false, false, true);
            break;
        case RAX_SMIR_DEC:
            r = a - bv(1, w);
            arithmetic(s, o, a, bv(1, w), r, true, false, true);
            break;
        case RAX_SMIR_BT:
        case RAX_SMIR_BTS:
        case RAX_SMIR_BTR:
        case RAX_SMIR_BTC:
        {
            const auto bit = z3::shl(bv(1, w), b & bv(w - 1, w));
            s.flags[0] = (a & bit) != bv(0, w);
            if (o.opcode == RAX_SMIR_BT)
                write = false;
            else if (o.opcode == RAX_SMIR_BTS)
                r = a | bit;
            else if (o.opcode == RAX_SMIR_BTR)
                r = a & ~bit;
            else
                r = a ^ bit;
            break;
        }
        case RAX_SMIR_MUL_U:
        case RAX_SMIR_MUL_S:
        {
            auto p = resize(a, w * 2, o.opcode == RAX_SMIR_MUL_S) *
                     resize(b, w * 2, o.opcode == RAX_SMIR_MUL_S);
            r = p.extract(w - 1, 0);
            if (w == 8)
            {
                // x86 byte MUL/IMUL writes the complete product to AX.
                put(s, o.dst, p, 16);
                write = false;
            }
            else if (o.dst2.kind)
                put(s, o.dst2, p.extract(w * 2 - 1, w), w);
            if (o.flags_mask)
            {
                s.flags[0] = p != resize(r, w * 2, o.opcode == RAX_SMIR_MUL_S);
                s.flags[3] = s.flags[0];
                for (unsigned f : {1u, 2u, 4u, 5u})
                    s.flags[f] = fresh(1) == bv(1, 1);
            }
            break;
        }
        case RAX_SMIR_ZERO_EXTEND:
        case RAX_SMIR_SIGN_EXTEND:
        case RAX_SMIR_TRUNCATE:
        {
            auto source = get(s, o.a);
            if (o.auxiliary & 0x100)
                source = z3::lshr(source, bv(8));
            if (!o.source_width_bits || o.source_width_bits > 64)
                throw std::runtime_error("invalid extension width");
            r = resize(resize(source, o.source_width_bits), w, o.opcode == RAX_SMIR_SIGN_EXTEND);
            break;
        }
        case RAX_SMIR_LEA:
            r = address(s, o.address);
            break;
        case RAX_SMIR_LOAD:
            r = load(s, address(s, o.address), w);
            if (o.auxiliary & 1)
            {
                put(s, o.dst, resize(r, 64, true));
                write = false;
            }
            break;
        case RAX_SMIR_STORE:
            store(s, address(s, o.address), a, w);
            write = false;
            break;
        case RAX_SMIR_SELECT:
            r = z3::ite(get(s, o.a) != bv(0), resize(get(s, o.b), w), resize(get(s, o.c), w));
            break;
        case RAX_SMIR_CMOVE:
            r = z3::ite(condition(s, o.condition), a, resize(get(s, o.dst), w));
            break;
        case RAX_SMIR_SET_CC:
            r = z3::ite(condition(s, o.condition), bv(1, w), bv(0, w));
            break;
        case RAX_SMIR_SHL:
        case RAX_SMIR_SHR:
        case RAX_SMIR_SAR:
        case RAX_SMIR_ROL:
        case RAX_SMIR_ROR:
        {
            auto count = resize(get(s, o.b), w) & bv(w == 64 ? 63 : 31, w);
            if (o.opcode == RAX_SMIR_SHL)
                r = z3::shl(a, count);
            else if (o.opcode == RAX_SMIR_SHR)
                r = z3::lshr(a, count);
            else if (o.opcode == RAX_SMIR_SAR)
                r = z3::ashr(a, count);
            else
            {
                auto n = z3::urem(count, bv(w, w));
                r = o.opcode == RAX_SMIR_ROL ? (z3::shl(a, n) | z3::lshr(a, bv(w, w) - n))
                                             : (z3::lshr(a, n) | z3::shl(a, bv(w, w) - n));
            }
            if (o.flags_mask)
            {
                // Nonzero shifts leave AF and some OF/CF values undefined.
                // Retain symbols instead of selecting a convenient zero.
                auto old = s.flags;
                arithmetic(s, o, a, b, r, false, true);
                auto cf = o.opcode == RAX_SMIR_SHL
                              ? (z3::lshr(a, bv(w, w) - count) & bv(1, w)) != bv(0, w)
                              : (z3::lshr(a, count - bv(1, w)) & bv(1, w)) != bv(0, w);
                if (o.opcode == RAX_SMIR_ROL)
                    cf = (r & bv(1, w)) != bv(0, w);
                if (o.opcode == RAX_SMIR_ROR)
                    cf = r.extract(w - 1, w - 1) == bv(1, 1);
                s.flags[0] = z3::ite(count == bv(0, w), old[0], cf);
                auto of = fresh(1) == bv(1, 1);
                if (o.opcode == RAX_SMIR_SHL || o.opcode == RAX_SMIR_ROL)
                    of = (r.extract(w - 1, w - 1) == bv(1, 1)) != cf;
                if (o.opcode == RAX_SMIR_SHR)
                    of = a.extract(w - 1, w - 1) == bv(1, 1);
                if (o.opcode == RAX_SMIR_SAR)
                    of = ctx.bool_val(false);
                if (o.opcode == RAX_SMIR_ROR)
                    of = r.extract(w - 1, w - 1) != r.extract(w - 2, w - 2);
                s.flags[3] = z3::ite(count == bv(0, w), old[3],
                                     z3::ite(count == bv(1, w), of, fresh(1) == bv(1, 1)));
                for (unsigned f : {1u, 2u, 4u, 5u})
                    s.flags[f] = (o.opcode == RAX_SMIR_ROL || o.opcode == RAX_SMIR_ROR)
                                     ? old[f]
                                     : z3::ite(count == bv(0, w), old[f], s.flags[f]);
            }
            break;
        }
        case RAX_SMIR_RCL:
        case RAX_SMIR_RCR:
        {
            const auto input = z3::concat(a, z3::ite(old_flags[0], bv(1, 1), bv(0, 1)));
            const auto count =
                z3::urem(resize(get(s, o.b) & bv(w == 64 ? 63 : 31), w + 1), bv(w + 1, w + 1));
            const auto distance = bv(w + 1, w + 1) - count;
            const auto rotated = o.opcode == RAX_SMIR_RCL
                                     ? z3::shl(input, count) | z3::lshr(input, distance)
                                     : z3::lshr(input, count) | z3::shl(input, distance);
            r = rotated.extract(w, 1);
            if (o.flags_mask)
            {
                const auto carry = rotated.extract(0, 0) == bv(1, 1);
                const auto overflow = o.opcode == RAX_SMIR_RCL
                                          ? (r.extract(w - 1, w - 1) == bv(1, 1)) != carry
                                          : r.extract(w - 1, w - 1) != r.extract(w - 2, w - 2);
                s.flags[0] = z3::ite(count == bv(0, w + 1), old_flags[0], carry);
                s.flags[3] =
                    z3::ite(count == bv(0, w + 1), old_flags[3],
                            z3::ite(count == bv(1, w + 1), overflow, fresh(1) == bv(1, 1)));
            }
            break;
        }
        case RAX_SMIR_BSWAP:
            r = a.extract(7, 0);
            for (unsigned i = 1; i < w / 8; ++i)
                r = z3::concat(r, a.extract(i * 8 + 7, i * 8));
            break;
        case RAX_SMIR_SET_CF:
            s.flags[0] = ctx.bool_val(o.auxiliary != 0);
            write = false;
            break;
        case RAX_SMIR_SET_DF:
            s.flags[6] = ctx.bool_val(o.auxiliary != 0);
            write = false;
            break;
        case RAX_SMIR_CMC_CF:
            s.flags[0] = !s.flags[0];
            write = false;
            break;
        case RAX_SMIR_MATERIALIZE_FLAGS:
        case RAX_SMIR_NOP:
            write = false;
            break;
        default:
            throw std::runtime_error("symbolic semantics not implemented for SMIR opcode " +
                                     std::to_string(o.opcode));
        }
        if (o.flags_mask)
            for (unsigned bit = 0; bit < 6; ++bit)
                if ((o.flags_mask & (1u << bit)) == 0)
                    s.flags[bit] = old_flags[bit];
        if (write)
            put(s, o.dst, r, w);
    }
    bool feasible(const z3::expr &domain)
    {
        auto simple = domain.simplify(simplify_params);
        if (simple.is_true())
            return true;
        if (simple.is_false())
            return false;
        z3::solver solver(ctx);
        solver.set("timeout", 50u);
        solver.set("rlimit", 200000u);
        solver.add(simple);
        // Unknown is retained, never treated as proof of infeasibility.
        return solver.check() != z3::unsat;
    }
    void enter(State &s, uint64_t key)
    {
        if (!s.table_unchanged)
            throw std::runtime_error("mutable dispatch table may have been overwritten");
        ++report.states;
        s.key = key;
        s.pc = admission.handlers.at(key & (admission.handlers.size() - 1));
        // Caller-saved registers and incoming flags are not handler inputs
        // promised by the validated RCX/RDX contract. Never carry values from
        // the preceding handler through the native dispatch thunk.
        for (unsigned r : {0u, 8u, 9u, 10u, 11u})
            s.registers[r] = fresh();
        for (auto &flag : s.flags)
            flag = fresh(1) == bv(1, 1);
        for (unsigned reg = 0; reg < 6; ++reg)
            s.vectors[reg] = fresh(128);
        s.registers[0] = bv(s.pc);
        s.registers[1] = bv(context_base);
        s.registers[2] = bv(key);
        s.registers[4] = bv(native_stack);
        s.calls.clear();
        store(s, bv(native_stack), bv(return_sentinel), 64);
        keys.insert(key);
    }
    const std::pair<rax_smir_instruction, std::vector<rax_smir_op>> &decode(uint64_t pc)
    {
        auto found = cache.find(pc);
        if (found != cache.end())
            return found->second;
        if (!image.executable(pc) || image.writable(pc))
            throw std::runtime_error("native target not immutable executable code");
        const auto view = image.loaded_view(pc, 15);
        if (!view.size)
            throw std::runtime_error("unloaded native instruction");
        rax_smir_instruction info{};
        rax_smir_op ops[256]{};
        auto status = rax_smir_lift_x64(pc, view.data, view.size, &info, ops, 256);
        if (status != RAX_OK || info.flags != RAX_SMIR_COMPLETE ||
            info.struct_size != sizeof(info) || info.abi_version != RAX_SMIR_ABI_VERSION ||
            !info.bytes_consumed || info.bytes_consumed > view.size || info.op_count > 256 ||
            info.op_count != info.required_op_count)
            throw std::runtime_error("RAX complete SMIR lift unavailable");
        report.dependencies.push_back(
            {pc, image.segment_at(pc)->perm, {view.data, view.data + info.bytes_consumed}});
        return cache
            .emplace(pc, std::make_pair(info, std::vector<rax_smir_op>(ops, ops + info.op_count)))
            .first->second;
    }

    bool return_from_native(State &s, const z3::expr &native_return, std::deque<State> &work)
    {
        uint64_t returned = 0;
        const auto expected = s.calls.empty() ? return_sentinel : s.calls.back();
        if (!number(native_return, returned) || returned != expected)
        {
            // A symbolic write may overlap the saved return address.
            // Retain that nonlocal-return frontier, but do not discard
            // the separately guarded ordinary-return continuation.
            const auto normal = native_return == bv(expected);
            if (feasible((s.domain && !normal).simplify(simplify_params)))
                frontier(s, "possible nonlocal native return");
            s.domain = (s.domain && normal).simplify(simplify_params);
            if (!feasible(s.domain))
                return false;
            ++report.return_splits;
        }
        if (!s.calls.empty())
        {
            s.pc = s.calls.back();
            s.calls.pop_back();
            return true;
        }
        const auto key_expression = s.registers[0].simplify(simplify_params);
        const auto choices = resolve_key_domain(key_expression, s.domain);
        report.key_queries += choices.queries;
        if (choices.status == KeyDomainStatus::UNSATISFIABLE)
            return false;
        if (!choices.complete())
            throw std::runtime_error(choices.status == KeyDomainStatus::VALUE_LIMIT
                                         ? "next key set exceeds exhaustive value limit"
                                         : "next key domain solver did not prove completeness");
        if (choices.values.size() > 1)
            ++report.key_splits;
        for (const auto next : choices.values)
        {
            State successor = s;
            successor.domain = (s.domain && key_expression == bv(next)).simplify(simplify_params);
            if (!feasible(successor.domain))
                continue;
            report.edges.push_back(
                {s.key, next, s.pc,
                 successor.domain.is_true() ? "true" : "symbolic path condition (not serialized)"});
            if (next != 0)
            {
                enter(successor, next);
                work.push_back(std::move(successor));
            }
        }
        return false;
    }

    void external(State &s, const ImportBinding &binding, const rax_smir_instruction &instruction,
                  std::deque<State> &work)
    {
        if (binding.module != "ntoskrnl.exe" ||
            (binding.symbol != "ExAllocatePoolWithTag" && binding.symbol != "ExFreePoolWithTag"))
            throw std::runtime_error("external import: " + binding.module + "!" + binding.symbol);
        ++report.external_calls;
        // A declared import does not prove the runtime target, execution IRQL,
        // or kernel-global effects. Retain that boundary even while exploring
        // the separately modeled normal return relation.
        frontier(s, "pool runtime binding, IRQL and kernel effects unverified");
        const bool allocate = binding.symbol == "ExAllocatePoolWithTag";
        auto outcomes =
            allocate ? pool_allocate(s.pool, resize(resize(s.registers[1], 32), 64), s.registers[2],
                                     resize(resize(s.registers[8], 32), 64), fresh())
                     : pool_free(s.pool, s.registers[1], resize(resize(s.registers[2], 32), 64),
                                 fresh());
        const bool call = instruction.flow == 8;
        auto callee_sp = (s.registers[4] - bv(call ? 8 : 0)).simplify(simplify_params);
        if (call)
        {
            if (s.calls.size() >= limits.call_depth)
                throw std::runtime_error("native call depth quota");
            store(s, callee_sp, bv(instruction.fallthrough), 64);
            s.calls.push_back(instruction.fallthrough);
        }
        std::vector<std::pair<uint64_t, uint64_t>> excluded;
        for (const auto &segment : image.segs)
            excluded.emplace_back(segment.start, segment.end);
        for (uint64_t reserved : {context_base, native_stack, virtual_stack})
            excluded.emplace_back(reserved - 0x10000, reserved + 0x10000);
        for (auto &outcome : outcomes)
        {
            State next = s;
            next.domain = (s.domain && outcome.condition).simplify(simplify_params);
            if (!outcome.frontier.empty())
            {
                if (feasible(next.domain))
                    frontier(next, outcome.frontier);
                continue;
            }
            if (outcome.changed_region && allocate)
            {
                const auto &block = outcome.state.blocks[*outcome.changed_region];
                const auto end = block.address + block.bytes;
                for (const auto &[begin, limit] : excluded)
                    next.domain = next.domain &&
                                  (z3::ule(end, bv(begin)) || z3::uge(block.address, bv(limit)));
            }
            next.domain = next.domain.simplify(simplify_params);
            if (!feasible(next.domain))
                continue;
            if (outcome.changed_region)
            {
                const auto &block = outcome.state.blocks[*outcome.changed_region];
                const auto name = "pool_bytes_" + std::to_string(symbolic_serial++);
                const auto bytes =
                    ctx.constant(name.c_str(), ctx.array_sort(ctx.bv_sort(64), ctx.bv_sort(8)));
                next.memory.havoc(block.address, block.bytes, bytes, excluded);
            }
            next.pool = std::move(outcome.state);
            // The Win64 home area belongs to the callee. Preserve no values
            // there or in volatile integer registers/flags across this call.
            for (unsigned offset = 8; offset <= 32; offset += 8)
                store(next, callee_sp + bv(offset), fresh(), 64);
            for (unsigned reg : {0u, 1u, 2u, 8u, 9u, 10u, 11u})
                next.registers[reg] = fresh();
            for (auto &flag : next.flags)
                flag = fresh(1) == bv(1, 1);
            for (unsigned reg = 0; reg < 6; ++reg)
                next.vectors[reg] = fresh(128);
            next.registers[0] = outcome.result;
            const auto saved_return = load(next, callee_sp, 64);
            next.registers[4] = (callee_sp + bv(8)).simplify(simplify_params);
            if (return_from_native(next, saved_return, work))
                work.push_back(std::move(next));
        }
    }

  public:
    Explorer(const hybrid::ProgramImage &i, const Admission &a, const Lease &l, const Limits &lim,
             const std::atomic_bool &c)
        : image(i), admission(a), limits(lim), cancel(c)
    {
        simplify_params.set("max_steps", 10000u);
        report.lease = l;
        report.limits = lim;
        report.profile = a.valid() ? a.profile->name : "";
        report.dependencies = a.dependencies;
        report.imports = a.imports;
    }
    Report run()
    {
        if (!admission.valid())
        {
            report.frontiers.push_back({report.lease.key, 0, admission.rejection});
            return report;
        }
        for (const auto &segment : image.segs)
            for (uint64_t reserved : {context_base, native_stack, virtual_stack})
                if (segment.start < reserved + 0x10000 && segment.end > reserved - 0x10000)
                {
                    report.frontiers.push_back(
                        {report.lease.key, 0, "image overlaps symbolic private memory"});
                    return report;
                }
        State first(ctx);
        // Context slots are intentionally uninitialized, as in the native
        // dispatcher. The explorer starts at a handler ABI boundary, so no
        // undocumented zero-fill or argument-layout assumption is required.
        if (report.lease.key == 0)
            return report;
        if (!admission.profile->setup_bytes.empty())
        {
            for (auto slot : admission.profile->argument_slots)
                store(first, bv(context_base + slot * 8), fresh(), 64);
            for (auto slot : admission.profile->stack_slots)
                store(first, bv(context_base + slot * 8), bv(virtual_stack), 64);
            store(first, bv(virtual_stack), bv(0), 64);
        }
        enter(first, report.lease.key);
        std::deque<State> work;
        work.push_back(std::move(first));
        while (!work.empty())
        {
            State s = std::move(work.front());
            work.pop_front();
            ++report.states;
            try
            {
                for (;;)
                {
                    if (exhausted())
                    {
                        frontier(s, cancel.load() ? "cancelled" : "resource quota");
                        break;
                    }
                    // A repeated full symbolic state is a real loop. Do not
                    // identify states by table index, native address or key.
                    std::vector<unsigned> identity = {unsigned(s.key),
                                                      unsigned(s.key >> 32),
                                                      unsigned(s.pc),
                                                      unsigned(s.pc >> 32),

                                                      s.domain.id(),
                                                      unsigned(s.table_unchanged),
                                                      unsigned(s.imports_unchanged)};
                    s.memory.append_identity(identity);
                    for (const auto &r : s.registers)
                        identity.push_back(r.id());
                    for (const auto &f : s.flags)
                        identity.push_back(f.id());
                    for (const auto &v : s.vectors)
                        identity.push_back(v.id());
                    identity.push_back(unsigned(s.pool.blocks.size()));
                    for (const auto &block : s.pool.blocks)
                    {
                        identity.push_back(block.address.id());
                        identity.push_back(block.bytes.id());
                        identity.push_back(block.tag.id());
                        identity.push_back(unsigned(block.live));
                    }
                    for (auto c : s.calls)
                    {
                        identity.push_back(unsigned(c));
                        identity.push_back(unsigned(c >> 32));
                    }
                    const auto bytes = identity.size() * sizeof(unsigned);
                    if (bytes > limits.bytes / 2 || identity_bytes > limits.bytes / 2 - bytes)
                        throw std::runtime_error("symbolic state identity quota");
                    identity_bytes += bytes;
                    if (!seen.insert(std::move(identity)).second)
                    {
                        frontier(s, "exact native cycle requires CFG lowering");
                        break;
                    }
                    const auto &decoded = decode(s.pc);
                    const auto &d = decoded.first;
                    ++report.instructions;
                    if (d.temporary_count > 4096 ||
                        decoded.second.size() > limits.operations - report.operations)
                        throw std::runtime_error("SMIR operation quota");
                    auto native_return = d.flow == 9 ? load(s, s.registers[4], 64) : bv(0);
                    s.temporary.clear();
                    s.vector_temporary.clear();
                    for (unsigned n = 0; n < d.temporary_count; ++n)
                        s.temporary.push_back(fresh());
                    report.operations += decoded.second.size();
                    for (const auto &o : decoded.second)
                        operation(s, o);
                    if (d.flow == 0)
                    {
                        s.pc = d.fallthrough;
                        continue;
                    }
                    if (d.flow == 1)
                    {
                        s.pc = d.target;
                        continue;
                    }
                    if (d.flow == 2 || d.flow == 3)
                    {
                        auto predicate = (d.flow == 2 ? condition(s, d.condition)
                                                      : (get(s, d.predicate) != bv(0)))
                                             .simplify(simplify_params);
                        State taken = s;
                        taken.pc = d.target;
                        taken.domain = (s.domain && predicate).simplify(simplify_params);
                        s.pc = d.fallthrough;
                        s.domain = (s.domain && !predicate).simplify(simplify_params);
                        if (feasible(taken.domain))
                            work.push_back(std::move(taken));
                        if (feasible(s.domain))
                            continue;
                        break;
                    }
                    if (d.flow >= 4 && d.flow <= 8)
                    {
                        uint64_t target = 0;
                        if (d.flow == 5 || d.flow == 8)
                        {
                            uint64_t slot = 0;
                            if (number(address(s, d.address), slot))
                                if (const auto *binding = find_import(admission.imports, slot))
                                {
                                    if (!s.imports_unchanged)
                                        throw std::runtime_error(
                                            "import table may have been overwritten");
                                    const auto native = binding->snapshot_value;
                                    if (binding->loaded_mask != 255 || !image.executable(native) ||
                                        image.writable(native))
                                    {
                                        external(s, *binding, d, work);
                                        break;
                                    }
                                }
                        }
                        auto value = (d.flow == 4 || d.flow == 7) ? get(s, d.predicate)
                                     : (d.flow == 5 || d.flow == 8)
                                         ? load(s, address(s, d.address), 64)
                                         : bv(d.target);
                        if (!number(value, target))
                            throw std::runtime_error("symbolic native transfer");
                        if (d.flow >= 6)
                        {
                            if (s.calls.size() >= limits.call_depth)
                                throw std::runtime_error("native call depth quota");
                            s.calls.push_back(d.fallthrough);
                            s.registers[4] = (s.registers[4] - bv(8)).simplify(simplify_params);
                            store(s, s.registers[4], bv(d.fallthrough), 64);
                        }
                        s.pc = target;
                        continue;
                    }
                    if (d.flow == 9)
                    {
                        if (return_from_native(s, native_return, work))
                            continue;
                        break;
                    }
                    throw std::runtime_error(d.flow == 10 ? "native trap"
                                                          : "unsupported native flow");
                }
            }
            catch (const std::exception &e)
            {
                frontier(s, e.what());
            }
            if (exhausted())
            {
                for (const auto &pending : work)
                    frontier(pending, "unexplored queued state");
                break;
            }
        }
        report.cancelled = cancel.load();
        report.keys.assign(keys.begin(), keys.end());
        return report;
    }
};
}
Report explore(const hybrid::ProgramImage &i, const Admission &a, const Lease &l, const Limits &lim,
               const std::atomic_bool &cancel)
{
    Report rejected;
    rejected.lease = l;
    if (running.test_and_set())
    {
        rejected.frontiers.push_back({l.key, 0, "another WARBIRD job is active"});
        return rejected;
    }
    struct Release
    {
        ~Release() { running.clear(); }
    } release;
    if (l.model != model_version || l.smir_abi != RAX_SMIR_ABI_VERSION ||
        !dependencies_match(i, a.dependencies))
    {
        rejected.frontiers.push_back({l.key, 0, "stale admission or incompatible semantic ABI"});
        return rejected;
    }
    try
    {
        auto bindings = a.imports;
        validate_imports(i, bindings);
        if (bindings != a.imports)
            throw std::runtime_error("stale import snapshot");
    }
    catch (const std::exception &e)
    {
        rejected.frontiers.push_back({l.key, 0, e.what()});
        return rejected;
    }
    if (!lim.states || !lim.instructions || !lim.operations || lim.bytes < 1024 ||
        lim.time.count() <= 0 || lim.states > 4096 || lim.instructions > 65536 ||
        lim.operations > 1000000 || lim.bytes > 256 * 1024 * 1024 ||
        lim.time > std::chrono::milliseconds(60000))
    {
        rejected.frontiers.push_back({l.key, 0, "invalid resource limits"});
        return rejected;
    }
    try
    {
        return Explorer(i, a, l, lim, cancel).run();
    }
    catch (const std::exception &e)
    {
        rejected.frontiers.push_back({l.key, 0, e.what()});
        return rejected;
    }
}
} // namespace chernobog::warbird
