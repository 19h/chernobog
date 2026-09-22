#include "rotating_string_ctree.h"
#include "../analysis/arch_utils.h"
#include "../../common/rotating_string_transform.h"
#include <allins.hpp>
#include <sstream>
#include <limits>

namespace
{
namespace rs = chernobog::rotating_string;
namespace sr = chernobog::string_recovery;

struct Induction
{
    uint64_t start = 0, step = 0;
    uint8_t bits = 0;
    bool is_signed = false;
};
struct Address
{
    uint64_t start = 0, step = 0;
};
struct Shape
{
    rs::Program program;
    rs::Contract contract;
    ea_t entry = BADADDR, source = BADADDR, destination = BADADDR, store = BADADDR;
    cexpr_t *store_expression = nullptr;
    std::string identity;
};
struct Saved
{
    cfunc_t *owner = nullptr;
    Shape shape;
    ea_t end = BADADDR;
    int bitness = -1;
    std::vector<uint8_t> code, ciphertext;
    sr::recovered_text_t text;
};
std::map<std::pair<int64_t, ea_t>, Saved> facts;

uint8_t width(const cexpr_t *expression)
{
    if (!expression)
        return 0;
    const size_t bytes = expression->type.get_size();
    return bytes == 1 || bytes == 2 || bytes == 4 || bytes == 8 ? uint8_t(bytes * 8) : 0;
}

uint8_t integer_width(const cexpr_t *expression)
{
    // Floating conversions and Boolean normalization are not bitvector casts.
    return expression && expression->type.is_integral() && !expression->type.is_bool() &&
                   !expression->type.is_enum() && !expression->type.is_volatile()
               ? width(expression)
               : 0;
}

bool number(const cexpr_t *expression, uint64_t *value, unsigned depth = 0)
{
    if (!expression || !value || !integer_width(expression) || depth > 16)
        return false;
    if (expression->op == cot_num)
    {
        *value = expression->numval() & rs::mask(width(expression));
        return true;
    }
    if (expression->op == cot_cast && number(expression->x, value, depth + 1))
    {
        rs::SymbolicValue child;
        child.constant = *value;
        child.bits = width(expression->x);
        child.is_signed = expression->x->type.is_signed();
        *value = rs::resize(child, width(expression)).constant;
        return true;
    }
    return false;
}

bool pure_address_expression(const cexpr_t *expression, unsigned depth = 0)
{
    if (!expression || depth > 8)
        return false;
    if (expression->op == cot_obj || expression->op == cot_num || expression->op == cot_var)
        return true;
    return (expression->op == cot_ref || expression->op == cot_cast) &&
           pure_address_expression(expression->x, depth + 1);
}

bool initialize(const cexpr_t *expression, std::map<int, Induction> &variables)
{
    if (!expression || expression->op != cot_asg || !expression->x ||
        expression->x->op != cot_var || !expression->y || !width(expression->x))
        return false;
    const int variable = expression->x->v.idx;
    uint64_t value = 0;
    if (integer_width(expression->x) && number(expression->y, &value))
    {
        rs::SymbolicValue initial;
        initial.constant = value;
        initial.bits = width(expression->y);
        initial.is_signed = expression->y->type.is_signed();
        variables[variable] = {rs::resize(initial, width(expression->x)).constant, 0,
                               width(expression->x), expression->x->type.is_signed()};
    }
    else
    {
        variables.erase(variable); // An address-valued preheader alias is not a scalar fact.
        if (!pure_address_expression(expression->y))
            return false;
    }
    return true;
}

bool increment(const cexpr_t *expression, int *variable, uint64_t *step)
{
    if (!expression || !expression->x || expression->x->op != cot_var ||
        !integer_width(expression->x))
        return false;
    if (expression->op == cot_preinc || expression->op == cot_postinc)
        *step = 1;
    else if (expression->op != cot_asgadd || !number(expression->y, step))
        return false;
    *variable = expression->x->v.idx;
    return *step != 0 && *step <= 16;
}

bool safe_add(uint64_t left, uint64_t right, uint64_t *result)
{
    if (right > std::numeric_limits<uint64_t>::max() - left)
        return false;
    *result = left + right;
    return true;
}

bool scalar_address(const cexpr_t *expression, const std::map<int, Induction> &variables,
                    size_t count, Address *out, unsigned depth = 0)
{
    if (!expression || depth > 12 || !integer_width(expression))
        return false;
    uint64_t value = 0;
    if (number(expression, &value))
    {
        *out = {value, 0};
        return true;
    }
    if (expression->op == cot_var)
    {
        const auto found = variables.find(expression->v.idx);
        if (found == variables.end())
            return false;
        *out = {found->second.start, found->second.step};
    }
    else if (expression->op == cot_cast)
    {
        if (!scalar_address(expression->x, variables, count, out, depth + 1))
            return false;
    }
    else if (expression->op == cot_add)
    {
        Address left, right;
        if (!scalar_address(expression->x, variables, count, &left, depth + 1) ||
            !scalar_address(expression->y, variables, count, &right, depth + 1) ||
            !safe_add(left.start, right.start, &out->start) ||
            !safe_add(left.step, right.step, &out->step))
            return false;
    }
    else
        return false;
    const uint64_t limit = expression->type.is_signed() ? rs::mask(width(expression)) >> 1
                                                        : rs::mask(width(expression));
    return out->start <= limit && (out->step == 0 || count <= (limit - out->start) / out->step);
}

bool pointer_address(const cexpr_t *expression, const std::map<int, Induction> &variables,
                     size_t count, Address *out, unsigned depth = 0)
{
    if (!expression || depth > 12)
        return false;
    if (expression->op == cot_cast && expression->type.is_ptr() &&
        width(expression) == width(expression->x))
        return pointer_address(expression->x, variables, count, out, depth + 1);
    if (expression->op == cot_obj && expression->type.is_array())
    {
        *out = {uint64_t(expression->obj_ea), 0};
        return true;
    }
    if (expression->op == cot_ref && expression->x && expression->x->op == cot_obj)
    {
        *out = {uint64_t(expression->x->obj_ea), 0};
        return true;
    }
    if (expression->op == cot_add && expression->x && expression->y)
    {
        Address base, offset;
        const int scale = expression->x->type.get_ptrarr_objsize();
        if (scale < 1 || scale > 8 ||
            !pointer_address(expression->x, variables, count, &base, depth + 1) ||
            !scalar_address(expression->y, variables, count, &offset, depth + 1) ||
            offset.start > UINT64_MAX / uint64_t(scale) ||
            offset.step > UINT64_MAX / uint64_t(scale) ||
            !safe_add(base.start, offset.start * uint64_t(scale), &out->start) ||
            !safe_add(base.step, offset.step * uint64_t(scale), &out->step))
            return false;
        return true;
    }
    return false;
}

bool memory_address(const cexpr_t *expression, const std::map<int, Induction> &variables,
                    size_t count, Address *out)
{
    if (!expression || (integer_width(expression) != 8 && integer_width(expression) != 16))
        return false;
    if (expression->op == cot_ptr)
        return pointer_address(expression->x, variables, count, out);
    if (expression->op != cot_idx || !expression->x)
        return false;
    Address base, offset;
    const int scale = expression->x->type.get_ptrarr_objsize();
    if (scale != width(expression) / 8 ||
        !pointer_address(expression->x, variables, count, &base) ||
        !scalar_address(expression->y, variables, count, &offset) ||
        offset.start > UINT64_MAX / uint64_t(scale) || offset.step > UINT64_MAX / uint64_t(scale) ||
        !safe_add(base.start, offset.start * uint64_t(scale), &out->start) ||
        !safe_add(base.step, offset.step * uint64_t(scale), &out->step))
        return false;
    return true;
}

bool native_memory(ea_t address, size_t bytes, bool store, ea_t entry)
{
    insn_t instruction;
    auto *owner = get_func(address);
    if (address == BADADDR || !owner || owner->start_ea != entry ||
        decode_insn(&instruction, address) <= 0)
        return false;
    if (store && instruction.itype != NN_mov)
        return false;
    for (size_t index = 0; index < UA_MAXOP; ++index)
    {
        const auto &operand = instruction.ops[index];
        if ((operand.type == o_mem || operand.type == o_displ || operand.type == o_phrase) &&
            get_dtype_size(operand.dtype) == bytes && (!store || index == 0))
            return true;
    }
    return false;
}

struct Builder
{
    Shape &shape;
    const std::map<int, Induction> &variables;
    std::map<int, size_t> temporaries;
    bool key_found = false;
    std::optional<size_t> expression(const cexpr_t *value, unsigned depth = 0)
    {
        if (!value || depth > 24 || !integer_width(value) ||
            shape.program.nodes.size() >= rs::maximum_nodes)
            return {};
        rs::Node node;
        node.bits = width(value);
        node.is_signed = value->type.is_signed();
        if (value->op == cot_num)
        {
            node.operation = rs::Operation::CONSTANT;
            node.value = value->numval();
        }
        else if (value->op == cot_var)
        {
            const auto temporary = temporaries.find(value->v.idx);
            if (temporary != temporaries.end())
                return temporary->second;
            const auto found = variables.find(value->v.idx);
            if (found == variables.end())
                return {};
            node.operation =
                found->second.step == 0 ? rs::Operation::CONSTANT : rs::Operation::INDEX;
            node.value = found->second.start;
            node.step = found->second.step;
        }
        else if (value->op == cot_idx || value->op == cot_ptr)
        {
            Address address;
            if (node.bits != shape.contract.unit_bytes * 8 ||
                !memory_address(value, variables, shape.contract.units, &address) ||
                address.step != shape.contract.unit_bytes || address.start >= uint64_t(BADADDR) ||
                !native_memory(value->ea, shape.contract.unit_bytes, false, shape.entry))
                return {};
            if (shape.source != BADADDR && shape.source != ea_t(address.start))
                return {};
            shape.source = ea_t(address.start);
            node.operation = rs::Operation::INPUT;
        }
        else if (value->op == cot_cast)
        {
            const auto child = expression(value->x, depth + 1);
            if (!child)
                return {};
            node.operation = rs::Operation::CAST;
            node.left = *child;
        }
        else if (value->op == cot_add || value->op == cot_sub || value->op == cot_xor)
        {
            const auto left = expression(value->x, depth + 1),
                       right = expression(value->y, depth + 1);
            if (!left || !right)
                return {};
            node.operation = value->op == cot_add   ? rs::Operation::ADD
                             : value->op == cot_sub ? rs::Operation::SUB
                                                    : rs::Operation::XOR;
            node.left = *left;
            node.right = *right;
        }
        else if (value->op == cot_call && value->x && value->x->op == cot_helper && value->a &&
                 value->a->size() == 2 && node.bits == 32)
        {
            const bool left = streq(value->x->helper, "__ROL4__");
            if (!left && !streq(value->x->helper, "__ROR4__"))
                return {};
            insn_t native;
            auto *owner = get_func(value->ea);
            if (!owner || owner->start_ea != shape.entry || decode_insn(&native, value->ea) <= 0 ||
                native.itype != (left ? NN_rol : NN_ror) || get_dtype_size(native.Op1.dtype) != 4)
                return {};
            uint64_t key = 0;
            if (!number(&(*value->a)[0], &key))
                return {};
            if (key_found && shape.contract.key != uint32_t(key))
                return {};
            shape.contract.key = uint32_t(key);
            key_found = true;
            const auto key_node = expression(&(*value->a)[0], depth + 1);
            const auto count_node = expression(&(*value->a)[1], depth + 1);
            if (!key_node || !count_node)
                return {};
            node.operation = left ? rs::Operation::ROL32 : rs::Operation::ROR32;
            node.left = *key_node;
            node.right = *count_node;
        }
        else
            return {};
        if (shape.program.nodes.size() >= rs::maximum_nodes)
            return {};
        shape.program.nodes.push_back(node);
        return shape.program.nodes.size() - 1;
    }
};

std::optional<Shape> extract(cfunc_t *function)
{
    if (!function || !arch::is_x86() || inf_is_be() || function->body.op != cit_block ||
        !function->body.cblock || function->body.cblock->size() > 64)
        return {};
    std::map<int, Induction> variables;
    cloop_t *loop = nullptr;
    cfor_t *for_loop = nullptr;
    for (auto &statement : *function->body.cblock)
    {
        if (statement.op == cit_empty)
            continue;
        if (loop)
        {
            if (statement.op != cit_return)
                return {};
            continue;
        }
        if (statement.op == cit_expr && initialize(statement.cexpr, variables))
            continue;
        if (statement.op == cit_do)
            loop = statement.cdo;
        else if (statement.op == cit_while)
            loop = statement.cwhile;
        else if (statement.op == cit_for)
        {
            loop = for_loop = statement.cfor;
            if (for_loop->init.op != cot_empty && !initialize(&for_loop->init, variables))
                return {};
        }
        else
            return {};
    }
    if (!loop || !loop->body || loop->body->op != cit_block || !loop->body->cblock ||
        loop->body->cblock->size() > 32)
        return {};
    const cexpr_t &condition = loop->expr;
    if (condition.op != cot_ne && condition.op != cot_slt && condition.op != cot_ult)
        return {};
    if (!condition.x || condition.x->op != cot_var)
        return {};
    uint64_t bound = 0;
    if (!number(condition.y, &bound) || bound == 0 || bound > rs::maximum_bytes)
        return {};
    const int counter = condition.x->v.idx;
    const auto initial = variables.find(counter);
    if (initial == variables.end() || initial->second.start != 0 ||
        integer_width(condition.x) != initial->second.bits)
        return {};
    std::map<int, uint64_t> increments;
    std::vector<cexpr_t *> definitions;
    cexpr_t *store = nullptr;
    for (auto &statement : *loop->body->cblock)
    {
        if (statement.op != cit_expr || !statement.cexpr)
            return {};
        auto *expression = statement.cexpr;
        int variable = -1;
        uint64_t step = 0;
        if (store && increment(expression, &variable, &step))
        {
            if (!increments.emplace(variable, step).second)
                return {};
            continue;
        }
        if (store || expression->op != cot_asg || !expression->x)
            return {};
        if (expression->x->op == cot_var)
            definitions.push_back(expression);
        else
            store = expression;
    }
    if (for_loop && for_loop->step.op != cot_empty)
    {
        int variable = -1;
        uint64_t step = 0;
        if (!increment(&for_loop->step, &variable, &step) ||
            !increments.emplace(variable, step).second)
            return {};
    }
    if (!store || increments[counter] != 1)
        return {};
    for (const auto &increment : increments)
    {
        auto found = variables.find(increment.first);
        if (found == variables.end())
            return {};
        auto &variable = found->second;
        variable.step = increment.second;
        const uint64_t limit =
            variable.is_signed ? rs::mask(variable.bits) >> 1 : rs::mask(variable.bits);
        if (variable.start > limit || bound > (limit - variable.start) / variable.step)
            return {};
    }
    Shape shape;
    shape.entry = function->entry_ea;
    shape.contract.units = size_t(bound);
    shape.contract.unit_bytes = uint8_t(width(store->x) / 8);
    if ((shape.contract.unit_bytes != 1 && shape.contract.unit_bytes != 2) ||
        bound > rs::maximum_bytes / shape.contract.unit_bytes)
        return {};
    Address destination;
    if (!memory_address(store->x, variables, size_t(bound), &destination) ||
        destination.step != shape.contract.unit_bytes || destination.start >= uint64_t(BADADDR) ||
        !native_memory(store->ea, shape.contract.unit_bytes, true, shape.entry))
        return {};
    shape.destination = ea_t(destination.start);
    shape.store = store->ea;
    shape.store_expression = store;
    Builder builder{shape, variables, {}, false};
    for (const auto *definition : definitions)
    {
        if (variables.count(definition->x->v.idx))
            return {};
        const auto value = builder.expression(definition->y);
        if (!value || !integer_width(definition->x) ||
            shape.program.nodes.size() >= rs::maximum_nodes)
            return {};
        shape.program.nodes.push_back({rs::Operation::CAST, width(definition->x),
                                       definition->x->type.is_signed(), *value, 0, 0, 0});
        builder.temporaries[definition->x->v.idx] = shape.program.nodes.size() - 1;
    }
    const auto result = builder.expression(store->y);
    if (!result || !builder.key_found || shape.source == BADADDR)
        return {};
    shape.program.result = *result;
    const uint64_t bytes = bound * shape.contract.unit_bytes;
    if (shape.source > BADADDR - bytes || shape.destination > BADADDR - bytes ||
        (shape.source < shape.destination + bytes && shape.destination < shape.source + bytes))
        return {};
    std::ostringstream identity;
    identity << shape.source << ':' << shape.destination << ':' << shape.store << ':'
             << shape.contract.key << ':' << bound << ':' << unsigned(shape.contract.unit_bytes)
             << ':' << shape.program.result;
    for (const auto &node : shape.program.nodes)
        identity << ';' << unsigned(node.operation) << ',' << unsigned(node.bits) << ','
                 << node.is_signed << ',' << node.left << ',' << node.right << ',' << node.value
                 << ',' << node.step;
    shape.identity = identity.str();
    return shape;
}

bool permissions(const Shape &shape)
{
    const size_t bytes = shape.contract.units * shape.contract.unit_bytes;
    const auto *source = getseg(shape.source), *destination = getseg(shape.destination);
    return source && destination && source->end_ea - shape.source >= bytes &&
           destination->end_ea - shape.destination >= bytes && (source->perm & SEGPERM_READ) &&
           !(source->perm & SEGPERM_WRITE) && (destination->perm & SEGPERM_WRITE);
}

bool loaded(ea_t address, size_t size, std::vector<uint8_t> *bytes)
{
    if (size == 0 || size > 65536 || address > BADADDR - size)
        return false;
    for (size_t offset = 0; offset < size; ++offset)
        if (!is_loaded(address + offset))
            return false;
    bytes->resize(size);
    return get_bytes(bytes->data(), ssize_t(size), address) == ssize_t(size);
}

bool single_chunk(cfunc_t *function, ea_t *end, int *bitness)
{
    auto *native = get_func(function->entry_ea);
    auto *segment = getseg(function->entry_ea);
    if (!native || native->start_ea != function->entry_ea || !segment || segment->bitness == 0)
        return false;
    func_tail_iterator_t iterator(native);
    size_t count = 0;
    for (bool present = iterator.main(); present; present = iterator.next())
        ++count;
    if (count != 1 || native->end_ea <= native->start_ea ||
        native->end_ea - native->start_ea > 65536)
        return false;
    *end = native->end_ea;
    *bitness = segment->bitness;
    return true;
}
} // namespace

void capture_rotating_string_facts(cfunc_t *function)
{
    if (!function)
        return;
    const auto key = std::make_pair(int64_t(get_dbctx_id()), function->entry_ea);
    facts.erase(key);
    const auto shape = extract(function);
    if (!shape || !permissions(*shape))
        return;
    Saved saved;
    saved.owner = function;
    saved.shape = *shape;
    if (!single_chunk(function, &saved.end, &saved.bitness) ||
        !loaded(function->entry_ea, saved.end - function->entry_ea, &saved.code) ||
        !loaded(shape->source, shape->contract.units * shape->contract.unit_bytes,
                &saved.ciphertext))
        return;
    const auto output = rs::decode_bytes(shape->program, shape->contract, saved.ciphertext);
    if (!output)
        return;
    auto text = rs::decode_text(*output, sr::text_encoding_t::utf8);
    if (!text)
        text = rs::decode_text(*output, sr::text_encoding_t::utf16_le);
    if (!text)
        return;
    saved.text = *text;
    // Bound retained proof receipts across open databases/functions.
    if (facts.size() >= 64)
        facts.erase(facts.begin());
    facts.emplace(key, std::move(saved));
}

int annotate_rotating_string_facts(cfunc_t *function)
{
    if (!function || function->maturity != CMAT_FINAL || function->sv.empty())
        return 0;
    const auto found = facts.find({int64_t(get_dbctx_id()), function->entry_ea});
    if (found == facts.end() || found->second.owner != function)
        return 0;
    const auto &saved = found->second;
    ea_t end = BADADDR;
    int bitness = -1;
    std::vector<uint8_t> code, ciphertext;
    const auto current = extract(function);
    if (!current || current->identity != saved.shape.identity || !permissions(*current) ||
        !single_chunk(function, &end, &bitness) || end != saved.end || bitness != saved.bitness ||
        !loaded(function->entry_ea, saved.code.size(), &code) || code != saved.code ||
        !loaded(current->source, saved.ciphertext.size(), &ciphertext) ||
        ciphertext != saved.ciphertext)
        return 0;
    int x = -1, y = -1;
    if (!function->find_item_coords(current->store_expression, &x, &y) || y < 0 ||
        size_t(y) >= function->sv.size())
        return 0;
    qstring text;
    text.sprnt("rot32-xor[%u-bit units, key=0x%08X, units=%zu]: %s candidate \"",
               unsigned(current->contract.unit_bytes * 8), unsigned(current->contract.key),
               current->contract.units,
               saved.text.encoding == sr::text_encoding_t::utf8 ? "UTF-8" : "UTF-16LE");
    size_t shown = std::min<size_t>(saved.text.utf8.size(), 128);
    while (shown < saved.text.utf8.size() && shown > 0 &&
           (uint8_t(saved.text.utf8[shown]) & 0xC0) == 0x80)
        --shown;
    for (size_t index = 0; index < shown; ++index)
    {
        const char byte = saved.text.utf8[index];
        if (byte == '\n')
            text.append("\\n");
        else if (byte == '\r')
            text.append("\\r");
        else if (byte == '\t')
            text.append("\\t");
        else
        {
            if (byte == '\\' || byte == '"')
                text.append('\\');
            text.append(byte);
        }
    }
    text.append('"');
    if (shown < saved.text.utf8.size())
        text.append(" [display truncated]");
    auto &line = function->sv[size_t(y)].line;
    if (line.find(text) != qstring::npos)
        return 0;
    line.append(" " SCOLOR_ON SCOLOR_AUTOCMT "// ");
    line.append(text);
    line.append(SCOLOR_OFF SCOLOR_AUTOCMT);
    return 1;
}

void clear_rotating_string_facts(int64_t database_id)
{
    for (auto iterator = facts.begin(); iterator != facts.end();)
        if (iterator->first.first == database_id)
            iterator = facts.erase(iterator);
        else
            ++iterator;
}
