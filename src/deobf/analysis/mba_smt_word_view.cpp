#include "mba_smt_word_view.hpp"

#include <algorithm>
#include <map>
#include <set>

namespace chernobog::mba_smt::detail
{
namespace
{
bool boolean(Op op) { return op == Op::And || op == Op::Or || op == Op::Xor || op == Op::Not; }
bool arithmetic(const Term &term)
{
    return term &&
           (term->op == Op::Add || term->op == Op::Sub || term->op == Op::Mul ||
            term->op == Op::Neg || (term->op == Op::Shl && term->right->op == Op::Constant));
}
bool region_operator(const Term &term)
{
    return term && (arithmetic(term) || boolean(term->op) ||
                    (term->op == Op::Shr && term->right->op == Op::Constant));
}
bool plain_arithmetic(const Term &term, unsigned depth = 0)
{
    if (!term || depth > limits::expression_depth)
        return !term;
    if (term->op == Op::Constant || term->op == Op::Variable)
        return true;
    if (!arithmetic(term))
        return false;
    return plain_arithmetic(term->left, depth + 1) &&
           (term->op == Op::Shl || plain_arithmetic(term->right, depth + 1));
}
uint64_t mask(unsigned bits) { return bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1; }
struct Limit
{
};
struct Builder
{
    SolverSession &session;
    unsigned bits;
    size_t visits = 0;
    std::vector<Term> atoms;
    std::map<std::string, size_t> indices;
    size_t first_virtual = 0;
    std::set<std::string> reverse_subtractions;

    void inspect(const Term &node, unsigned depth = 0)
    {
        if (!node)
            return;
        poll(depth);
        if (node->op == Op::Load)
            throw Limit{};
        if (node->op == Op::Sub && node->left->op == Op::Constant)
            reverse_subtractions.insert(key(node));
        inspect(node->left, depth + 1);
        inspect(node->right, depth + 1);
    }
    void raw_inputs(const Term &node, std::set<std::string> &inputs, unsigned depth = 0)
    {
        poll(depth);
        if (node->bits != bits)
            throw Limit{};
        if (node->op == Op::Constant)
            return;
        if (node->op == Op::Add || node->op == Op::Sub || node->op == Op::Mul ||
            node->op == Op::Neg || boolean(node->op))
        {
            raw_inputs(node->left, inputs, depth + 1);
            if (node->right)
                raw_inputs(node->right, inputs, depth + 1);
            return;
        }
        if ((node->op == Op::Shl || node->op == Op::Shr) && node->right &&
            node->right->op == Op::Constant)
        {
            if ((node->right->value & 255) < bits)
                raw_inputs(node->left, inputs, depth + 1);
            return;
        }
        inputs.insert(key(node));
    }

    void poll(unsigned depth)
    {
        if (++visits > limits::expression_visits || depth > limits::expression_depth ||
            !session.has_budget())
            throw Limit{};
    }
    Term canonicalize(const Term &node, unsigned depth = 0)
    {
        if (!node)
            return {};
        poll(depth);
        // Keep conversions and opaque boundaries intact. They are restored
        // exactly and their independently admitted inner regions keep their
        // original width. Loads must never be hidden behind a virtual value.
        if (node->op == Op::Load)
            throw Limit{};
        if (node->bits != bits)
            return node;
        Term left = canonicalize(node->left, depth + 1);
        Term right = canonicalize(node->right, depth + 1);
        if (node->op == Op::Sub && right->op == Op::Constant && left->op != Op::Constant)
        {
            // Prefer the already present c-x word: x-(c+1) == ~(c-x).
            // That orientation avoids an extra NOT after restoring XOR.
            const Term reverse = expression(Op::Sub, constant(right->value - 1, bits), left);
            if (reverse_subtractions.count(key(reverse)))
                return expression(Op::Not, reverse);
        }
        return !node->left ? node : expression(node->op, left, right, node->bits);
    }
    void collect(const Term &node, unsigned depth = 0)
    {
        if (!node || node->bits != bits)
            return;
        poll(depth);
        if (boolean(node->op))
        {
            for (const Term &child : {node->left, node->right})
            {
                if (arithmetic(child) && child->bits == bits && plain_arithmetic(child))
                {
                    const auto id = key(child);
                    if (indices.emplace(id, atoms.size()).second)
                        atoms.push_back(child);
                }
            }
        }
        collect(node->left, depth + 1);
        collect(node->right, depth + 1);
    }
    struct Sum
    {
        uint64_t literal = 0;
        std::map<std::string, std::pair<Term, uint64_t>> terms;
    };
    void flatten(const Term &node, uint64_t factor, Sum &sum, unsigned depth = 0)
    {
        poll(depth);
        factor &= mask(bits);
        if (node->op == Op::Constant)
            sum.literal += factor * node->value;
        else if (node->op == Op::Add || node->op == Op::Sub)
        {
            flatten(node->left, factor, sum, depth + 1);
            flatten(node->right, node->op == Op::Sub ? -factor : factor, sum, depth + 1);
        }
        else if (node->op == Op::Neg)
            flatten(node->left, -factor, sum, depth + 1);
        else if (node->op == Op::Mul &&
                 (node->left->op == Op::Constant || node->right->op == Op::Constant))
        {
            const bool left = node->left->op == Op::Constant;
            flatten(left ? node->right : node->left,
                    factor * (left ? node->left->value : node->right->value), sum, depth + 1);
        }
        else if (node->op == Op::Shl && node->right->op == Op::Constant)
        {
            const uint64_t shift = node->right->value & 255;
            if (shift < bits)
                flatten(node->left, factor * (uint64_t{1} << shift), sum, depth + 1);
        }
        else
        {
            auto &entry = sum.terms[key(node)];
            entry.first = node;
            entry.second = (entry.second + factor) & mask(bits);
        }
        sum.literal &= mask(bits);
    }
    Term replace(const Term &node, const std::vector<Sum> &basis, unsigned depth = 0)
    {
        if (!node || node->bits != bits)
            return node;
        poll(depth);
        if (const auto it = indices.find(key(node)); it != indices.end())
            return variable(first_virtual + it->second, bits);
        if (node->op == Op::Mul && node->left->op != Op::Constant &&
            node->right->op != Op::Constant)
            return expression(Op::Mul, replace(node->left, basis, depth + 1),
                              replace(node->right, basis, depth + 1));
        if (arithmetic(node))
        {
            Sum sum;
            flatten(node, 1, sum);
            std::vector<Term> parts;
            // Exact +/-1 elimination only. There is no division by an even
            // coefficient in Z/(2^w), and no independence assumption about
            // the virtual words. Each coefficient is compared modulo 2^w.
            for (size_t index = 0; index < basis.size(); ++index)
            {
                const auto &atom = basis[index];
                if (atom.terms.empty())
                    continue;
                for (uint64_t sign : {uint64_t{1}, mask(bits)})
                {
                    bool matches = true;
                    for (const auto &[id, term] : atom.terms)
                    {
                        if (term.second == 0)
                            continue;
                        const auto found = sum.terms.find(id);
                        if (found == sum.terms.end() ||
                            found->second.second != ((sign * term.second) & mask(bits)))
                        {
                            matches = false;
                            break;
                        }
                    }
                    if (!matches)
                        continue;
                    for (const auto &[id, term] : atom.terms)
                        if (term.second)
                            sum.terms.erase(id);
                    sum.literal = (sum.literal - sign * atom.literal) & mask(bits);
                    const Term value = variable(first_virtual + index, bits);
                    parts.push_back(sign == 1 ? value : expression(Op::Neg, value));
                    break;
                }
            }
            for (const auto &[id, term] : sum.terms)
            {
                if (!term.second)
                    continue;
                Term value = replace(term.first, basis, depth + 1);
                if (term.second == mask(bits))
                    value = expression(Op::Neg, value);
                else if (term.second != 1)
                    value = expression(Op::Mul, constant(term.second, bits), value);
                parts.push_back(value);
            }
            if (sum.literal || parts.empty())
                parts.push_back(constant(sum.literal, bits));
            Term result = parts.front();
            for (size_t i = 1; i < parts.size(); ++i)
                result = expression(Op::Add, result, parts[i]);
            return result;
        }
        return !node->left ? node
                           : expression(node->op, replace(node->left, basis, depth + 1),
                                        replace(node->right, basis, depth + 1), node->bits);
    }
};
} // namespace

bool CobraWordView::useful(const Term &source)
{
    size_t visits = 0;
    bool masked = false;
    const auto inspect = [&](const auto &self, const Term &node, unsigned depth) -> bool
    {
        if (!node || ++visits > limits::expression_visits || depth > limits::expression_depth ||
            node->bits != source->bits)
            return false;
        if (!region_operator(node))
            return false;
        if (boolean(node->op) && node->right &&
            (node->left->op == Op::Constant || node->right->op == Op::Constant))
            masked = true;
        const bool found =
            boolean(node->op) && ((arithmetic(node->left) && plain_arithmetic(node->left)) ||
                                  (arithmetic(node->right) && plain_arithmetic(node->right)));
        const bool left = self(self, node->left, depth + 1);
        const bool right = self(self, node->right, depth + 1);
        return found || left || right;
    };
    const bool found = source && inspect(inspect, source, 0);
    // Constant-masked regions retain the existing semilinear preparation;
    // an independent virtual word would hide its known-bit relationships.
    return found && !masked;
}

CobraWordView::CobraWordView(const Term &source, SolverSession &session)
    : input_(source), source_(source)
{
    if (!source || source->bits < 8 || source->bits > 64 || source->bits % 8 || !useful(source))
        return;
    try
    {
        Builder builder{session, source->bits};
        builder.inspect(source);
        builder.visits = 0;
        std::set<std::string> raw_inputs;
        builder.raw_inputs(source, raw_inputs);
        builder.visits = 0;
        const Term normalized = builder.canonicalize(source);
        builder.visits = 0;
        builder.collect(normalized);
        if (builder.atoms.empty())
            return;
        const auto inputs = variables(source);
        if (!inputs.empty() &&
            *std::max_element(inputs.begin(), inputs.end()) >= limits::storage_regions)
            return;
        const size_t limit = session.options.profile == Profile::Deep ? 12 : 8;
        // Count real source inputs AND virtual inputs before allocation. This
        // conservative bound cannot hide an over-limit source behind atoms.
        if (raw_inputs.size() + builder.atoms.size() > limit)
            return;
        first_virtual_ = inputs.empty() ? 0 : *std::max_element(inputs.begin(), inputs.end()) + 1;
        builder.first_virtual = first_virtual_;
        builder.visits = 0;
        std::vector<Builder::Sum> basis(builder.atoms.size());
        for (size_t i = 0; i < basis.size(); ++i)
            builder.flatten(builder.atoms[i], 1, basis[i]);
        builder.visits = 0;
        Term view = builder.replace(normalized, basis);
        if (!session.has_budget())
            return;
        atoms_ = std::move(builder.atoms);
        input_ = std::move(view);
    }
    catch (const Limit &)
    {
        // Preserve the admitted original on shape/budget refusal. Generation
        // independently rechecks its deadline before accepting any result.
    }
}

bool CobraWordView::certify(SymbolicProgram &program, const SymbolicState &state,
                            const Term &candidate) const
{
    if (!lifted())
        return true;
    auto &session = program.session;
    if (!session.has_budget())
        return false;
    const Term restored_input = restore(input_), restored_candidate = restore(candidate);
    if (!restored_input || !restored_candidate)
        return false;

    const auto certified = [&](z3::solver &solver, const char *purpose)
    {
        ++session.statistics.candidates;
        const auto result = session.check(solver, purpose);
        if (result == z3::sat)
            ++session.statistics.disproved;
        else if (result == z3::unknown)
            ++session.statistics.unknown;
        return result == z3::unsat;
    };

    // First prove the candidate on independent arbitrary words. Concrete
    // products, additions and correlations cannot make this theorem easier.
    SymbolicState arbitrary(session.fresh_memory(program.program.address_bits));
    for (size_t i = 0; i < first_virtual_ + atoms_.size(); ++i)
        arbitrary.registers.push_back(session.fresh_value(
            i < program.program.widths.size() ? program.program.widths[i] : source_->bits));
    for (size_t i = 0; i < atoms_.size(); ++i)
        arbitrary.registers[first_virtual_ + i] = session.fresh_value(atoms_[i]->bits);
    const auto boolean_only = [](const auto &self, const Term &node) -> bool
    {
        if (!node)
            return true;
        switch (node->op)
        {
        case Op::Variable:
        case Op::Constant:
        case Op::And:
        case Op::Or:
        case Op::Xor:
        case Op::Not:
            return self(self, node->left) && self(self, node->right);
        default:
            return false;
        }
    };
    // Preserve a Boolean miter as bitwise logic. Expanding XOR into modular
    // products obscures bit independence and makes this otherwise trivial
    // width-generic theorem sensitive to the native solver's search schedule.
    const bool pure_boolean =
        boolean_only(boolean_only, input_) && boolean_only(boolean_only, candidate);
    if (!pure_boolean)
    {
        prepare_algebraic_word_proofs(program, arbitrary, input_);
        prepare_algebraic_word_proofs(program, arbitrary, candidate);
    }
    const auto word_value = [&](const Term &value)
    {
        auto result = program.evaluate(value, arbitrary);
        return pure_boolean ? result
                            : program.canonicalize_verified_complements(
                                  program.apply_verified_rewrites(result));
    };
    z3::solver word(session.context);
    word.add(word_value(input_) != word_value(candidate));
    if (!certified(word, "CoBRA compound-word universal mismatch"))
        return false;

    // Independently prove the algebraic bridge from the actual source to the
    // restored input. Complement normalization uses an accepted width-specific
    // universal theorem; its proof is never inferred from heuristic samples.
    const auto identity = std::make_pair(source_->bits, WordLaw::Invert);
    if (!program.verified_word_laws.count(identity))
    {
        const auto value = session.fresh_value(source_->bits);
        z3::solver invert(session.context);
        invert.add(~value != -value - 1);
        if (!certified(invert, "CoBRA compound-word complement mismatch"))
            return false;
        program.verified_word_laws.insert(identity);
    }
    const auto before = program.evaluate(source_, state);
    const auto restored = program.evaluate(restored_input, state);
    z3::solver bridge(session.context);
    bridge.add(program.canonicalize_verified_complements(before) !=
               program.canonicalize_verified_complements(restored));
    if (!certified(bridge, "CoBRA compound-word restoration mismatch"))
        return false;

    // The arbitrary-word theorem is instantiated only after the exact restore
    // map and bridge have been checked. Compose with earlier proved equalities
    // in their existing order; complete-site and emitted proofs still follow.
    prepare_algebraic_word_proofs(program, state, restored_candidate);
    const auto target = program.evaluate(restored_candidate, state);
    const auto normalized_before = program.apply_verified_rewrites(before);
    const auto normalized_target = program.apply_verified_rewrites(target);
    program.retain_verified_rewrite(normalized_before, normalized_target);
    program.retain_verified_rewrite(before, normalized_target);
    program.has_compound_word_proofs = true;
    return session.has_budget();
}

Term CobraWordView::restore(const Term &candidate) const
{
    size_t visits = 0;
    const auto expand = [&](const auto &self, const Term &node, unsigned depth) -> Term
    {
        if (!node)
            return {};
        if (++visits > limits::expression_visits || depth > limits::expression_depth)
            throw Limit{};
        if (node->op == Op::Variable && node->value >= first_virtual_ &&
            node->value - first_virtual_ < atoms_.size())
        {
            const auto &atom = atoms_[size_t(node->value - first_virtual_)];
            if (atom->bits != node->bits)
                throw Limit{};
            return self(self, atom, depth + 1);
        }
        return !node->left ? node
                           : expression(node->op, self(self, node->left, depth + 1),
                                        self(self, node->right, depth + 1), node->bits);
    };
    try
    {
        return expand(expand, candidate, 0);
    }
    catch (const Limit &)
    {
        return {};
    }
}
} // namespace chernobog::mba_smt::detail
