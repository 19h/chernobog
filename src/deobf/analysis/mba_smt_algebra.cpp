#include "mba_smt_internal.hpp"
#include "mba_cobra.hpp"

#include <algorithm>
#include <map>
#include <optional>
#include <set>

namespace chernobog::mba_smt::detail
{
namespace
{
constexpr size_t max_boolean_inputs = 4;
constexpr size_t max_boolean_candidates = 65536;

uint64_t width_mask(unsigned bits) { return bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1; }

// Cancel identical summands without enumerating Boolean functions or fitting
// coefficients. The full-width proof below authorizes every resulting change.
Term cancel_summands(const Term &original)
{
    if (original->op != Op::Add && original->op != Op::Sub)
        return original;
    std::map<std::string, std::pair<Term, uint64_t>> summands;
    uint64_t literal = 0;
    const uint64_t mask = width_mask(original->bits);
    size_t remaining = limits::expression_visits;
    std::function<bool(const Term &, uint64_t)> collect = [&](const Term &term, uint64_t scale)
    {
        if (remaining-- == 0)
            return false;
        if (term->bits == original->bits)
        {
            if (term->op == Op::Add || term->op == Op::Sub)
                return collect(term->left, scale) &&
                       collect(term->right, term->op == Op::Sub ? 0 - scale : scale);
            if (term->op == Op::Constant)
            {
                literal += scale * term->value;
                return true;
            }
            if (term->op == Op::Mul && term->left->op == Op::Constant)
                return collect(term->right, scale * term->left->value);
            if (term->op == Op::Mul && term->right->op == Op::Constant)
                return collect(term->left, scale * term->right->value);
        }
        auto &entry = summands[key(term)];
        entry.first = term;
        entry.second += scale;
        return true;
    };
    if (!collect(original, 1))
        return original;
    std::map<uint64_t, Term> groups;
    for (const auto &[identifier, entry] : summands)
    {
        const uint64_t coefficient = entry.second & mask;
        if (!coefficient)
            continue;
        auto &group = groups[coefficient];
        group = group ? expression(Op::Add, group, entry.first) : entry.first;
    }
    Term result;
    for (const auto &[coefficient, group] : groups)
    {
        const Term part = coefficient == 1 ? group
                          : coefficient == mask
                              ? expression(Op::Neg, group)
                              : expression(Op::Mul, constant(coefficient, original->bits), group);
        result = result ? expression(Op::Add, result, part) : part;
    }
    literal &= mask;
    if (literal || !result)
        result = result ? expression(Op::Add, result, constant(literal, original->bits))
                        : constant(literal, original->bits);
    return cost(result) < cost(original) ? result : original;
}

// Fixed word identity: (a | b) + ~a + 1 == ~a & b modulo 2^w.
// This bounded normalization still needs its ordinary compositional proof;
// it performs no signature enumeration or legacy search.
Term fold_complemented_word_sum(const Term &term)
{
    if (term->op != Op::Add)
        return term;
    const Term literal = term->right->op == Op::Constant ? term->right : term->left;
    const Term sum = term->right->op == Op::Constant ? term->left : term->right;
    if (literal->op != Op::Constant || literal->value != 1 || sum->op != Op::Add)
        return term;
    for (bool reversed : {false, true})
    {
        const Term disjunction = reversed ? sum->right : sum->left;
        const Term complement = reversed ? sum->left : sum->right;
        if (disjunction->op != Op::Or || complement->op != Op::Not)
            continue;
        if (key(disjunction->left) == key(complement->left))
            return expression(Op::And, complement, disjunction->right);
        if (key(disjunction->right) == key(complement->left))
            return expression(Op::And, complement, disjunction->left);
    }
    return term;
}

struct UnsignedRange
{
    uint64_t minimum;
    uint64_t maximum;
};

// Complement normalization exposes shared Boolean atoms during proof search.
// Fold it back before comparing costs so a smaller hypothesis does not acquire
// an extra emitted NOT merely because its literal uses the upper half-word.
Term compact_complements(const Term &term,
                         const std::function<bool(const Term &, const Term &)> &verify)
{
    if (!term || !term->left)
        return term;
    Term left = compact_complements(term->left, verify);
    Term right = compact_complements(term->right, verify);
    if (term->op == Op::Not && left->op == Op::Xor)
    {
        const Term literal = left->right->op == Op::Constant ? left->right : left->left;
        const Term input = left->right->op == Op::Constant ? left->left : left->right;
        if (literal->op == Op::Constant)
        {
            const Term candidate = expression(
                Op::Xor, input, constant(literal->value ^ width_mask(term->bits), term->bits));
            if (verify(expression(term->op, left, right, term->bits), candidate))
                return candidate;
        }
    }
    return expression(term->op, left, right, term->bits);
}

UnsignedRange unsigned_range(const Term &term)
{
    const KnownBits bits = known_bits(term);
    const uint64_t mask = width_mask(term->bits);
    const UnsignedRange fallback{bits.one, mask & ~bits.zero};
    if (term->op == Op::UnsignedDivide && term->right->op == Op::Constant &&
        term->right->value != 0)
    {
        const auto numerator = unsigned_range(term->left);
        return {numerator.minimum / term->right->value, numerator.maximum / term->right->value};
    }
    if (term->op == Op::Add)
    {
        const auto left = unsigned_range(term->left);
        const auto right = unsigned_range(term->right);
        if (left.maximum <= mask - right.maximum)
        {
            return {left.minimum + right.minimum, left.maximum + right.maximum};
        }
    }
    return fallback;
}

bool nonuniform_constant(const Term &term)
{
    return term && term->op == Op::Constant && term->value != 0 &&
           (term->value & width_mask(term->bits)) != width_mask(term->bits);
}

// Boolean words may themselves be expressions, for example x ^ 0x393F5533.
// A cut treats such a word as one input. Its relationship to other words is
// restored by the full-width proof, never assumed from truth-table samples.
bool is_boolean_input(const Term &term)
{
    switch (term->op)
    {
    case Op::Variable:
    case Op::Load:
    case Op::Low:
    case Op::High:
    case Op::ZeroExtend:
    case Op::SignExtend:
        return true;
    case Op::Xor:
        return nonuniform_constant(term->left) || nonuniform_constant(term->right);
    default:
        return false;
    }
}

// A comparison may observe only some bits of a word. Remove conversions and
// constant masks that do not affect those bits before constructing the test.
Term observed_bits(Term term, uint64_t mask)
{
    for (;;)
    {
        if ((term->op == Op::ZeroExtend || term->op == Op::SignExtend || term->op == Op::Low) &&
            (mask & ~width_mask(term->left->bits)) == 0)
        {
            term = term->left;
            continue;
        }

        if (term->op == Op::And || term->op == Op::Or)
        {
            const Term literal = term->left->op == Op::Constant ? term->left : term->right;
            const Term input = term->left->op == Op::Constant ? term->right : term->left;
            if (literal->op == Op::Constant)
            {
                const uint64_t retained = literal->value & mask;
                const bool transparent = term->op == Op::And ? retained == mask : retained == 0;
                if (transparent)
                {
                    term = input;
                    continue;
                }
            }
        }
        break;
    }

    if (mask == width_mask(term->bits))
    {
        return term;
    }
    return expression(Op::And, term, constant(mask, term->bits));
}

// Compare from the most significant bit. A fixed bit that differs from the
// threshold determines the result whenever all earlier unknown bits match.
// Some such decision chains reduce to one equality or inequality on a mask.
Term simplify_threshold(const Term &term)
{
    if (term->op != Op::UnsignedLess)
    {
        return term;
    }

    const bool greater = term->left->op == Op::Constant;
    const Term literal = greater ? term->left : term->right;
    const Term input = greater ? term->right : term->left;
    if (literal->op != Op::Constant)
    {
        return term;
    }

    const uint64_t threshold = literal->value & width_mask(input->bits);
    const KnownBits known = known_bits(input);
    uint64_t mask = 0;
    bool suffix_result = false;
    for (unsigned remaining = input->bits; remaining != 0; --remaining)
    {
        const uint64_t bit = uint64_t{1} << (remaining - 1);
        if (((known.zero | known.one) & bit) == 0)
        {
            mask |= bit;
            continue;
        }

        const bool input_set = (known.one & bit) != 0;
        const bool threshold_set = (threshold & bit) != 0;
        if (input_set != threshold_set)
        {
            suffix_result = greater ? input_set : threshold_set;
            break;
        }
    }

    // With a true suffix, > needs leading ones and < needs leading zeroes.
    // With a false suffix, > needs a nonzero prefix and < a prefix not all ones.
    // Opposite trailing bits can therefore be discarded before testing whether
    // the remaining threshold bits have one uniform value.
    const bool matching_value = suffix_result ? greater : !greater;
    const bool removable_value = !matching_value;
    while (mask != 0)
    {
        const uint64_t lowest = mask & (~mask + 1);
        if (((threshold & lowest) != 0) != removable_value)
        {
            break;
        }
        mask &= ~lowest;
    }
    if (mask == 0)
    {
        return constant(suffix_result, term->bits);
    }

    const uint64_t expected = matching_value ? mask : 0;
    if ((threshold & mask) != expected)
    {
        return term;
    }

    const Term observed = observed_bits(input, mask);
    const Op comparison = suffix_result ? Op::Equal : Op::NotEqual;
    const Term candidate =
        expression(comparison, observed, constant(expected, observed->bits), term->bits);
    // This local form can cost the same as OR + threshold. Retain it inside
    // a cheaper enclosing division replacement; the complete candidate and
    // actual SDK emission must still pass their strict cost gates.
    return cost(candidate) <= cost(term) ? candidate : term;
}

class AlgebraicSimplifier
{
  public:
    AlgebraicSimplifier(SymbolicProgram &program, const SymbolicState &state)
        : program_(program), session_(program.session), state_(state)
    {
    }

    Term run(const Term &original)
    {
        if (session_.options.backend == Backend::Legacy && cost(original) >= 8)
        {
            prepare_bitwise_proofs(original);
        }
        return compact_complements(rewrite(original), [&](const Term &before, const Term &after)
                                   { return prove(before, after); });
    }

    bool from_cobra() const noexcept { return cobra_origin_; }

  private:
    bool collect_word_inputs(const Term &term, unsigned bits, std::vector<Term> &inputs) const
    {
        if (term->bits != bits)
        {
            return false;
        }
        if (term->op == Op::Constant)
        {
            return true;
        }
        const bool bitwise =
            term->op == Op::And || term->op == Op::Or || term->op == Op::Xor || term->op == Op::Not;
        if (!bitwise || is_boolean_input(term))
        {
            const auto identifier = key(term);
            const auto same = [&](const Term &input) { return key(input) == identifier; };
            if (std::none_of(inputs.begin(), inputs.end(), same))
            {
                inputs.push_back(term);
            }
            return inputs.size() <= max_boolean_inputs;
        }
        return collect_word_inputs(term->left, bits, inputs) &&
               (!term->right || collect_word_inputs(term->right, bits, inputs));
    }

    void prepare_bitwise_proofs(const Term &term)
    {
        if (!term || !term->left || !session_.has_budget() ||
            linearized_.size() >= limits::expression_visits ||
            !linearized_.insert(key(term)).second)
        {
            return;
        }
        if (term->op == Op::And || term->op == Op::Or || term->op == Op::Xor || term->op == Op::Not)
        {
            std::vector<Term> inputs;
            if (collect_word_inputs(term, term->bits, inputs))
            {
                const Term candidate = reconstruct_linear_mba(program_, state_, term, inputs);
                if (candidate && key(candidate) != key(term))
                {
                    // A proof-only expansion can expose cancellation between
                    // distant summands without enlarging the emitted code.
                    // Arithmetic operands inside a Boolean word are atoms;
                    // their real relationships remain in the SMT proof.
                    prove(term, candidate);
                }
            }
        }
        prepare_bitwise_proofs(term->left);
        prepare_bitwise_proofs(term->right);
    }

    unsigned word_degree(const Term &node) const
    {
        if (node->op == Op::Constant)
            return 0;
        if (node->op == Op::Mul)
            return std::min(2u, word_degree(node->left) + word_degree(node->right));
        if (node->op == Op::Add || node->op == Op::Sub)
            return std::max(word_degree(node->left), word_degree(node->right));
        if (node->op == Op::Neg)
            return word_degree(node->left);
        return 1; // Boolean words and typed boundaries are atoms here.
    }

    bool has_word_masks(const Term &node) const
    {
        if (!node || !node->left)
            return false;
        if (node->op == Op::And || node->op == Op::Or || node->op == Op::Xor)
            for (const auto &operand : {node->left, node->right})
                if (operand->op == Op::Constant && operand->value != 0 &&
                    (operand->value & width_mask(node->bits)) != width_mask(node->bits))
                    return true;
        return has_word_masks(node->left) || has_word_masks(node->right);
    }

    enum class WordLaw
    {
        Invert,
        Or,
        Xor,
        AndNot,
        OrNot,
        OrAndNot
    };

    std::pair<z3::expr, z3::expr> word_identity(WordLaw law, const z3::expr &a,
                                                const z3::expr &b) const
    {
        switch (law)
        {
        case WordLaw::Invert:
            return {~a, -a - 1};
        case WordLaw::Or:
            return {a | b, a + b - (a & b)};
        case WordLaw::Xor:
            return {a ^ b, a + b - 2 * (a & b)};
        case WordLaw::AndNot:
            return {a & ~b, a - (a & b)};
        case WordLaw::OrNot:
            return {a | ~b, -b - 1 + (a & b)};
        case WordLaw::OrAndNot:
            return {(a | b) & ~b, a - (a & b)};
        }
        throw std::invalid_argument("unsupported word identity");
    }

    void prepare_word_proofs(const Term &node, unsigned bits)
    {
        if (!node || !node->left || node->bits != bits || !session_.has_budget() ||
            !linearized_.insert(key(node)).second)
            return;
        prepare_word_proofs(node->left, bits);
        prepare_word_proofs(node->right, bits);
        Term a = node->left, b = node->right;
        std::optional<WordLaw> law;
        if (node->op == Op::Not)
            law = WordLaw::Invert;
        else if (node->op == Op::Xor)
            law = WordLaw::Xor;
        else if (node->op == Op::Or || node->op == Op::And)
        {
            if (b->op == Op::Not)
            {
                law = node->op == Op::And ? WordLaw::AndNot : WordLaw::OrNot;
                b = b->left;
            }
            else if (a->op == Op::Not)
            {
                law = node->op == Op::And ? WordLaw::AndNot : WordLaw::OrNot;
                a = node->right;
                b = node->left->left;
            }
            else if (node->op == Op::Or)
                law = WordLaw::Or;
        }
        if (!law)
            return;
        if (*law == WordLaw::AndNot && a->op == Op::Or)
        {
            if (key(a->left) == key(b))
            {
                a = a->right;
                law = WordLaw::OrAndNot;
            }
            else if (key(a->right) == key(b))
            {
                a = a->left;
                law = WordLaw::OrAndNot;
            }
        }
        const auto identity = std::make_pair(bits, *law);
        if (word_laws_.count(identity) == 0)
        {
            const auto x = session_.fresh_value(bits), y = session_.fresh_value(bits);
            const auto theorem = word_identity(*law, x, y);
            z3::solver solver(session_.context);
            solver.add(theorem.first != theorem.second);
            ++session_.statistics.candidates;
            const auto result = session_.check(solver, "MBA Boolean word identity");
            if (result != z3::unsat)
            {
                if (result == z3::sat)
                    ++session_.statistics.disproved;
                else
                    ++session_.statistics.unknown;
                return;
            }
            word_laws_.insert(identity);
        }
        z3::params parameters(session_.context);
        parameters.set("som", true);
        parameters.set("bv_sort_ac", true);
        parameters.set("max_steps", 10000u);
        const auto normalized = [&](const Term &value)
        {
            return program_.apply_verified_rewrites(program_.evaluate(value, state_))
                .simplify(parameters);
        };
        const auto left = normalized(a);
        const auto right = b ? normalized(b) : left;
        const auto after = word_identity(*law, left, right).second.simplify(parameters);
        const auto original = program_.evaluate(node, state_);
        const auto before = program_.apply_verified_rewrites(original);
        // Universal word theorem instantiation, composed with previously proved
        // child equalities. These entries assist proof only; the unchanged input
        // still goes to CoBRA, which alone supplies the algebraic candidate.
        program_.retain_verified_rewrite(before, after);
        if (!z3::eq(original, before))
            program_.retain_verified_rewrite(original, after);
    }

    Term prepare_boundaries(const Term &node)
    {
        if (!node || !node->left)
            return node;
        const bool region_operator = node->op == Op::Add || node->op == Op::Sub ||
                                     node->op == Op::Mul || node->op == Op::And ||
                                     node->op == Op::Or || node->op == Op::Xor ||
                                     node->op == Op::Not || node->op == Op::Neg ||
                                     ((node->op == Op::Shl || node->op == Op::Shr) && node->right &&
                                      node->right->op == Op::Constant);
        const auto left = region_operator ? prepare_boundaries(node->left) : rewrite(node->left);
        const auto right = region_operator ? prepare_boundaries(node->right) : rewrite(node->right);
        return left == node->left && right == node->right
                   ? node
                   : expression(node->op, left, right, node->bits);
    }

    Term rewrite(const Term &original, bool boundaries_prepared = false)
    {
        if (!original || !original->left || !session_.has_budget())
        {
            return original;
        }
        const std::string identifier = key(original);
        const auto cached = rewritten_.find(identifier);
        if (cached != rewritten_.end())
        {
            return cached->second;
        }
        if (++visited_ > limits::expression_visits)
        {
            return original;
        }

        Term term;
        const bool arithmetic =
            original->op == Op::Add || original->op == Op::Sub || original->op == Op::Mul;
        if (session_.options.backend == Backend::Cobra && arithmetic && original->bits <= 32 &&
            word_degree(original) <= 1 && !has_word_masks(original))
        {
            // Visit typed/opaque boundaries bottom-up, then give the complete
            // same-width region its allowance before spending it on prefixes.
            // A failed complete attempt may still expose useful child regions.
            const auto prepared = boundaries_prepared ? original : prepare_boundaries(original);
            const auto proof_started = session_.now();
            if (session_.remaining_budget(proof_started) >= std::chrono::milliseconds(10))
                prepare_word_proofs(prepared, prepared->bits);
            session_.statistics.cobra.candidate_proof_ns += static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(session_.now() - proof_started)
                    .count());
            if (Term candidate = cost(prepared) >= 2 ? simplify_cobra(prepared) : Term{})
                term = std::move(candidate);
            else
            {
                term = expression(prepared->op, rewrite(prepared->left, true),
                                  rewrite(prepared->right, true), prepared->bits);
                if (cost(term) >= 2 && key(term) != key(prepared))
                    if (Term candidate = simplify_cobra(term))
                        term = std::move(candidate);
            }
        }
        else
        {
            term = expression(original->op, rewrite(original->left), rewrite(original->right),
                              original->bits);
            // Wide and polynomial roots need the child equality lemmas before
            // their full-width proof; retain their bottom-up schedule.
            if (session_.options.backend == Backend::Cobra && cost(term) >= 2)
                if (Term candidate = simplify_cobra(term))
                    term = std::move(candidate);
        }
        // A returned hypothesis can reconstruct equal factors or replace a
        // complementary word's canonical literal form below its root.
        std::function<Term(const Term &)> normalize = [&](const Term &input) -> Term
        {
            if (!input || !input->left)
                return input;
            return fold_complemented_word_sum(normalize_complement(cancel_summands(expression(
                input->op, normalize(input->left), normalize(input->right), input->bits))));
        };
        term = normalize(term);

        if (term->right && term->right->op == Op::Constant && term->right->value == 0 &&
            (term->op == Op::Add || term->op == Op::Sub || term->op == Op::Or ||
             term->op == Op::Xor))
            term = term->left;
        else if (term->left && term->left->op == Op::Constant && term->left->value == 0 &&
                 term->right && (term->op == Op::Add || term->op == Op::Or || term->op == Op::Xor))
            term = term->right;
        term = normalize_masks(term);
        term = normalize_complement(term);
        term = factor_constant_offset(term);
        if ((term->op == Op::Add || term->op == Op::Sub) && term->left && term->right &&
            term->left->op == Op::Mul && term->right->op == Op::Mul)
        {
            const auto factor = [](const Term &product)
            { return product->left->op == Op::Constant ? product->left : product->right; };
            const auto input = [](const Term &product)
            { return product->left->op == Op::Constant ? product->right : product->left; };
            const auto a = factor(term->left), b = factor(term->right);
            if (a->op == Op::Constant && b->op == Op::Constant && a->value == b->value)
                term = expression(
                    Op::Mul, a,
                    expression(term->op, input(term->left), input(term->right), term->bits),
                    term->bits);
        }

        const z3::expr value = program_.evaluate(term, state_).simplify();
        uint64_t literal = 0;
        if (value.is_numeral_u64(literal))
        {
            term = constant(literal, term->bits);
        }
        else if (term->op == Op::UnsignedDivide)
        {
            term = simplify_division(term);
        }
        else if (term->op == Op::Equal || term->op == Op::NotEqual || term->op == Op::UnsignedLess)
        {
            term = simplify_comparison(term);
        }
        else if (session_.options.backend == Backend::Legacy && cost(term) >= 2)
        {
            if (Term candidate = simplify_linear(term))
            {
                term = std::move(candidate);
            }
            if (cost(term) >= 2)
            {
                if (Term candidate = simplify_boolean(term))
                {
                    term = std::move(candidate);
                }
            }
        }

        if (key(term) != identifier && !prove(original, term))
        {
            term = original;
        }
        rewritten_.emplace(identifier, term);
        return term;
    }

    bool prove(const Term &before, const Term &after)
    {
        const z3::expr original = program_.evaluate(before, state_);
        const z3::expr replacement = program_.evaluate(after, state_);
        const auto normalized_original = program_.apply_verified_rewrites(original);
        const auto normalized_replacement = program_.apply_verified_rewrites(replacement);
        z3::params simplifier(session_.context);
        simplifier.set("som", true);
        simplifier.set("bv_sort_ac", true);
        simplifier.set("max_steps", 10000u);
        z3::solver solver(session_.context);
        solver.add((normalized_original != normalized_replacement).simplify(simplifier));
        ++session_.statistics.candidates;
        const auto result = session_.check(solver, "MBA compositional equality proof");
        if (result == z3::unsat)
        {
            // These equalities are unconditional in this immutable symbol
            // context. Later proofs may substitute them without importing
            // block-specific assumptions or accepting a sampled equality.
            program_.retain_verified_rewrite(original, replacement);
            if (!z3::eq(original, normalized_original))
            {
                program_.retain_verified_rewrite(normalized_original, normalized_replacement);
            }
            return true;
        }
        if (result == z3::sat)
        {
            ++session_.statistics.disproved;
        }
        else
        {
            ++session_.statistics.unknown;
        }
        return false;
    }

    Term factor_constant_offset(const Term &term)
    {
        if (term->op != Op::Add)
        {
            return term;
        }
        const Term offset = term->right->op == Op::Constant ? term->right : term->left;
        const Term product = term->right->op == Op::Constant ? term->left : term->right;
        if (offset->op != Op::Constant || product->op != Op::Mul)
        {
            return term;
        }
        const Term factor = product->left->op == Op::Constant ? product->left : product->right;
        const Term input = product->left->op == Op::Constant ? product->right : product->left;
        if (factor->op != Op::Constant || factor->value == 0 || offset->value % factor->value != 0)
        {
            return term;
        }

        // Moving an integral offset through a constant factor can expose a
        // Boolean-word identity across an arithmetic expression boundary.
        const Term inner =
            expression(Op::Add, input, constant(offset->value / factor->value, term->bits));
        const Term factored = expression(Op::Mul, factor, inner);
        if (!prove(term, factored))
        {
            return term;
        }
        return expression(Op::Mul, factor, rewrite(inner));
    }

    Term normalize_complement(const Term &term) const
    {
        if (term->op != Op::Xor)
        {
            return term;
        }
        const Term literal = term->right->op == Op::Constant ? term->right : term->left;
        const Term input = term->right->op == Op::Constant ? term->left : term->right;
        if (literal->op != Op::Constant)
        {
            return term;
        }
        const uint64_t value = literal->value & width_mask(term->bits);
        const uint64_t complement = value ^ width_mask(term->bits);
        if (complement >= value)
        {
            return term;
        }
        return expression(Op::Not, expression(Op::Xor, input, constant(complement, term->bits)));
    }

    Term simplify_division(const Term &term)
    {
        if (term->right->op != Op::Constant || term->right->value == 0)
        {
            return term;
        }
        const uint64_t divisor = term->right->value;
        const auto numerator = unsigned_range(term->left);
        const uint64_t minimum = numerator.minimum / divisor;
        const uint64_t maximum = numerator.maximum / divisor;
        if (minimum == maximum)
        {
            return constant(minimum, term->bits);
        }
        if (maximum - minimum != 1)
        {
            return term;
        }

        // The upper quotient exists within the numerator's range, so its
        // threshold cannot overflow the unsigned result width.
        const uint64_t threshold = maximum * divisor;
        Term upper =
            expression(Op::UnsignedLess, constant(threshold - 1, term->bits), term->left, 8);
        upper = rewrite(upper);
        if (term->bits != 8)
        {
            upper = expression(Op::ZeroExtend, upper, {}, term->bits);
        }
        return minimum == 0 ? upper : expression(Op::Add, constant(minimum, term->bits), upper);
    }

    Term simplify_comparison(const Term &term) const
    {
        const auto left = unsigned_range(term->left);
        const auto right = unsigned_range(term->right);
        if (term->op == Op::UnsignedLess)
        {
            if (left.maximum < right.minimum)
            {
                return constant(1, term->bits);
            }
            if (left.minimum >= right.maximum)
            {
                return constant(0, term->bits);
            }
        }
        else if (left.maximum < right.minimum || right.maximum < left.minimum)
        {
            return constant(term->op == Op::NotEqual, term->bits);
        }
        return simplify_threshold(term);
    }

    bool collect_inputs(const Term &term, unsigned bits, std::vector<Term> &inputs) const
    {
        if (term->bits != bits)
        {
            return false;
        }
        if (term->op == Op::Constant)
        {
            return true;
        }
        if (is_boolean_input(term))
        {
            const auto identifier = key(term);
            const auto same_input = [&](const Term &input) { return key(input) == identifier; };
            if (std::none_of(inputs.begin(), inputs.end(), same_input))
            {
                inputs.push_back(term);
            }
            return inputs.size() <= max_boolean_inputs;
        }
        switch (term->op)
        {
        case Op::Add:
        case Op::Sub:
        case Op::Mul:
        case Op::And:
        case Op::Or:
        case Op::Xor:
        case Op::Not:
        case Op::Neg:
            return collect_inputs(term->left, bits, inputs) &&
                   (!term->right || collect_inputs(term->right, bits, inputs));
        default:
            return false;
        }
    }

    std::optional<uint16_t> truth_table(const Term &term, const std::vector<Term> &inputs)
    {
        const uint64_t mask = width_mask(term->bits);
        z3::expr_vector symbols(session_.context);
        for (const Term &input : inputs)
        {
            symbols.push_back(program_.evaluate(input, state_));
        }

        const z3::expr original = program_.evaluate(term, state_);
        uint16_t table = 0;
        for (size_t assignment = 0; assignment < (size_t{1} << inputs.size()); ++assignment)
        {
            if (!session_.has_budget())
            {
                return {};
            }
            z3::expr_vector values(session_.context);
            for (size_t input = 0; input < inputs.size(); ++input)
            {
                const bool set = (assignment & (size_t{1} << input)) != 0;
                values.push_back(session_.context.bv_val(set ? mask : 0, term->bits));
            }
            z3::expr instantiated = original;
            instantiated = instantiated.substitute(symbols, values).simplify();
            uint64_t value = 0;
            if (!instantiated.is_numeral_u64(value) || (value != 0 && value != mask))
            {
                return {};
            }
            if (value != 0)
            {
                table |= uint16_t(uint16_t{1} << assignment);
            }
        }
        return table;
    }

    Term synthesize_table(uint16_t target, const std::vector<Term> &inputs, unsigned bits,
                          size_t maximum_cost)
    {
        using Entry = std::pair<uint16_t, Term>;
        const size_t assignments = size_t{1} << inputs.size();
        const uint16_t table_mask = uint16_t((uint32_t{1} << assignments) - 1);
        std::vector<std::vector<Entry>> layers(maximum_cost + 1);
        std::map<uint16_t, Term> best;
        auto offer = [&](uint16_t table, Term term, size_t term_cost)
        {
            const auto found = best.find(table);
            if (term_cost <= maximum_cost &&
                (found == best.end() || cost(found->second) > term_cost))
            {
                best[table] = term;
                layers[term_cost].emplace_back(table, std::move(term));
            }
        };
        offer(0, constant(0, bits), 0);
        offer(table_mask, constant(width_mask(bits), bits), 0);
        for (size_t input = 0; input < inputs.size(); ++input)
        {
            uint16_t table = 0;
            for (size_t assignment = 0; assignment < assignments; ++assignment)
            {
                if ((assignment & (size_t{1} << input)) != 0)
                {
                    table |= uint16_t(uint16_t{1} << assignment);
                }
            }
            offer(table, inputs[input], cost(inputs[input]));
        }

        size_t generated = 0;
        for (size_t level = 0; level <= maximum_cost; ++level)
        {
            if (!session_.has_budget())
            {
                return {};
            }
            if (level != 0)
            {
                for (const auto &[table, term] : layers[level - 1])
                {
                    offer(uint16_t(table ^ table_mask), expression(Op::Not, term), level);
                }
                for (size_t left_cost = 0; left_cost < level; ++left_cost)
                {
                    const size_t right_cost = level - left_cost - 1;
                    if (left_cost > right_cost)
                    {
                        continue;
                    }
                    for (const auto &[left_table, left] : layers[left_cost])
                    {
                        for (const auto &[right_table, right] : layers[right_cost])
                        {
                            if (generated > max_boolean_candidates - 3)
                            {
                                return {};
                            }
                            generated += 3;
                            if (generated % 64 == 0 && !session_.has_budget())
                            {
                                return {};
                            }
                            offer(left_table & right_table, expression(Op::And, left, right),
                                  level);
                            offer(left_table | right_table, expression(Op::Or, left, right), level);
                            offer(left_table ^ right_table, expression(Op::Xor, left, right),
                                  level);
                        }
                    }
                }
            }
            const auto found = best.find(target);
            if (found != best.end() && cost(found->second) <= level)
            {
                return found->second;
            }
        }
        return {};
    }

    Term simplify_boolean(const Term &term)
    {
        std::vector<Term> inputs;
        if (!collect_inputs(term, term->bits, inputs) || inputs.empty())
        {
            return {};
        }
        const auto table = truth_table(term, inputs);
        if (!table)
        {
            return {};
        }
        const size_t maximum = std::min(limits::replacement_operations, cost(term) - 1);
        Term candidate = synthesize_table(*table, inputs, term->bits, maximum);
        if (!candidate || cost(candidate) >= cost(term))
        {
            return {};
        }

        return prove(term, candidate) ? candidate : Term{};
    }

    Term simplify_cobra(const Term &term)
    {
        bool bitwise = false;
        std::function<void(const Term &)> classify = [&](const Term &node)
        {
            if (!node || node->bits != term->bits)
                return;
            bitwise |= node->op == Op::And || node->op == Op::Or || node->op == Op::Xor ||
                       node->op == Op::Not;
            classify(node->left);
            classify(node->right);
        };
        classify(term);
        if (!bitwise || !session_.has_budget())
            return {};
        auto &statistics = session_.statistics.cobra;
        const auto time = session_.now();
        const auto budget =
            cobra_backend::reserve_site(time, session_.deadline(), session_.remaining_budget(time));
        if (!budget.admitted)
        {
            ++statistics.exhausted;
            ++statistics.rejected;
            session_.statistics.cancel_stage = RejectReason::BudgetExhaustedPreFlight;
            return {};
        }
        cobra_backend::Request request;
        request.deadline = budget.candidate_deadline;
        request.profile = session_.options.profile;
        request.snapshot = session_.options.snapshot;
        request.cancelled = [&] { return session_.is_cancelled(); };
        request.now = [&] { return session_.now(); };
        const auto outcome = cobra_backend::generate(term, request);
        ++statistics.calls;
        statistics.generation_ns += outcome.elapsed_ns;
        statistics.extraction_ns += outcome.extraction_ns;
        statistics.invocation_ns += outcome.invocation_ns;
        statistics.reconstruction_ns += outcome.reconstruction_ns;
        statistics.cleanup_ns += outcome.cleanup_ns;
        statistics.admitted += outcome.admitted;
        statistics.rejected += !outcome.admitted;
        statistics.input_cost = outcome.input_cost;
        statistics.output_cost = outcome.output_cost;
        statistics.timings_complete = outcome.timings_complete;
        statistics.overshoot_ns = std::max(statistics.overshoot_ns, outcome.overshoot_ns);
        statistics.scratch_peak_bytes =
            std::max(statistics.scratch_peak_bytes, outcome.scratch_peak_bytes);
        statistics.raw_leaves = outcome.raw_leaves;
        statistics.input_nodes = outcome.input_nodes;
        statistics.output_nodes = outcome.output_nodes;
        statistics.raw_support = outcome.raw_support;
        statistics.canonical_support = outcome.canonical_support;
        statistics.raw_indices = outcome.raw_indices;
        statistics.spot_check = outcome.spot_check;
        statistics.last_generation_phase = outcome.last_phase;
        if (outcome.status == cobra_backend::Status::Exhausted)
            session_.statistics.cancel_stage = RejectReason::CobraGenerationExhausted;
        statistics.last_status = unsigned(outcome.status);
        statistics.last_reason = unsigned(outcome.reason);
        switch (outcome.status)
        {
        case cobra_backend::Status::Candidate:
            ++statistics.candidates;
            break;
        case cobra_backend::Status::Unchanged:
            ++statistics.unchanged;
            break;
        case cobra_backend::Status::Unsupported:
            ++statistics.unsupported;
            break;
        case cobra_backend::Status::Exhausted:
            ++statistics.exhausted;
            break;
        case cobra_backend::Status::Failure:
            ++statistics.failures;
            break;
        }
        if (outcome.status != cobra_backend::Status::Candidate || !session_.has_budget())
            return {};
        const auto proof_start = session_.now();
        const bool accepted = prove(term, outcome.candidate);
        statistics.candidate_proof_ns += static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(session_.now() - proof_start)
                .count());
        if (!accepted)
            return {};
        ++statistics.proved;
        statistics.proved_widths |= UINT64_C(1) << (term->bits / 8);
        cobra_origin_ = true;
        return outcome.candidate;
    }

    Term simplify_linear(const Term &term)
    {
        std::vector<Term> inputs;
        if (!collect_inputs(term, term->bits, inputs))
        {
            return {};
        }
        Term candidate = reconstruct_linear_mba(program_, state_, term, inputs);
        if (!candidate || cost(candidate) >= cost(term))
        {
            return {};
        }

        // Unlike the outer synthesis pass, this proof has no path assumptions.
        // Its result can therefore be composed inside later arithmetic and
        // bitwise expressions in the same immutable symbol context.
        return prove(term, candidate) ? candidate : Term{};
    }

    SymbolicProgram &program_;
    SolverSession &session_;
    const SymbolicState &state_;
    std::map<std::string, Term> rewritten_;
    std::set<std::string> linearized_;
    std::set<std::pair<unsigned, WordLaw>> word_laws_;
    size_t visited_ = 0;
    bool cobra_origin_ = false;
};
} // namespace

Term simplify_algebraic(SymbolicProgram &program, const SymbolicState &state, const Term &original,
                        bool *cobra_origin)
{
    AlgebraicSimplifier simplifier(program, state);
    Term result = simplifier.run(original);
    if (cobra_origin)
        *cobra_origin = simplifier.from_cobra();
    return result && cost(result) < cost(original) ? result : Term{};
}
} // namespace chernobog::mba_smt::detail
