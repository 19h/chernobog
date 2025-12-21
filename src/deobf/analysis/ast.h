#pragma once
#include "../deobf_types.h"
#include <memory>
#include <vector>
#include <map>
#include <string>

//--------------------------------------------------------------------------
// AST (Abstract Syntax Tree) System for Pattern-Based Deobfuscation
//
// This system provides:
//   - Tree representation of microcode expressions
//   - Hierarchical signature generation for efficient pattern matching
//   - Freezing mechanism for immutable pattern templates
//   - Pattern variable binding (x_0, x_1, etc.)
//
// Ported from d810-ng's ast.py with C++ optimizations
//--------------------------------------------------------------------------

namespace chernobog {
namespace ast {

// Forward declarations
class AstBase;
class AstNode;
class AstLeaf;
class AstConstant;

using AstPtr = std::shared_ptr<AstBase>;
using AstNodePtr = std::shared_ptr<AstNode>;
using AstLeafPtr = std::shared_ptr<AstLeaf>;
using AstConstPtr = std::shared_ptr<AstConstant>;

//--------------------------------------------------------------------------
// Opcodes that can be converted to AST (MBA-related)
//--------------------------------------------------------------------------
bool is_mba_opcode(mcode_t op);

//--------------------------------------------------------------------------
// AstBase - Abstract base class for all AST nodes
//--------------------------------------------------------------------------
class AstBase : public std::enable_shared_from_this<AstBase> {
public:
    // Virtual destructor that safely clears mop_t before destruction.
    // This is critical because mop_t's destructor may call IDA functions
    // that are unavailable during static destruction (after IDA unloads).
    virtual ~AstBase() {
        mop.erase();
    }

    // Type checking
    virtual bool is_node() const = 0;
    virtual bool is_leaf() const = 0;
    virtual bool is_constant() const { return false; }

    // Deep copy
    virtual AstPtr clone() const = 0;

    // Signature generation for pattern matching
    // Returns vector like ["10"] (opcode), ["L"] (leaf), ["C"] (constant), ["N"] (none)
    virtual std::vector<std::string> get_depth_signature(int depth) const = 0;

    // Equality check (structural)
    virtual bool equals(const AstBase& other) const = 0;

    // Debug string representation
    virtual std::string to_string() const = 0;

    // Metadata from microcode
    int ast_index = -1;         // Unique index in builder context
    int dest_size = 0;          // Size in bytes (1,2,4,8)
    ea_t ea = BADADDR;          // Address in binary
    mop_t mop;                  // Original microcode operand

    // Immutability for cached templates
    bool frozen = false;

    void freeze();
    bool is_frozen() const { return frozen; }

    // Get mutable copy if frozen
    AstPtr ensure_mutable();

protected:
    AstBase() = default;
    AstBase(const AstBase& other);
};

//--------------------------------------------------------------------------
// AstNode - Binary or unary operation node
//--------------------------------------------------------------------------
class AstNode : public AstBase {
public:
    mcode_t opcode;             // Operation (m_add, m_sub, m_xor, etc.)
    AstPtr left;                // Left operand (always present)
    AstPtr right;               // Right operand (nullptr for unary ops)
    mop_t dst_mop;              // Destination operand

    // Constructors
    AstNode(mcode_t op, AstPtr l, AstPtr r = nullptr);
    AstNode(const AstNode& other);

    // Destructor - clear dst_mop before destruction
    ~AstNode() override {
        dst_mop.erase();
    }

    // Type checking
    bool is_node() const override { return true; }
    bool is_leaf() const override { return false; }
    bool is_unary() const { return right == nullptr; }
    bool is_binary() const { return right != nullptr; }

    // Deep copy
    AstPtr clone() const override;

    // Signature generation
    std::vector<std::string> get_depth_signature(int depth) const override;

    // Equality
    bool equals(const AstBase& other) const override;

    // Debug
    std::string to_string() const override;

    //----------------------------------------------------------------------
    // Pattern matching operations
    //----------------------------------------------------------------------

    // Match this pattern against a candidate AST and copy operand references
    // Returns true if structure matches
    bool check_pattern_and_copy_mops(AstPtr candidate);

    // Get all leaf nodes in this subtree
    std::vector<AstLeafPtr> get_leaf_list() const;

    // Get leaves indexed by their variable names
    std::map<std::string, AstLeafPtr> get_leafs_by_name() const;

    // Reset all mop references (before pattern matching)
    void reset_mops();

private:
    // Internal pattern matching helper
    bool copy_mops_from_ast(AstPtr other);

    // Verify that same-named variables have equal mops
    bool check_implicit_equalities() const;

    // Collect leaves recursively
    void collect_leaves(std::vector<AstLeafPtr>& out) const;
};

//--------------------------------------------------------------------------
// AstLeaf - Variable or register leaf node
//--------------------------------------------------------------------------
class AstLeaf : public AstBase {
public:
    std::string name;           // Variable name ("x_0", "x_1", etc.)

    // Constructors
    explicit AstLeaf(const std::string& n);
    explicit AstLeaf(const mop_t& m);  // From microcode operand
    AstLeaf(const AstLeaf& other);

    // Type checking
    bool is_node() const override { return false; }
    bool is_leaf() const override { return true; }

    // Deep copy
    AstPtr clone() const override;

    // Signature - returns ["L"] for variable leaf
    std::vector<std::string> get_depth_signature(int depth) const override;

    // Equality
    bool equals(const AstBase& other) const override;

    // Debug
    std::string to_string() const override;

    // Generate a name from microcode operand
    static std::string name_from_mop(const mop_t& m);
};

//--------------------------------------------------------------------------
// AstConstant - Constant value leaf node
//--------------------------------------------------------------------------
class AstConstant : public AstLeaf {
public:
    uint64_t value;             // Constant value
    std::string const_name;     // Named constant (e.g., "c_minus_2")

    // Constructors
    AstConstant(uint64_t v, int size);
    AstConstant(const std::string& name, uint64_t v);
    AstConstant(const AstConstant& other);

    // Type checking
    bool is_constant() const override { return true; }

    // Deep copy
    AstPtr clone() const override;

    // Signature - returns ["C"] for constant
    std::vector<std::string> get_depth_signature(int depth) const override;

    // Equality
    bool equals(const AstBase& other) const override;

    // Debug
    std::string to_string() const override;
};

//--------------------------------------------------------------------------
// Helper functions for creating AST nodes (for rule definitions)
//--------------------------------------------------------------------------

// Create a variable leaf node
inline AstPtr make_leaf(const std::string& name) {
    return std::make_shared<AstLeaf>(name);
}

// Create a constant leaf node
inline AstPtr make_const(uint64_t value, int size = 8) {
    return std::make_shared<AstConstant>(value, size);
}

// Create a named constant (for pattern matching with validation)
inline AstPtr make_named_const(const std::string& name, uint64_t value = 0) {
    return std::make_shared<AstConstant>(name, value);
}

// Create a binary operation node
inline AstPtr make_node(mcode_t op, AstPtr left, AstPtr right) {
    return std::make_shared<AstNode>(op, left, right);
}

// Create a unary operation node
inline AstPtr make_unary(mcode_t op, AstPtr operand) {
    return std::make_shared<AstNode>(op, operand, nullptr);
}

//--------------------------------------------------------------------------
// Utility functions
//--------------------------------------------------------------------------

// Get opcode name for debugging
const char* opcode_name(mcode_t op);

// Check if two mops are equal (ignoring size differences)
bool mops_equal_ignore_size(const mop_t& a, const mop_t& b);

// Size mask for given byte size
uint64_t size_mask(int size);

// Two's complement table for subtraction patterns
uint64_t twos_complement_sub_value(int size);

} // namespace ast
} // namespace chernobog
