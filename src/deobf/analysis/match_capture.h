#pragma once

#include "ast.h"
#include "mba_diagnostics.hpp"
#include <string>
#include <utility>
#include <vector>

namespace chernobog::ast
{

constexpr size_t match_capture_visit_limit = 512;
constexpr size_t match_capture_depth_limit = 64;
constexpr size_t match_prefix_head_limit = 64;
constexpr size_t catalog_capture_byte_limit = 32768;

// Capture the fields actually consulted by structural matching and strict
// operand comparison. Unsupported comparison payloads stay opaque. Owner
// identities are event-local tokens; host pointers and SDK objects never escape.
// Context contains a consecutive predecessor suffix before the enclosing top
// level instruction. A missing/broken anchor supplies no predecessor facts.
mba_diagnostics::CapturedInput capture_match_input(const AstPtr &candidate,
                                                   const minsn_t *anchor = nullptr,
                                                   const minsn_t *block_head = nullptr);

// Templates are the exact certified pattern roots, in registry traversal order.
// The snapshot includes the local SDK tags needed for independent replay.
std::string capture_catalog_patterns(const std::vector<std::pair<std::string, AstPtr>> &patterns,
                                     bool initialized);

} // namespace chernobog::ast
