/*
 * Kernel-less Hex-Rays dispatcher for the standalone MBA catalog test.
 *
 * chernobog_catalog_tests links only Chernobog's IDA-independent runtime, so
 * no decompiler exists behind HEXDSP. get_hexdsp() nevertheless returns a
 * non-null value in that state, and calling it transfers control to an address
 * derived from the call arguments. On macOS x86_64 that address lands in
 * __DATA_CONST and the instruction fetch raises SIGBUS:
 *
 *   KERN_PROTECTION_FAILURE at 0x108ba1a20  (trap 14, "invalid protections
 *   for user instruction read")
 *     0  vtable for chernobog::ast::AstNode + 16
 *     1  chernobog::ast::AstNode::~AstNode()
 *     2  chernobog::rules::RuleRegistry::rebuild_storage_locked()
 *
 * mop_t's own destructor calls the hexapi erase(), so destroying any AST node
 * was sufficient to reach it; the test previously survived only by retaining
 * every AST it built, which an exception unwind out of rule verification
 * defeats.
 *
 * Redirecting the dispatcher is the SDK's supported extension point -- the
 * IDAPython runtime does the same for get_idapython_hexdsp(). This header is
 * force-included into every translation unit of the test target so the whole
 * program agrees on one expansion of the inline SDK functions that use
 * HEXDSP; a per-header opt-in would give different translation units
 * different definitions of the same inline function.
 */
#pragma once

// Signature-compatible with the SDK's hexdsp_t, declared without including
// idp.hpp so this header stays ahead of every SDK include.
extern "C" void *chernobog_catalog_hexdsp(int code, ...);

#undef HEXDSP
#define HEXDSP chernobog_catalog_hexdsp
