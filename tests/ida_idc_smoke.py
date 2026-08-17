"""Batch smoke test for Chernobog's IDC orchestration surface.

Everything below is driven through IDA's IDC interpreter rather than the
IDAPython bindings, so a regression in the registered `chernobog_*` functions
fails here even when the underlying C++ still works. The caller may set
CHERNOBOG_SMOKE_EA to select the function; without it the first function of at
least 0x80 bytes is used.
"""

import os

import ida_auto
import ida_expr
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_pro


def finish(code, message):
    line = "[chernobog][idc-smoke] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


def evaluate(expression):
    """Evaluate one IDC expression and return its value."""
    result = ida_expr.idc_value_t()
    error = ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
    if error:
        finish(6, "IDC error in %s: %s" % (expression, error))
    if result.vtype == ida_expr.VT_STR:
        return result.c_str()
    if result.vtype == ida_expr.VT_INT64:
        return result.i64
    if result.vtype == ida_expr.VT_LONG:
        return result.num
    return result


def attribute(expression, name):
    """Read one attribute of an object-returning IDC function."""
    return evaluate("%s.%s" % (expression, name))


def require(condition, message):
    if not condition:
        finish(7, message)


def pick_function():
    raw = os.environ.get("CHERNOBOG_SMOKE_EA")
    if raw is not None:
        start = ida_funcs.get_func_start(int(raw, 0))
        if start == ida_idaapi.BADADDR:
            finish(5, "no function contains %s" % raw)
        return start
    # get_func_ea_by_num() enumerates entries only, so tails need no filter.
    for index in range(ida_funcs.get_func_qty()):
        entry = ida_funcs.get_func_ea_by_num(index)
        if entry == ida_idaapi.BADADDR:
            continue
        info = ida_funcs.func_entry_info_t()
        if not ida_funcs.get_func_entry_info(info, entry):
            continue
        if info.end_ea - info.start_ea >= 0x80:
            return info.start_ea
    finish(5, "no function of at least 0x80 bytes in the database")
    return ida_idaapi.BADADDR


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")

    plugin_path = os.environ.get(
        "CHERNOBOG_PLUGIN_PATH",
        os.path.expanduser("~/.idapro/plugins/chernobog.so"),
    )
    plugin = ida_loader.load_plugin(plugin_path)
    if plugin is None:
        finish(3, "plugin load failed: %s" % plugin_path)

    # Registration and introspection.
    version = evaluate("chernobog_version()")
    require(version.startswith("chernobog "), "unexpected version %r" % version)
    require(
        int(attribute("chernobog_status()", "loaded")) == 1,
        "no IDC host is bound to this database",
    )
    require(
        int(attribute("chernobog_status()", "hexrays")) == 1,
        "the Hex-Rays lifecycle is not installed",
    )
    functions = int(attribute("chernobog_status()", "idc_functions"))
    require(functions > 0, "no IDC functions are registered")
    require(
        len(evaluate("chernobog_help()").splitlines()) > functions,
        "chernobog_help() does not describe every function",
    )

    # Options: aliases, verbatim variables, numbers, and clearing.
    require(
        int(evaluate('chernobog_set_option("no_such_option", "1")')) == 0,
        "an unknown option was accepted",
    )
    require(
        int(evaluate('chernobog_set_option("rax_runs", 3)')) == 1,
        "a numeric option value was rejected",
    )
    require(
        evaluate('chernobog_get_option("rax_runs")') == "3",
        "a numeric option value did not round-trip as text",
    )
    require(
        int(attribute("chernobog_status()", "rax_runs")) == 3,
        "a numeric option value did not take effect",
    )
    require(
        int(evaluate('chernobog_set_option("CHERNOBOG_RAX_EXPLORE_RUNS", "")'))
        == 1,
        "an option could not be cleared through its variable name",
    )
    evaluate('chernobog_set_option("auto", 1)')
    require(
        int(attribute("chernobog_status()", "auto_mode")) == 1,
        "auto mode did not take effect immediately",
    )
    evaluate('chernobog_set_option("auto", 0)')
    require(
        int(attribute("chernobog_status()", "auto_mode")) == 0,
        "auto mode could not be turned back off",
    )

    function_start = pick_function()
    target = "0x%X" % function_start
    ida_kernwin.msg("[chernobog][idc-smoke] target %s\n" % target)

    # Analysis. Every object result must expose its full attribute set even on
    # the failure path, so a script can read fields unconditionally.
    detect = "chernobog_detect(%s)" % target
    require(int(attribute(detect, "ok")) == 1, "chernobog_detect() failed")
    mask = int(attribute(detect, "mask"))
    names = evaluate("chernobog_obf_names(%d)" % mask)
    require(
        (mask == 0) == (names == ""),
        "obfuscation names disagree with mask 0x%X" % mask,
    )
    bad = "chernobog_detect(-1)"
    require(int(attribute(bad, "ok")) == 0, "detect accepted a bad address")
    require(attribute(bad, "error") != "", "a failed detect carries no reason")
    require(int(attribute(bad, "mask")) == 0, "a failed detect carries a mask")

    flatten = "chernobog_detect_flatten(%s)" % target
    require(int(attribute(flatten, "ok")) == 1, "flatten detection failed")
    attribute(flatten, "confidence_score")
    attribute("chernobog_detect_flatten(-1)", "confidence_score")

    require(int(evaluate("chernobog_analyze(%s)" % target)) == 1,
            "chernobog_analyze() failed")

    # Admission tracking.
    require(int(evaluate("chernobog_request(%s)" % target)) == 1,
            "chernobog_request() failed")
    require(int(evaluate("chernobog_enabled_for(%s)" % target)) == 1,
            "an explicitly requested function is not admitted")

    # rax exploration is bounded and synchronous; a disabled or unavailable
    # engine is a valid outcome, an interpreter-level failure is not.
    explore = int(evaluate("chernobog_rax_explore(%s)" % target))
    name = evaluate("chernobog_rax_result_name(%d)" % explore)
    require(name != "unknown", "unknown rax result code %d" % explore)
    ida_kernwin.msg("[chernobog][idc-smoke] rax %s\n" % name)
    summary = "chernobog_rax_summary(%s)" % target
    attribute(summary, "available")
    attribute(summary, "completed_runs")
    attribute(summary, "decoder_disagreements")
    strings = int(evaluate("chernobog_rax_string_count(%s)" % target))
    require(strings >= 0, "negative runtime string count")
    out_of_range = "chernobog_rax_string(%s, 100000)" % target
    require(int(attribute(out_of_range, "ok")) == 0,
            "an out-of-range string index reported success")
    require(attribute(out_of_range, "value") == "",
            "an out-of-range string index returned a value")
    attribute("chernobog_rax_target(%s, %s, 0)" % (target, target), "ok")
    attribute("chernobog_rax_branch(%s, %s, 1)" % (target, target), "veto")
    require(int(evaluate("chernobog_rax_show()")) == 1,
            "chernobog_rax_show() failed")

    # Native passes report whether they ran; both are opt-in and default off.
    attribute("chernobog_hikari_cfg()", "patched_dispatchers")
    attribute("chernobog_native_opaque()", "predicates_proved")
    attribute("chernobog_native_analysis()", "redundant_prefixes")
    attribute("chernobog_early_stats()", "flowchart_edges")

    # Rule registry.
    rules = int(evaluate("chernobog_rule_count()"))
    require(rules > 0, "no MBA rules are registered")
    first = evaluate("chernobog_rule_name(0)")
    require(first != "", "the first rule has no name")
    require(int(evaluate('chernobog_rule_hits("%s")' % first)) >= 0,
            "a registered rule has no hit counter")
    require(int(evaluate('chernobog_rule_hits("no_such_rule")')) == -1,
            "an unknown rule name did not report -1")
    require(int(attribute("chernobog_rule_stats()", "rules")) == rules,
            "rule registry statistics disagree with the rule count")

    # Transformation and text extraction.
    require(int(evaluate("chernobog_deobfuscate(%s)" % target)) == 1,
            "chernobog_deobfuscate() failed")
    text = evaluate("chernobog_deobfuscate_text(%s)" % target)
    require(len(text) > 0, "chernobog_deobfuscate_text() returned no text")
    require(len(evaluate("chernobog_decompile(%s)" % target)) > 0,
            "chernobog_decompile() returned no text")

    sweep = "chernobog_deobfuscate_range(%s, %s + 1)" % (target, target)
    require(int(attribute(sweep, "processed")) == 1,
            "a single-function sweep did not process its function")

    require(int(evaluate("chernobog_clear_function(%s)" % target)) == 1,
            "chernobog_clear_function() failed")
    require(int(evaluate("chernobog_clear_all()")) == 1,
            "chernobog_clear_all() failed")
    require(int(evaluate("chernobog_clear_cache()")) == 1,
            "chernobog_clear_cache() failed")

    finish(0, "PASS function=0x%X idc_functions=%d rules=%d"
           % (function_start, functions, rules))
except BaseException as error:  # IDAPython must convert every failure to qexit.
    finish(9, "exception: %r" % (error,))
