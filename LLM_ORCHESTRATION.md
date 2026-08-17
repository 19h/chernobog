# Orchestrating Chernobog from IDAPython

This document is written for an LLM agent driving Chernobog inside a running
IDA instance. Everything below was executed against IDA 9.4 with the plugin
loaded; the code is meant to be pasted and run, not adapted.

Chernobog exposes its full capability surface as `chernobog_*` functions in
IDA's **IDC** interpreter. There is no Python binding for them. The supported
route from IDAPython is to build an IDC expression string and evaluate it. That
is a stable, documented IDA mechanism, not a workaround.

## Preconditions

1. A database is open. Every function is registered `EXTFUN_BASE` and refuses
   to run without one.
2. `ida_auto.auto_wait()` has completed. Before autoanalysis finishes, the
   database has almost no functions and detection results are meaningless.
3. The plugin is loaded for **this** database. It loads automatically from the
   plugins directory; `ida_loader.load_plugin(path)` forces it. On success the
   Output window shows `[chernobog] N IDC functions registered`.
4. Hex-Rays is available. Analysis and transformation entry points need it;
   `chernobog_status()["hexrays"]` reports whether the lifecycle is installed,
   and `chernobog_activate()` retries installation.

```python
import ida_auto, ida_hexrays, ida_loader

ida_auto.auto_wait()
ida_hexrays.init_hexrays_plugin()
ida_loader.load_plugin("/path/to/chernobog.so")   # no-op if already loaded
```

## The bridge

Two evaluation mechanisms exist. Their difference matters:

| Mechanism | Returns | Use it for |
|---|---|---|
| `idc.eval_idc(expr)` | `int` or `str` | scalar results, or one attribute of an object result |
| `ida_expr.eval_idc_expr(rv, ea, expr)` | fills an `idc_value_t` | everything, including whole objects |

`idc.eval_idc` **raises `NotImplementedError`** when the expression returns an
object, and it reports interpreter failures by returning the string
`"IDC_FAILURE: ..."` rather than raising. Both behaviours are easy to miss, so
prefer the helper below, which normalises them.

## The helper

Paste this once per session. It converts every Chernobog result into a plain
Python value — object results become a `dict` of all their attributes — and
turns interpreter failures into an exception.

```python
import ida_expr
import ida_idaapi

_MASK64 = 0xFFFFFFFFFFFFFFFF


class ChernobogError(RuntimeError):
    """An IDC-level failure: bad expression, missing function, or bad type."""


def _decode(value):
    if value.vtype == ida_expr.VT_STR:
        return value.c_str()
    if value.vtype == ida_expr.VT_INT64:
        return value.i64
    if value.vtype == ida_expr.VT_OBJ:
        fields = {}
        name = ida_expr.first_idcv_attr(value)
        while name:
            slot = ida_expr.idc_value_t()
            if ida_expr.get_idcv_attr(slot, value, name) == 0:
                fields[name] = _decode(slot)
            name = ida_expr.next_idcv_attr(value, name)
        return fields
    return value.num


def _literal(argument):
    if isinstance(argument, bool):
        return "1" if argument else "0"
    if isinstance(argument, int):
        if argument < 0:
            return "-0x%X" % (-argument)
        return "0x%X" % (argument & _MASK64)
    if isinstance(argument, str):
        escaped = argument.replace("\\", "\\\\").replace('"', '\\"')
        if "\n" in escaped or "\r" in escaped or "\0" in escaped:
            raise ChernobogError("control characters cannot be passed in IDC")
        return '"%s"' % escaped
    raise ChernobogError("unsupported argument type %r" % type(argument))


def call(function, *arguments):
    """Call one chernobog_* IDC function and return a Python value.

    Numbers come back as int, strings as str, and object results as a dict of
    every attribute. Raises ChernobogError when the interpreter itself fails.
    """
    expression = "%s(%s)" % (
        function, ", ".join(_literal(a) for a in arguments))
    result = ida_expr.idc_value_t()
    error = ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
    if error:
        raise ChernobogError("%s: %s" % (expression, error))
    return _decode(result)
```

Usage:

```python
call("chernobog_version")                       # -> 'chernobog 3abf0eb3e14e ...'
call("chernobog_status")["rule_count"]          # -> 108
call("chernobog_detect", 0x1576)["names"]       # -> 'substitution'
call("chernobog_set_option", "rax_runs", 6)     # -> 1
```

## Argument encoding

The helper handles all of this; the rules matter if you build expressions
yourself.

| Python value | IDC literal | Notes |
|---|---|---|
| `int` address | `0x1576` | any address **inside** a function is accepted; the containing function is used |
| `ida_idaapi.BADADDR` | `0xFFFFFFFFFFFFFFFF` | parses to the same bit pattern as `-1`; both are handled |
| `bool` | `1` / `0` | |
| `str` | `"..."` | escape `\` and `"`; newlines and NUL cannot be passed |

Option **values** are the one place where numbers keep their type instead of
being converted: `chernobog_set_option("rax_runs", 4)` sets `4`. Do not rely on
IDC's own number-to-string conversion anywhere else — it produces the
*character* with that code, not the digits.

## Return values

Failure is always a return value, never an IDC exception:

- numeric entry points return `0`, or `-1` where `0` is a valid answer;
- string entry points return `""`;
- object entry points **always carry their complete attribute set**, including
  on failure paths, and flag the outcome with `ok` or `available`.

That last rule is deliberate: `call("chernobog_detect", bad_ea)["mask"]` is
safe and returns `0`. You never need to guard an attribute read.

Addresses inside objects are signed 64-bit values, so `BADADDR` reads back as
`-1`. Normalise with `ea & 0xFFFFFFFFFFFFFFFF` when you need the unsigned form.

## Function reference

Result shapes below list the attributes an object result carries. Use
`call("chernobog_help")` for the authoritative in-build list, and inspect the
returned dict directly when you need the exact attribute set of this build.

### Introspection and lifecycle

| Call | Result |
|---|---|
| `chernobog_help()` | `str` — every function with a one-line description |
| `chernobog_version()` | `str` — revision, source fingerprint, SDK, pinned rax revision |
| `chernobog_status()` | dict: `loaded`, `hexrays`, `components`, `component_count`, `auto_mode`, `disabled`, `verbose`, `database_id`, `rax_enabled`, `rax_available`, `rax_unavailable_reason`, `rax_runs`, `rax_max_insns`, `rax_timeout_ms`, `rax_log_level`, `hikari_cfg_mode`, `native_opaque_mode`, `rule_count`, `pattern_count`, `arm64`, `x86_64`, `idc_functions`, `revision`, `dirty`, `source`, `sdk`, `rax_revision` |
| `chernobog_activate()` | `1` once the Hex-Rays lifecycle is installed |

`status["auto_mode"]` is *not* named `auto`: `auto` is an IDC keyword and
`status.auto` does not parse.

### Options

| Call | Result |
|---|---|
| `chernobog_get_option(name)` | `str`, `""` when unset or unknown |
| `chernobog_set_option(name, value)` | `1` on success, `0` for an unknown name |
| `chernobog_list_options()` | `str` — alias, variable, current value, description |

`name` is either a short alias (`"rax_runs"`) or the variable itself
(`"CHERNOBOG_RAX_EXPLORE_RUNS"`); any `CHERNOBOG_`-prefixed variable is
accepted, so options added after this document still work. Setting `""` clears
a value. Options are process-wide and are read when each operation starts, so a
change applies to the next call. `auto` and `verbose` are cached at startup and
are re-applied immediately.

### Analysis (read-only)

| Call | Result |
|---|---|
| `chernobog_detect(ea)` | dict: `ok`, `error`, `ea`, `mask`, `names`, `any`, plus one flag per obfuscation: `flattened`, `bogus_cf`, `string_enc`, `const_enc`, `indirect_br`, `substitution`, `split_blocks`, `func_wrapper`, `identity_call`, `stack_string`, `savedregs`, `objc_obfusc`, `global_const`, `ptr_indirect`, `mba_complex`, `chain_ops`, `opaque_jump`, `const_obfusc`, `indirect_call`, `vm_mba`, `select_chain` |
| `chernobog_obf_names(mask)` | `str` — comma-separated names for a mask |
| `chernobog_detect_flatten(ea)` | dict: `ok`, `error`, `ea`, `detected`, `kind`, `dispatcher_block`, `switch_block`, `loop_entry_block`, `loop_end_block`, `case_count`, `returning_target_count`, `direct_return_target_count`, `return_frontier_count`, `dispatcher_block_count`, `state_count`, `confidence_score` |
| `chernobog_analyze(ea)` | `1`, and prints the candidate report to the Output window |

`chernobog_detect` and `chernobog_detect_flatten` generate uncached
`MMAT_LOCOPT` microcode with no mutation components enabled and add nothing to
the decompiler cache. They are the correct tools for surveying a database.

Detection flags are **structural candidates**, not transformation counts. A
candidate for which no guarded rewrite matches produces no changes; do not
report a detection as a removed obfuscation.

### Transformation

| Call | Result |
|---|---|
| `chernobog_deobfuscate(ea)` | `1` — the `Ctrl+Shift+D` action |
| `chernobog_deobfuscate_text(ea)` | `str` — admit, re-decompile uncached, return pseudocode |
| `chernobog_decompile(ea)` | `str` — pseudocode without forcing a new pass |
| `chernobog_deobfuscate_range(start, end)` | dict: `ok`, `start`, `end`, `considered`, `processed`, `cancelled` |
| `chernobog_deobfuscate_all()` | same shape, whole database |

`chernobog_deobfuscate_text` is the single-call primitive: it admits the
function, drops its tracking so the optimizer pipeline runs again, decompiles
with `DECOMP_NO_CACHE`, and returns the text. Prefer it over composing the
steps yourself.

### Admission and tracking

| Call | Result |
|---|---|
| `chernobog_request(ea)` | `1` — admit a function for its next decompilation |
| `chernobog_enabled_for(ea)` | `1` when auto mode or a request admits it |
| `chernobog_pending(ea)` | `1` when the LOCOPT pipeline has not completed |
| `chernobog_clear_function(ea)` | `1` — drop per-function tracking and rax evidence |
| `chernobog_clear_all()` | `1` — drop every cache for this database |
| `chernobog_clear_cache()` | `1` — clear the Hex-Rays decompiler cache |

Without auto mode, Chernobog only transforms functions that were explicitly
admitted. `chernobog_request` admits one without decompiling it now, which is
how you stage work before an unrelated decompilation.

### Native pre-Hex-Rays passes

| Call | Result |
|---|---|
| `chernobog_hikari_cfg()` | dict: `ran`, `mode`, `root_state_slots`, `terminal_indirect_branches`, `recovered_dispatchers`, `patched_dispatchers`, `reachable_functions` |
| `chernobog_native_opaque()` | dict: `ran`, `mode`, `functions_scanned`, `blocks_scanned`, `conditional_branches`, `predicates_proved`, `branches_patched` |
| `chernobog_native_analysis()` | dict: `ran`, `enabled`, `redundant_prefixes`, `get_pc_gadgets`, `push_return_targets`, `zero_register_branches`, `opposite_branch_pairs`, `entry_predicates`, `known_flag_branches`, `indirect_targets`, `gaps_retyped`, `get_pc_tail_extensions`, `orphan_functions`, `outlined_wrappers`, `post_scan_heads`, `post_scan_functions`, `post_scan_truncated` |
| `chernobog_early_stats()` | dict: `available`, `enabled`, `flowchart_edges`, `codegen_returns`, `generated_gotos`, `folded_instructions`, `character_operands`, `bounded_skips` |

`chernobog_hikari_cfg` and `chernobog_native_opaque` are ARM64-only and
**opt-in**: they report `ran == 0` until `hikari_cfg` / `native_opaque` is set.
Both mutate the IDB (xrefs, comments, and at tier 2 reversible instruction
patches). They are whole-database scans, so call them once, not per function.

### rax exploratory emulation

| Call | Result |
|---|---|
| `chernobog_rax_explore(ea)` | `int` code: `0` already_fresh, `1` explored, `2` disabled, `3` unavailable, `4` cancelled, `5` failed |
| `chernobog_rax_result_name(code)` | `str` name for that code |
| `chernobog_rax_fresh(ea)` | `1` when exact evidence is still current |
| `chernobog_rax_summary(ea)` | dict: `available`, `fresh`, `ea`, `generation`, `function_hash`, `image_hash`, `focus`, `arch`, `name`, `objc_selector`, `explicit_arguments`, `explicit_arguments_known`, `inputs`, `runs`, `branches`, `indirect_observations`, `diagnostic`, plus every `EvidenceSummary` counter (`completed_runs`, `returned_runs`, `timeout_runs`, `conditional_observations`, `indirect_targets`, `image_reads`, `decoder_disagreements`, …) |
| `chernobog_rax_string_count(ea)` / `chernobog_rax_string(ea, i)` | count, then dict: `ok`, `address`, `value`, `length`, `observations`, `eligible_runs` |
| `chernobog_rax_target_count(ea, insn)` / `chernobog_rax_target(ea, insn, i)` | count, then dict: `ok`, `target`, `kind`, `observations`, `runs` |
| `chernobog_rax_branch(ea, insn, taken)` | dict: `available`, `current`, `generation`, `veto`, `verdict`, `verdict_name`, `matching`, `opposing`, `opposing_context_complete`, `other` |
| `chernobog_rax_show()` | `1`, prints the full evidence report |
| `chernobog_rax_cancel()` / `chernobog_rax_clear()` | `1` |

`chernobog_rax_explore` is **synchronous and bounded**. It reuses exact fresh
evidence, waits for a matching in-flight job, or explores only that function.
It never sweeps the database and never recurses into callees. Do not poll it,
do not run it in a loop waiting for a state change, and do not call it from a
background thread.

The session holds evidence for **one function at a time**. `rax_summary` for
any other function reports `available == 0`; explore the function you want
first.

### MBA rule registry

| Call | Result |
|---|---|
| `chernobog_rule_stats()` | dict: `initialized`, `rules`, `patterns`, `verified`, `rejected`, `total_matches`, `successful_matches` |
| `chernobog_rule_count()` / `chernobog_rule_name(i)` | count, then name |
| `chernobog_rule_hits(name)` | hit count, `-1` for an unknown name |
| `chernobog_rule_reset_stats()` | `1` |

## Recipes

### Survey a database without changing it

`get_func_ea_by_num` enumerates function entries; `getn_func` is deprecated in
IDA 9.4.

```python
import ida_funcs

candidates = []
for index in range(ida_funcs.get_func_qty()):
    entry = ida_funcs.get_func_ea_by_num(index)
    if entry == ida_idaapi.BADADDR:
        continue
    detection = call("chernobog_detect", entry)
    if detection["ok"] and detection["any"]:
        candidates.append((entry, detection["names"]))
```

### Deobfuscate one function and read the result

```python
detection = call("chernobog_detect", ea)
if detection["flattened"]:
    flatten = call("chernobog_detect_flatten", ea)
    print("dispatcher block %d, %d cases, score %d"
          % (flatten["dispatcher_block"], flatten["case_count"],
             flatten["confidence_score"]))

text = call("chernobog_deobfuscate_text", ea)   # admits, re-runs, decompiles
```

### Drive rax and read its evidence

```python
code = call("chernobog_rax_explore", ea)
if code in (0, 1):                              # already_fresh or explored
    summary = call("chernobog_rax_summary", ea)
    print("%s: %d runs, %d branch observations"
          % (summary["arch"], summary["completed_runs"],
             summary["conditional_observations"]))
    for i in range(call("chernobog_rax_string_count", ea)):
        witness = call("chernobog_rax_string", ea, i)
        print("0x%X %r seen in %d of %d runs"
              % (witness["address"] & 0xFFFFFFFFFFFFFFFF, witness["value"],
                 witness["observations"], witness["eligible_runs"]))
else:
    print("no evidence: %s" % call("chernobog_rax_result_name", code))
```

### Configure a run

```python
call("chernobog_set_option", "rax_runs", 8)         # more concrete runs
call("chernobog_set_option", "rax_timeout_ms", 2000)
call("chernobog_set_option", "vm", 1)               # opt-in VM-family handlers
call("chernobog_set_option", "auto", False)         # keep transformation explicit
print(call("chernobog_list_options"))               # everything, with values
```

### Push a hot loop into IDC

Each `call()` is an interpreter round trip. For a whole-database loop, compile
an IDC helper once and call it once. This is only worth doing for large
databases.

```python
import ida_expr

source = ("static _cb_count() { auto ea, n; n = 0;"
          " for (ea = get_next_func(0); ea != BADADDR; ea = get_next_func(ea))"
          " if (chernobog_detect(ea).any) n = n + 1; return n; }")
assert ida_expr.compile_idc_text(source) is None
total = call("_cb_count")
```

## Cost and side effects

Classify before you call. This is the part an agent most often gets wrong.

| Operation | Cost | Touches the IDB? |
|---|---|---|
| `status`, `version`, options, rule registry | negligible | no |
| `detect`, `detect_flatten` | one uncached microcode build per function | no |
| `decompile`, `analyze` | one decompilation | no |
| `rax_explore` | bounded emulation of one function (`rax_runs` × `rax_timeout_ms`) | yes, if `rax_apply_analysis` is on (default) |
| `deobfuscate`, `deobfuscate_text` | one uncached decompilation plus the pass pipeline | yes — may patch bytes and rewrite the ctree |
| `deobfuscate_range`, `deobfuscate_all` | the above, per function | yes |
| `hikari_cfg`, `native_opaque`, `native_analysis` | whole-database scan | yes — xrefs, comments, reversible patches |

`deobfuscate_all` on a large database is the most expensive call available.
Survey with `detect` first and transform only the candidates. Both sweeps
honour IDA's cancel request and report `cancelled`.

Byte-level changes go through IDA's patch database, so they are reversible and
the input file is never modified.

## Pitfalls

Each of these was observed in practice:

1. **`status.auto` does not parse.** `auto` is an IDC keyword; the attribute is
   `auto_mode`.
2. **`idc.eval_idc` raises `NotImplementedError` for object results.** Use the
   helper, or read a single attribute: `idc.eval_idc("chernobog_status().hexrays")`.
3. **`idc.eval_idc` returns `"IDC_FAILURE: ..."` instead of raising.** A typo'd
   function name yields a string that looks like a result. Check for the prefix
   or use the helper.
4. **`ida_expr.print_idcv` raises `UnicodeDecodeError`** on these objects: its
   numeric dump embeds raw bytes. Enumerate attributes instead.
5. **Skipping `auto_wait()`** yields a database with almost no functions;
   detection then reports nothing and looks like a Chernobog failure.
6. **Addresses in object results are signed.** `BADADDR` reads back as `-1`.
7. **Numbers passed where IDC converts to string become characters.** This
   affects hand-built expressions, not `chernobog_set_option`, whose value
   argument is deliberately unconverted.
8. **Every call resolves the plugin instance for IDA's current database.** With
   several IDBs open, a script always drives the one it runs in; there is no
   way to address another.
9. **rax evidence is a cross-run concrete witness, not a proof.** Runtime
   strings and indirect targets are values that were observed, and repeated
   runs cannot establish that no other value exists. There is deliberately no
   "unique target" entry point — do not present these as exhaustive.
10. **Detection is not transformation.** Report `processed` counts and applied
    changes, not detection flags, when describing what was actually done.

## Related documents

- [`README.md`](README.md) — the IDC surface, its conventions, and the plugin
  as a whole
- [`RAX_HYBRID.md`](RAX_HYBRID.md) — evidence strength, the execution model,
  and every `CHERNOBOG_RAX_*` option
- [`idc/chernobog_report.idc`](idc/chernobog_report.idc) — the same
  orchestration written directly in IDC
- [`tests/ida_idc_smoke.py`](tests/ida_idc_smoke.py) — a worked IDAPython
  client that exercises the whole surface
