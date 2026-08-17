//
// chernobog_report.idc -- orchestrate Chernobog from IDC.
//
// Surveys every function in the database with Chernobog's analysis-only
// detectors, then deobfuscates and re-decompiles the functions that look
// obfuscated, optionally exploring each one with rax first.
//
// Run it with  File > Script file...  , or in batch:
//
//     idat -A -c -S"chernobog_report.idc" <target>
//
// Configure it with environment variables, read here through the same option
// reader Chernobog itself uses:
//
//   CHERNOBOG_REPORT_MAX      how many obfuscated functions to transform (10)
//   CHERNOBOG_REPORT_RAX      1 to explore each candidate with rax first
//   CHERNOBOG_REPORT_TEXT     1 to print the resulting pseudocode
//
#include <idc.idc>

static setup()
{
    // Analysis-only detection needs no options at all; these only affect the
    // transformation phase below. Every one of them is also an environment
    // variable, so a batch caller can set them outside IDA instead.
    chernobog_set_option("rax_runs", 4);
    chernobog_set_option("rax_timeout_ms", 1000);
}

static describe_status()
{
    auto status;
    status = chernobog_status();
    msg("%s\n", chernobog_version());
    msg("  hexrays=%d components=%d auto=%d verbose=%d\n",
        status.hexrays, status.components, status.auto_mode, status.verbose);
    msg("  rax enabled=%d available=%d runs=%d timeout=%dms\n",
        status.rax_enabled, status.rax_available, status.rax_runs,
        status.rax_timeout_ms);
    msg("  rules=%d patterns=%d hikari_cfg=%d native_opaque=%d\n",
        status.rule_count, status.pattern_count, status.hikari_cfg_mode,
        status.native_opaque_mode);
    return status.hexrays;
}

// Print the rax witnesses Chernobog gathered for one function. These are
// cross-run concrete observations, not universal claims.
static show_rax_evidence(ea)
{
    auto summary, count, i, witness;

    summary = chernobog_rax_summary(ea);
    if (!summary.available)
        return 0;

    msg("      rax %s: %d runs, %d branch observations, %d indirect targets\n",
        summary.arch, summary.completed_runs, summary.conditional_observations,
        summary.indirect_targets);
    if (summary.decoder_disagreements > 0)
        msg("      rax decoder disagreements: %d of %d comparisons\n",
            summary.decoder_disagreements, summary.decoder_comparisons);

    count = chernobog_rax_string_count(ea);
    for (i = 0; i < count; i = i + 1)
    {
        witness = chernobog_rax_string(ea, i);
        msg("      string %a: \"%s\" (%d of %d runs)\n",
            witness.address, witness.value, witness.observations,
            witness.eligible_runs);
    }
    return count;
}

static transform(ea, want_rax, want_text)
{
    auto code, flatten, text;

    if (want_rax)
    {
        code = chernobog_rax_explore(ea);
        msg("      rax exploration: %s\n", chernobog_rax_result_name(code));
        show_rax_evidence(ea);
    }

    flatten = chernobog_detect_flatten(ea);
    if (flatten.detected)
        msg("      flattening: dispatcher block %d, %d cases, score %d\n",
            flatten.dispatcher_block, flatten.case_count,
            flatten.confidence_score);

    // One call admits the function, drops its tracking so the optimizer
    // pipeline runs again, decompiles without the cache, and hands back the
    // resulting pseudocode.
    text = chernobog_deobfuscate_text(ea);
    if (text == "")
    {
        msg("      deobfuscation produced no pseudocode\n");
        return 0;
    }
    if (want_text)
        msg("%s\n", text);
    return 1;
}

static main()
{
    auto limit, want_rax, want_text;
    auto ea, detection, examined, candidates, transformed;

    auto_wait();
    if (!describe_status())
    {
        msg("Hex-Rays is not available for this database.\n");
        return;
    }
    setup();

    // Any CHERNOBOG_-prefixed variable is readable through the option reader,
    // so this script's own knobs need no separate mechanism.
    limit = atol(chernobog_get_option("CHERNOBOG_REPORT_MAX"));
    if (limit <= 0)
        limit = 10;
    want_rax = atol(chernobog_get_option("CHERNOBOG_REPORT_RAX"));
    want_text = atol(chernobog_get_option("CHERNOBOG_REPORT_TEXT"));

    examined = 0;
    candidates = 0;
    transformed = 0;

    for (ea = get_next_func(0); ea != BADADDR; ea = get_next_func(ea))
    {
        // Analysis only: uncached LOCOPT microcode, no mutation, and no entry
        // added to the decompiler cache.
        detection = chernobog_detect(ea);
        if (!detection.ok)
            continue;
        examined = examined + 1;
        if (!detection.any)
            continue;

        candidates = candidates + 1;
        msg("  %a %-32s %s\n", ea, get_func_name(ea), detection.names);
        if (transformed < limit)
            transformed = transformed + transform(ea, want_rax, want_text);
    }

    msg("\nExamined %d functions, %d obfuscation candidates, "
        "%d transformed.\n", examined, candidates, transformed);
    if (candidates > limit)
        msg("Raise CHERNOBOG_REPORT_MAX above %d to transform the rest.\n",
            limit);
}
