"""Check bounded catalog-attempt diagnostics independently of their producer."""

import re

OUTCOMES = (
    "no_ast",
    "no_indexed_pattern",
    "structural_mismatch",
    "candidate_constraint",
    "constant_constraint",
    "replacement_unavailable",
    "instance_disproved",
    "instance_unsupported",
    "instance_unknown",
    "catalog_applied",
)

FAILURE_KINDS_WITH_VALUES = {
    "numeric_required",
    "opcode",
    "arity",
    "constant_value",
    "operand_kind",
    "operand_width",
    "value_number",
    "operand_properties",
    "register_identity",
    "number_value",
    "stack_offset",
    "global_address",
    "local_index",
    "local_offset",
    "nested_opcode",
    "instruction_props",
    "load_source",
    "block_identity",
}
FAILURE_KINDS_WITHOUT_VALUES = {
    "null_tree",
    "node_required",
    "null_payload",
    "frame_owner",
    "text_value",
    "unsupported_mop",
    "comparison_budget",
    "binding_capacity",
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def parse_constant_failure(reason):
    match = re.fullmatch(r"constant_check_failed;numeric=(.*);omitted=(0|[1-9][0-9]*)", reason)
    require(match is not None, "constant failure detail grammar")
    bindings = []
    if match[1]:
        for value in match[1].split(","):
            part = re.fullmatch(r"([A-Za-z0-9_]{1,20}):(0|[1-9][0-9]*):0x([0-9a-f]{1,16})", value)
            require(part is not None, "constant failure binding grammar")
            name, width, number = part[1], int(part[2]), int(part[3], 16)
            require(width <= 65535 and format(number, "x") == part[3], "constant binding domain")
            bindings.append({"name": name, "width_bytes": width, "value": number})
    require(len(bindings) <= 4, "constant failure binding quota")
    require(len({b["name"] for b in bindings}) == len(bindings), "duplicate constant binding")
    return bindings, int(match[2])


def parse_match_failure(reason):
    match = re.fullmatch(
        r"match_failed;kind=([a-z_]+);p=(-|[LR]{1,64});c=(-|[LR]{1,64});"
        r"nodes=(0|[1-9][0-9]*)(?:;e=0x([0-9a-f]{1,16});a=0x([0-9a-f]{1,16}))?;cut=([01])",
        reason,
    )
    require(match is not None, "match failure detail grammar")
    kind, pattern, candidate, nodes, expected, actual, cut = match.groups()
    require(kind in FAILURE_KINDS_WITH_VALUES | FAILURE_KINDS_WITHOUT_VALUES, "failure kind")
    require((expected is not None) == (kind in FAILURE_KINDS_WITH_VALUES), "failure value fields")
    pattern, candidate = ["" if path == "-" else path for path in (pattern, candidate)]
    nodes, cut = int(nodes), bool(int(cut))
    require(len(pattern) == len(candidate), "failure path depth disagreement")
    require(nodes < 2**64 and nodes >= len(pattern), "failure prefix count")
    require(not cut or len(pattern) == 64, "failure path truncation")
    result = {
        "kind": kind,
        "pattern_path": pattern,
        "candidate_path": candidate,
        "matched_nodes": nodes,
        "path_truncated": cut,
    }
    if expected is not None:
        expected, actual = int(expected, 16), int(actual, 16)
        require(
            format(expected, "x") == match[5]
            and format(actual, "x") == match[6]
            and expected != actual,
            "failure numeric difference",
        )
        result.update(expected=expected, actual=actual)
    return result


def validate_matching(value, statistics, entry, maximum_maturity, disabled, sample_limit=64):
    require(value["schema"] == 1, "matching diagnostic schema")
    counts = value["counts"]
    require(set(counts) == set(OUTCOMES), "matching outcome population")
    for count in (*counts.values(), value["events"], value["unrecorded"]):
        require(type(count) is int and count >= 0, "matching nonnegative integer count")
    require(sum(counts.values()) == value["events"], "matching outcome accounting")
    require(value["events"] == statistics["total_matches"], "matching attempt accounting")
    require(sample_limit in (64, 1024), "matching sample limit")
    require(len(value["samples"]) <= sample_limit, "matching sample quota")
    require(
        len(value["samples"]) == sample_limit or value["unrecorded"] == 0,
        "matching premature unrecorded events",
    )
    observed = {name: 0 for name in OUTCOMES}
    keys = set()
    for sample in value["samples"]:
        name = sample["outcome"]
        require(name in counts, "matching sample outcome")
        require(sample["entry"] == entry, "matching owning microcode entry")
        for field in ("entry", "source", "maturity", "block", "opcode", "width_bytes"):
            require(type(sample[field]) is int and sample[field] >= 0, "matching site metadata")
        require(
            sample["entry"] < 2**64
            and sample["source"] < 2**64
            and sample["maturity"] <= maximum_maturity
            and sample["width_bytes"] in (1, 2, 4, 8),
            "matching site scope",
        )
        require(
            isinstance(sample["reason"], str)
            and len(sample["reason"].encode()) <= 256
            and isinstance(sample["rule"], str)
            and len(sample["rule"].encode()) <= 128,
            "matching text quota",
        )
        indexed, structural, candidate, constant = (
            sample[field]
            for field in (
                "indexed_patterns",
                "structural_matches",
                "candidate_rejections",
                "constant_rejections",
            )
        )
        require(
            all(type(n) is int and n >= 0 for n in (indexed, structural, candidate, constant))
            and indexed >= structural >= candidate + constant,
            "matching phase counts",
        )
        if name in ("no_ast", "no_indexed_pattern"):
            require(indexed == structural == candidate == constant == 0, "matching empty index")
            if name == "no_indexed_pattern" and sample["reason"]:
                require(
                    sample["reason"] == "root_opcode_unindexed;opcode=" + str(sample["opcode"])
                    and not sample["rule"],
                    "unindexed root attribution",
                )
        elif name == "structural_mismatch":
            require(indexed > 0 and structural == candidate == constant == 0, "matching structure")
            if sample["rule"]:
                parse_match_failure(sample["reason"])
        elif name == "candidate_constraint":
            require(structural == candidate > 0 and constant == 0, "matching candidate gate")
            if sample["rule"]:
                require(sample["reason"] == "candidate_check_failed", "candidate rule attribution")
        elif name == "constant_constraint":
            require(constant > 0 and structural == candidate + constant, "matching constant gate")
            if sample["rule"]:
                parse_constant_failure(sample["reason"])
        else:
            require(
                bool(sample["rule"]) and structural == candidate + constant + 1,
                "matching accepted binding",
            )
        require(type(sample["count"]) is int and sample["count"] > 0, "matching sample count")
        key = tuple((k, v) for k, v in sorted(sample.items()) if k != "count")
        require(key not in keys, "duplicate matching sample")
        keys.add(key)
        observed[name] += sample["count"]
    require(
        sum(observed.values()) + value["unrecorded"] == value["events"],
        "matching retained event accounting",
    )
    require(
        all(observed[name] <= counts[name] for name in OUTCOMES), "matching per-outcome samples"
    )
    for name, status in (
        ("catalog_applied", "verified"),
        ("instance_disproved", "disproved"),
        ("instance_unsupported", "unsupported"),
        ("instance_unknown", "unknown"),
    ):
        require(counts[name] <= statistics["instance_" + status], "matching verifier attribution")
    require(
        sum(counts[name] for name in OUTCOMES[5:]) == statistics["successful_matches"],
        "matching replacement accounting",
    )
    if disabled:
        require(value["events"] == 0, "disabled catalog diagnostic activity")
    return observed
