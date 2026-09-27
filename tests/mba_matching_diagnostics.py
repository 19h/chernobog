"""Check bounded catalog-attempt diagnostics independently of their producer."""

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


def require(value, reason):
    if not value:
        raise ValueError(reason)


def validate_matching(value, statistics, entry, maximum_maturity, disabled):
    require(value["schema"] == 1, "matching diagnostic schema")
    counts = value["counts"]
    require(set(counts) == set(OUTCOMES), "matching outcome population")
    for count in (*counts.values(), value["events"], value["unrecorded"]):
        require(type(count) is int and count >= 0, "matching nonnegative integer count")
    require(sum(counts.values()) == value["events"], "matching outcome accounting")
    require(value["events"] == statistics["total_matches"], "matching attempt accounting")
    require(len(value["samples"]) <= 64, "matching sample quota")
    require(
        len(value["samples"]) == 64 or value["unrecorded"] == 0,
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
        elif name == "structural_mismatch":
            require(indexed > 0 and structural == candidate == constant == 0, "matching structure")
        elif name == "candidate_constraint":
            require(structural == candidate > 0 and constant == 0, "matching candidate gate")
        elif name == "constant_constraint":
            require(constant > 0 and structural == candidate + constant, "matching constant gate")
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
