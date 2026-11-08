INSTRUCTION_EVIDENCE_KINDS = frozenset(
    {"dex_invocation", "dex_string_reference", "dataflow_step", "source", "sink"}
)
DECLARATION_EVIDENCE_KINDS = frozenset(
    {"manifest_permission", "manifest_or_snapshot_permission"}
)


def evidence_level(evidence):
    kind = evidence.get("kind")
    if kind in INSTRUCTION_EVIDENCE_KINDS:
        return "E2"
    if kind in DECLARATION_EVIDENCE_KINDS:
        return "E0"
    return "E1"


def retain_evidence(retained, additions, maximum):
    identities = {item["id"] for item in retained}
    truncated = False
    for item in additions:
        if item["id"] in identities:
            continue
        if len(retained) < maximum:
            retained.append(item)
            identities.add(item["id"])
            continue
        truncated = True
        if not retained:
            continue
        weakest = min(
            range(len(retained)), key=lambda index: evidence_rank(retained[index])
        )
        if evidence_rank(item) > evidence_rank(retained[weakest]):
            identities.remove(retained[weakest]["id"])
            retained[weakest] = item
            identities.add(item["id"])
    return truncated


def evidence_rank(evidence):
    return evidence_level(evidence), evidence.get("kind") == "dex_class_definition"


def merge_evidence(target, source, maximum):
    truncated = False
    if "evidence" in target or "evidence" in source:
        target["evidence_level"] = max(
            target.get("evidence_level", "E0"), source.get("evidence_level", "E0")
        )
        truncated = retain_evidence(
            target.setdefault("evidence", []), source.get("evidence", []), maximum
        )
        if truncated or source.get("evidence_truncated"):
            target["evidence_truncated"] = True
    for key in ("roles", "tags"):
        if key in source:
            target[key] = sorted(set(target.get(key, ())) | set(source[key]))
    return truncated
