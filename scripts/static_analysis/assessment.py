import html
import json
from collections import Counter

from .common import AnalysisError
from .endpoints import sanitized
from .evidence import DECLARATION_EVIDENCE_KINDS, evidence_level
from .reports import _application_view, app_summary, summary
from .storage import EVIDENCE_SECTIONS, INDEXED_STORE_VERSION, Records

ASSESSMENT_VERSION = 1
REVIEW_STATES = frozenset({"pending", "reviewed", "metadata_only", "deferred"})
CLAIM_LEVELS = {
    "declaration": {"E0"},
    "static_clue": {"E1", "E2"},
    "direct_call": {"E2"},
    "static_path": {"E3", "E4"},
}
ACTIONS = frozenset(
    {"retain_restrict", "uninstall", "disable_optional", "defer", "retain"}
)
CLAIM_KEYS = frozenset(
    {
        "id",
        "type",
        "text",
        "finding_ids",
        "evidence_ids",
        "permission",
        "granted",
        "grant_source",
        "grant_scope",
        "limitations",
    }
)
RECOMMENDATION_KEYS = frozenset(
    {
        "action",
        "conditions",
        "claim_ids",
        "impact",
        "verification",
        "recovery",
        "prerequisites",
    }
)
PREREQUISITE_TYPES = frozenset({"dependency", "role", "reversibility"})
PREREQUISITE_STATES = frozenset({"verified", "unverified"})
CAPTURED_ROLES = (
    "enabled_accessibility_services",
    "enabled_notification_listeners",
    "default_input_method",
)
INVENTORY_SAMPLE_LIMIT = 3


def finding_key(finding):
    kind = finding["type"]
    category = finding.get("data_category")
    return kind + ":" + category if category else kind


def declaration_evidence_supported(app, evidence):
    if (
        evidence.get("kind") not in DECLARATION_EVIDENCE_KINDS
        or evidence.get("declaration") == "snapshot_only"
    ):
        return False
    permissions = [
        item
        for item in app.get("permissions", ())
        if item["name"] == evidence.get("excerpt")
        and item.get("declaration") != "snapshot_only"
        and (
            evidence.get("declaration") is None
            or item.get("declaration") == evidence["declaration"]
        )
    ]
    artifacts = {
        artifact for item in permissions for artifact in item.get("artifacts", ())
    }
    cited = set(evidence.get("artifacts", ()))
    if evidence.get("artifact"):
        cited.add(evidence["artifact"])
    return bool(permissions) and cited.issubset(artifacts)


def finding_reference_level(app, finding):
    level = finding.get("evidence_level", "E0")
    if level in {"E3", "E4"}:
        return level
    locations = list(finding.get("evidence", ()))
    for identity in finding.get("evidence_ids", ()):
        context = evidence_context(app, identity)
        if context:
            locations.append(context[1])
    if level == "E0" and any(
        not declaration_evidence_supported(app, item) for item in locations
    ):
        return None
    support = [evidence_level(item) for item in locations]
    return min(level, max(support)) if support else None


def evidence_inventory(app, claims=None):
    finding_ids = set()
    evidence_levels = {}
    for claim in claims or ():
        finding_ids.update(claim.get("finding_ids", ()))
        for identity in claim.get("evidence_ids", ()):
            context = evidence_context(app, identity)
            if context:
                level = evidence_level(context[1])
                evidence_levels[identity] = max(
                    evidence_levels.get(identity, "E0"), level
                )
    for identity in finding_ids:
        finding = record_by_id(app, "findings", identity)
        if finding:
            for evidence_id in finding.get("evidence_ids", ()):
                context = evidence_context(app, evidence_id)
                if context:
                    evidence_levels[evidence_id] = max(
                        evidence_levels.get(evidence_id, "E0"),
                        evidence_level(context[1]),
                    )
    groups = {}
    for section in ("findings", "endpoints"):
        records = app.get(section, ()) if section == "findings" or groups else ()
        for record in records:
            key = (
                finding_key(record) if section == "findings" else "endpoint_candidates"
            )
            item = groups.setdefault(
                key,
                {
                    "key": key,
                    "section": section,
                    "records": 0,
                    "highest_evidence_level": "E0",
                    "record_id_sample": [],
                    "record_ids_truncated": False,
                    "covered": False,
                },
            )
            level = record.get("evidence_level", "E1")
            if level > item["highest_evidence_level"]:
                item["highest_evidence_level"] = level
                item["covered"] = False
            item["records"] += 1
            if len(item["record_id_sample"]) < INVENTORY_SAMPLE_LIMIT:
                item["record_id_sample"].append(record["id"])
            item["record_ids_truncated"] = item["records"] > INVENTORY_SAMPLE_LIMIT
            references = (
                record.get("evidence_ids", ())
                if section == "findings"
                else (evidence["id"] for evidence in record.get("evidence", ()))
            )
            if level == item["highest_evidence_level"] and (
                section == "findings"
                and record["id"] in finding_ids
                and (finding_reference_level(app, record) or "") >= level
                or any(
                    evidence_levels.get(identity, "") >= level
                    for identity in references
                )
            ):
                item["covered"] = True
    if claims is None:
        for item in groups.values():
            item.pop("covered")
    return [groups[key] for key in sorted(groups)]


def source_statistics(report):
    levels = Counter(
        item.get("evidence_level", "unknown")
        for app in report["apps"]
        for item in app.get("capabilities", ())
    )
    return {
        "input_kind": report["run"].get("input_kind"),
        "capabilities": {
            "unit": "capability_record",
            "records": sum(levels.values()),
            "by_evidence_level": dict(sorted(levels.items())),
        },
    }


def application_identity(app):
    return {
        "app_id": app["id"],
        "package": app.get("package"),
        "version_code": app.get("version_code"),
        "user": app.get("user"),
        "artifact_sha256": sorted(
            {item["sha256"] for item in app.get("artifacts", ())}
        ),
    }


def assessment_context(app):
    overview = app_summary(app)
    return {
        key: overview[key]
        for key in ("status", "facts", "signal_summary", "installation")
    }


def prepare_assessment(report, skill_revision=None):
    return sanitized(
        {
            "schema_version": ASSESSMENT_VERSION,
            "run_id": report["run"]["id"],
            "producer": {
                "engine_version": report["engine_version"],
                "rule_version": report["run"].get("rule_version"),
                "model_version": report["run"].get("model_version"),
                "input_kind": report["run"].get("input_kind"),
                "skill_revision": skill_revision,
            },
            "facts": summary(report)["facts"],
            "applications": [
                {
                    "identity": application_identity(app),
                    "context": assessment_context(app),
                    "evidence_inventory": evidence_inventory(app),
                    "deferred_evidence": [],
                    "state": "pending" if app.get("artifacts") else "metadata_only",
                    "reason": ""
                    if app.get("artifacts")
                    else "No APK artifacts are available; code behavior is unknown",
                    "claims": [],
                    "recommendations": [],
                }
                for app in report["apps"]
            ],
        }
    )


def record_by_id(app, section, identity):
    records = app.get(section, ())
    values = (
        records.page(identity=identity)
        if isinstance(records, Records)
        and records.store.version >= INDEXED_STORE_VERSION
        else records
    )
    return next((item for item in values if item.get("id") == identity), None)


def evidence_context(app, identity):
    signals = app.get("signals")
    if isinstance(signals, Records) and signals.store.version >= INDEXED_STORE_VERSION:
        row = signals.store.connection.execute(
            "SELECT section,parent FROM evidence_refs WHERE app_id=? AND identity=?",
            (app["id"], identity),
        ).fetchone()
        parents = [record_by_id(app, row[0], row[1])] if row else []
    else:
        parents = (
            record for section in EVIDENCE_SECTIONS for record in app.get(section, ())
        )
    for parent in parents:
        if parent:
            for evidence in parent.get("evidence", ()):
                if evidence["id"] == identity:
                    return parent, evidence
    return None


def validate_claim(app, claim):
    errors = []
    kind = claim.get("type")
    if set(claim) - CLAIM_KEYS:
        errors.append("Unsupported claim fields")
    if not isinstance(claim.get("id"), str) or not claim["id"]:
        errors.append("A nonempty claim ID is required")
    if not isinstance(claim.get("text"), str) or not claim["text"].strip():
        errors.append("Claim text is required")
    if "limitations" in claim and not isinstance(claim["limitations"], str):
        errors.append("Claim limitations must be text")
    for key in ("finding_ids", "evidence_ids"):
        references = claim.get(key, [])
        if not isinstance(references, list) or any(
            not isinstance(value, str) or not value for value in references
        ):
            errors.append("Claim references must be lists of nonempty IDs")
            return errors
    if kind == "snapshot_grant":
        matches = [
            item
            for item in app.get("permissions", ())
            if item["name"] == claim.get("permission")
            and item.get("granted") is claim.get("granted")
            and item.get("grant_source") == claim.get("grant_source")
        ]
        source = str(claim.get("grant_source", "")).lower()
        scope = "shared_uid" if "shared" in source else "app"
        if (
            not matches
            or "granted" not in claim
            or type(claim["granted"]) is not bool
            or claim.get("grant_scope") != scope
        ):
            errors.append(
                "Grant state, source and scope must match captured permission facts"
            )
        if claim.get("finding_ids") or claim.get("evidence_ids"):
            errors.append(
                "Snapshot grants cite permission facts rather than finding or evidence IDs"
            )
        return errors
    if not isinstance(kind, str) or kind not in CLAIM_LEVELS:
        return [
            *errors,
            "Unsupported claim type; runtime observations are not available in this static assessment",
        ]
    levels = []
    cited_evidence = set()
    for identity in claim.get("finding_ids", ()):
        finding = record_by_id(app, "findings", identity)
        if finding is None:
            errors.append("Finding is missing or belongs to another application group")
            continue
        levels.append(finding_reference_level(app, finding))
        cited_evidence.update(finding.get("evidence_ids", ()))
        if kind == "static_path" and finding.get("type") != "privacy_transmission_path":
            errors.append("A static path requires a modeled dataflow finding")
    for identity in claim.get("evidence_ids", ()):
        context = evidence_context(app, identity)
        if context is None:
            errors.append("Evidence is missing or belongs to another application group")
            continue
        _, evidence = context
        if kind == "declaration" and not declaration_evidence_supported(app, evidence):
            errors.append(
                "A declaration claim requires matching Manifest permission facts and artifact scope"
            )
        if kind != "static_path":
            levels.append(evidence_level(evidence))
        if kind == "direct_call" and evidence.get("kind") not in {
            "dex_invocation",
            "dex_string_reference",
        }:
            errors.append(
                "A direct-call claim requires an instruction reference, not a promoted parent record"
            )
        if (
            evidence.get("artifact")
            and evidence["artifact"] not in application_identity(app)["artifact_sha256"]
        ):
            errors.append("Evidence artifact does not belong to this application group")
        if claim.get("finding_ids") and identity not in cited_evidence:
            errors.append("Evidence does not support the cited findings")
    if not levels or any(level not in CLAIM_LEVELS[kind] for level in levels):
        errors.append("Claim type is not supported by the cited evidence levels")
    if kind == "static_path" and not claim.get("finding_ids"):
        errors.append("A static path requires a finding ID, not co-occurring evidence")
    if kind == "direct_call" and not claim.get("evidence_ids"):
        errors.append(
            "A direct-call claim requires a supporting instruction evidence ID"
        )
    if kind == "static_path" and (
        not isinstance(claim.get("limitations"), str)
        or not claim["limitations"].strip()
    ):
        errors.append("Static-path limitations and unverified execution must be stated")
    return errors


def validate_recommendation(app, recommendation, claim_ids):
    errors = []
    if set(recommendation) - RECOMMENDATION_KEYS:
        errors.append("Unsupported recommendation fields")
    action = recommendation.get("action")
    if not isinstance(action, str) or action not in ACTIONS:
        errors.append("Unsupported recommendation action")
    for key in ("impact", "verification", "recovery"):
        if (
            not isinstance(recommendation.get(key), str)
            or not recommendation[key].strip()
        ):
            errors.append("Recommendation requires " + key)
    conditions = recommendation.get("conditions")
    if (
        not isinstance(conditions, list)
        or not conditions
        or any(not isinstance(item, str) or not item.strip() for item in conditions)
    ):
        errors.append("Explicit recommendation conditions are required")
    references = recommendation.get("claim_ids", [])
    if not isinstance(references, list) or any(
        not isinstance(identity, str) or identity not in claim_ids
        for identity in references
    ):
        errors.append("Recommendation references unknown claims")
        references = []
    prerequisites = recommendation.get("prerequisites", [])
    if not isinstance(prerequisites, list) or any(
        not isinstance(item, dict) for item in prerequisites
    ):
        errors.append("Recommendation prerequisites must be objects in a list")
        prerequisites = []
    verified = set()
    seen = set()
    for item in prerequisites:
        kind, status = item.get("type"), item.get("status")
        if (
            not isinstance(kind, str)
            or kind not in PREREQUISITE_TYPES
            or not isinstance(status, str)
            or status not in PREREQUISITE_STATES
            or set(item) - {"type", "status", "basis"}
        ):
            errors.append("Invalid recommendation prerequisite type, status or fields")
        elif not isinstance(item.get("basis"), str) or not item["basis"].strip():
            errors.append(
                "Recommendation prerequisites require a basis or missing-evidence explanation"
            )
        elif status == "verified":
            verified.add(kind)
        if isinstance(kind, str):
            if kind in seen:
                errors.append("Duplicate recommendation prerequisite type")
            seen.add(kind)
    facts = _application_view(app)["facts"]
    installation = app.get("installation") or {}
    special_access = installation.get("special_access") or {}
    unknown_roles = any(
        type(special_access.get(role)) is not bool for role in CAPTURED_ROLES
    )
    sensitive_role = bool(installation.get("shared_user")) or any(
        value is True for value in special_access.values()
    )
    if unknown_roles and "role" in verified:
        errors.append("Role verification contradicts unknown captured role states")
    if action == "uninstall" and unknown_roles and "role" not in verified:
        errors.append("Uninstall requires review of unknown captured role states")
    if action == "uninstall" and (
        facts["system_classification"] is not False
        or sensitive_role
        and "dependency" not in verified
    ):
        errors.append(
            "Uninstall requires known non-system classification and dependency review for shared or active roles"
        )
    if action == "disable_optional" and not {
        "dependency",
        "role",
        "reversibility",
    }.issubset(verified):
        errors.append(
            "Optional-system disabling requires role, dependency and recovery prerequisites; otherwise defer"
        )
    if (
        isinstance(action, str)
        and action in {"retain_restrict", "disable_optional"}
        and not references
    ):
        errors.append("Evidence-based restriction requires supporting claims")
    return errors


def validate_assessment(report, assessment):
    errors = []
    counts = Counter({state: 0 for state in sorted(REVIEW_STATES)})
    evidence_counts = Counter({"covered": 0, "deferred": 0, "unreviewed": 0})
    claim_count = 0
    claim_groups = 0
    recommendation_count = 0
    if not isinstance(assessment, dict):
        errors.append("Assessment must be a JSON object")
        assessment = {}
    if (
        assessment.get("schema_version") != ASSESSMENT_VERSION
        or assessment.get("run_id") != report["run"]["id"]
    ):
        errors.append("Assessment version or task identity does not match")
    if assessment.get("facts") != summary(report)["facts"]:
        errors.append(
            "Assessment counting and coverage facts do not match the authoritative report"
        )
    producer = assessment.get("producer", {})
    if not isinstance(producer, dict):
        errors.append("Assessment producer must be an object")
        producer = {}
    for key, value in (
        ("engine_version", report["engine_version"]),
        ("rule_version", report["run"].get("rule_version")),
        ("model_version", report["run"].get("model_version")),
        ("input_kind", report["run"].get("input_kind")),
    ):
        if producer.get(key) != value:
            errors.append("Assessment producer does not match: " + key)
    rows = assessment.get("applications", [])
    if not isinstance(rows, list):
        rows = []
        errors.append("Application assessment rows must be a list")
    indexed = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("identity"), dict):
            errors.append("Invalid application assessment row")
            continue
        identity = row["identity"].get("app_id")
        if not isinstance(identity, str) or identity in indexed:
            errors.append("Duplicate or invalid application group")
        else:
            indexed[identity] = row
    for app in report["apps"]:
        row = indexed.pop(app["id"], None)
        if row is None:
            errors.append(app["id"] + ": application group is missing")
            continue
        prefix = app["id"] + ": "
        if not {
            "identity",
            "context",
            "state",
            "reason",
            "claims",
            "recommendations",
        }.issubset(row):
            errors.append(prefix + "application assessment fields are missing")
        if row["identity"] != application_identity(app) or row.get(
            "context"
        ) != sanitized(assessment_context(app)):
            errors.append(
                prefix + "application identity or captured context was changed"
            )
        state = row.get("state")
        if not isinstance(state, str) or state not in REVIEW_STATES:
            errors.append(prefix + "invalid review state")
        else:
            counts[state] += 1
        if (
            not app.get("artifacts")
            and state == "reviewed"
            or app.get("artifacts")
            and state == "metadata_only"
        ):
            errors.append(prefix + "review state misrepresents APK availability")
        if (
            not isinstance(row.get("reason"), str)
            or state != "pending"
            and not row["reason"].strip()
        ):
            errors.append(prefix + "a review-state reason is required")
        claims = row.get("claims", [])
        if not isinstance(claims, list):
            errors.append(prefix + "claims must be a list")
            claims = []
        claim_ids = set()
        valid_claims = []
        for claim in claims:
            if not isinstance(claim, dict):
                errors.append(prefix + "invalid claim")
                continue
            identity = claim.get("id")
            duplicate = False
            if isinstance(identity, str):
                if identity in claim_ids:
                    errors.append(prefix + "duplicate claim ID")
                    duplicate = True
                claim_ids.add(identity)
            claim_errors = validate_claim(app, claim)
            errors.extend(prefix + error for error in claim_errors)
            if not claim_errors and not duplicate:
                valid_claims.append(claim)
        valid_claim_ids = {claim["id"] for claim in valid_claims}
        reviewed_inventory = evidence_inventory(app, valid_claims)
        claim_count += len(valid_claims)
        claim_groups += bool(valid_claims)
        inventory = [
            {key: value for key, value in item.items() if key != "covered"}
            for item in reviewed_inventory
        ]
        if "evidence_inventory" in row and row["evidence_inventory"] != sanitized(
            inventory
        ):
            errors.append(prefix + "derived evidence inventory was changed")
        keys = {item["key"] for item in reviewed_inventory}
        covered = {item["key"] for item in reviewed_inventory if item["covered"]}
        deferred = {}
        deferrals = row.get("deferred_evidence", [])
        if not isinstance(deferrals, list):
            errors.append(prefix + "deferred evidence must be a list")
            deferrals = []
        for item in deferrals:
            if (
                not isinstance(item, dict)
                or set(item) != {"key", "reason"}
                or not isinstance(item.get("key"), str)
                or item["key"] not in keys
                or not isinstance(item.get("reason"), str)
                or not item["reason"].strip()
            ):
                errors.append(prefix + "invalid deferred evidence key or reason")
                continue
            key = item["key"]
            if key in deferred or key in covered:
                errors.append(
                    prefix + "duplicate or already covered deferred evidence: " + key
                )
            deferred[key] = item["reason"]
        for item in reviewed_inventory:
            key = item["key"]
            status = (
                "covered"
                if key in covered
                else "deferred"
                if key in deferred
                else "unreviewed"
            )
            evidence_counts[status] += 1
            if state == "reviewed" and status == "unreviewed":
                errors.append(
                    prefix
                    + "evidence category requires a claim at its highest level or explicit deferral: "
                    + key
                )
        recommendations = row.get("recommendations", [])
        if not isinstance(recommendations, list):
            errors.append(prefix + "recommendations must be a list")
            recommendations = []
        for recommendation in recommendations:
            if not isinstance(recommendation, dict):
                errors.append(prefix + "invalid recommendation")
                continue
            recommendation_errors = validate_recommendation(
                app, recommendation, valid_claim_ids
            )
            if (
                state in ("pending", "deferred")
                and recommendation.get("action") != "defer"
            ):
                recommendation_errors.append(
                    "outstanding review permits only a deferred action"
                )
            errors.extend(prefix + error for error in recommendation_errors)
            recommendation_count += (
                not recommendation_errors
                and isinstance(state, str)
                and state in REVIEW_STATES
            )
    if indexed:
        errors.append("Assessment contains application groups outside this task")
    return {
        "validation_status": "FAILED" if errors else "PASS",
        "review_counts": dict(counts),
        "evidence_review_counts": dict(evidence_counts),
        "source_statistics": source_statistics(report),
        "outstanding_review": counts["pending"] + counts["deferred"],
        "unavailable_code": sum(not app.get("artifacts") for app in report["apps"]),
        "analysis_status": report["run"]["status"],
        "delivery_summary": {
            "analysis_status": report["run"]["status"],
            "stop_reason": report["run"].get("stop_reason"),
            "validation_status": "FAILED" if errors else "PASS",
            "review_counts": dict(counts),
            "evidence_review_counts": dict(evidence_counts),
            "claim_count": claim_count,
            "application_groups_with_claims": claim_groups,
            "recommendation_count": recommendation_count,
            "review_complete": bool(counts["reviewed"])
            and not errors
            and counts["reviewed"] == sum(counts.values())
            and not evidence_counts["unreviewed"]
            and not evidence_counts["deferred"],
            "meaning": "Ledger coverage only; parsing, validation and rendering do not establish exhaustive code review or actual execution",
        },
        "errors": errors,
        "meaning": "Structural and source validation only; PASS does not mean complete review, safe remediation or observed runtime behavior",
    }


def markdown_text(value):
    text = str(value).replace("\n", " ").replace("\r", " ")
    return "".join(
        f"&#{ord(character)};"
        if character in "\\`*_{}[]()#+-.!|"
        else html.escape(character)
        for character in text
    )


def render_assessment(report, assessment, language="en"):
    validation = validate_assessment(report, assessment)
    if validation["validation_status"] != "PASS":
        raise AnalysisError(
            "Assessment validation failed; inspect validation errors before rendering"
        )
    labels = {
        "en": {
            "title": "Application Assessment",
            "task": "Task",
            "analysis_status": "Analysis status",
            "scope": "Conclusions and review scope",
            "claims_summary": "Application groups with evidence claims: {claims}; Application groups marked reviewed: {reviewed}.",
            "evidence_summary": "Application/category pairs: covered {covered}; explicitly deferred {deferred}; unreviewed {unreviewed}.",
            "outstanding_summary": "Outstanding application assessments: {outstanding} (pending {pending}; deferred {deferred}); applications without APK: {missing}.",
            "scope_note": "Evidence claims may address selected questions or captured permissions only. The reviewed state requires each available category to have a supported claim or explicit deferral; it does not establish exhaustive review or complete code coverage. Category counts are not question or claim counts.",
            "limitations": "Static evidence and captured context only; no actual transmission or remediation safety is established. Validation PASS does not mean complete review.",
            "focus": "Evidence conclusions and recommendations",
            "no_conclusions": "No evidence conclusions or recommendations have been recorded; see the register for outstanding review and missing inputs.",
            "register": "Remaining application register",
            "register_summary": "Show {count} remaining application groups",
            "register_note": "Full identities, artifact hashes and the original row order remain in the accompanying [assessment.json](assessment.json).",
            "register_columns": "Application / group ID | User / version code | State | Reason",
            "pending_reason": "Evidence has not been assessed; no conclusion or remediation recommendation is established.",
            "statistics": "Full statistics and source details",
            "statistics_summary": "Show authoritative counts and source statistics",
            "review_states": "Review states",
            "evidence_categories": "Evidence categories",
            "facts": "Authoritative facts",
            "source_statistics": "Source statistics",
            "conditions": "Conditions",
            "impact": "Impact",
            "verification": "Verification",
            "recovery": "Recovery",
            "deferred_evidence": "Deferred evidence",
            "prerequisite": "Prerequisite",
        },
        "zh-CN": {
            "title": "逐应用评估",
            "task": "任务",
            "analysis_status": "分析状态",
            "scope": "结论与核对范围",
            "claims_summary": "已有证据结论：{claims} 个应用组；应用评估标记 reviewed：{reviewed} 个。",
            "evidence_summary": "证据类别（按应用组／类别计）：已回应 {covered}；明确延期 {deferred}；未核对 {unreviewed}。",
            "outstanding_summary": "待完成应用评估：{outstanding} 个（pending {pending}；deferred {deferred}）；没有 APK 的应用：{missing} 个。",
            "scope_note": "已有证据结论可能只涉及选定问题或采集时的授权。reviewed 表示各个可用证据类别已有支持结论或明确延期，不代表所有位置已审完或代码覆盖完整。类别数不等于问题数或结论条数。",
            "limitations": "结论限于静态证据与已捕获上下文；不代表实际传输或处置安全。校验 PASS 不等于完整审查。",
            "focus": "重点结论与建议",
            "no_conclusions": "尚未记录证据结论或处置建议；待核对范围和缺失输入见登记清单。",
            "register": "其余应用登记",
            "register_summary": "展开其余 {count} 个应用组",
            "register_note": "完整身份、制品哈希和原始行顺序保留在同目录的 [assessment.json](assessment.json)。",
            "register_columns": "应用／应用组 ID | 用户／版本号 | 状态 | 原因",
            "pending_reason": "尚未核对证据；未形成结论或处置建议。",
            "statistics": "完整统计与来源",
            "statistics_summary": "展开权威计数与源数据统计",
            "review_states": "评估状态计数",
            "evidence_categories": "证据类别核对",
            "facts": "权威事实",
            "source_statistics": "源数据统计",
            "conditions": "条件",
            "impact": "影响",
            "verification": "验证",
            "recovery": "恢复",
            "deferred_evidence": "延期证据",
            "prerequisite": "前提",
        },
    }[language]
    focus, remaining = [], []
    for row in assessment["applications"]:
        target = (
            focus
            if row["claims"]
            or row["recommendations"]
            or row.get("deferred_evidence")
            or row["state"] == "reviewed"
            else remaining
        )
        target.append(row)
    counts = validation["review_counts"]
    lines = [
        "# " + labels["title"],
        "",
        f"{labels['task']}: `{assessment['run_id']}`",
        f"{labels['analysis_status']}: `{validation['analysis_status']}`",
        "",
        "## " + labels["scope"],
        "",
        labels["claims_summary"].format(
            claims=sum(bool(row["claims"]) for row in focus),
            reviewed=counts["reviewed"],
        ),
        "",
        labels["evidence_summary"].format(**validation["evidence_review_counts"]),
        "",
        labels["outstanding_summary"].format(
            outstanding=validation["outstanding_review"],
            pending=counts["pending"],
            deferred=counts["deferred"],
            missing=validation["unavailable_code"],
        ),
        "",
        labels["scope_note"],
        "",
        labels["limitations"],
        "",
        "## " + labels["focus"],
        "",
    ]
    if not focus:
        lines.extend([labels["no_conclusions"], ""])
    for row in focus:
        identity = row["identity"]
        lines.extend(
            [
                f"### {markdown_text(identity['package'] or identity['app_id'])}",
                "",
                markdown_text(identity),
                "",
                f"`{row['state']}`: {markdown_text(row['reason'])}",
                "",
            ]
        )
        for claim in row["claims"]:
            references = [*claim.get("finding_ids", []), *claim.get("evidence_ids", [])]
            lines.extend(
                [
                    f"- [{claim['type']}] {markdown_text(claim['text'])} ({markdown_text(', '.join(references))})",
                    "",
                ]
            )
            if claim.get("limitations"):
                lines.extend([markdown_text(claim["limitations"]), ""])
        for item in row.get("deferred_evidence", ()):
            lines.extend(
                [
                    f"- {labels['deferred_evidence']}: {markdown_text(item['key'])}; {markdown_text(item['reason'])}",
                    "",
                ]
            )
        for recommendation in row["recommendations"]:
            lines.extend(
                [
                    f"- `{recommendation['action']}`; {labels['conditions']}: {markdown_text('; '.join(recommendation['conditions']))}",
                    f"  - {labels['impact']}: {markdown_text(recommendation['impact'])}",
                    f"  - {labels['verification']}: {markdown_text(recommendation['verification'])}",
                    f"  - {labels['recovery']}: {markdown_text(recommendation['recovery'])}",
                    "",
                ]
            )
            for prerequisite in recommendation.get("prerequisites", ()):
                lines.extend(
                    [
                        f"  - {labels['prerequisite']}: `{prerequisite['type']}` / `{prerequisite['status']}`; {markdown_text(prerequisite['basis'])}",
                        "",
                    ]
                )
    if remaining:
        lines.extend(
            [
                "## " + labels["register"],
                "",
                labels["register_note"],
                "",
                "<details>",
                "<summary>"
                + labels["register_summary"].format(count=len(remaining))
                + "</summary>",
                "",
                "| " + labels["register_columns"] + " |",
                "| --- | --- | --- | --- |",
            ]
        )
        for row in remaining:
            identity = row["identity"]
            lines.append(
                f"| {markdown_text(identity['package'])} / {markdown_text(identity['app_id'])} "
                f"| {markdown_text(identity['user'])} / {markdown_text(identity['version_code'])} "
                f"| `{row['state']}` | {markdown_text(row['reason'] or labels['pending_reason'])} |"
            )
        lines.extend(["", "</details>", ""])
    lines.extend(
        [
            "## " + labels["statistics"],
            "",
            "<details>",
            "<summary>" + labels["statistics_summary"] + "</summary>",
            "",
            f"{labels['review_states']}: `{counts}`",
            f"{labels['evidence_categories']}: `{validation['evidence_review_counts']}`",
            "",
            "### " + labels["facts"],
            "",
            "```json",
            json.dumps(assessment["facts"], ensure_ascii=False, indent=2),
            "```",
            "",
            "### " + labels["source_statistics"],
            "",
            "```json",
            json.dumps(validation["source_statistics"], ensure_ascii=False, indent=2),
            "```",
            "",
            "</details>",
            "",
        ]
    )
    return sanitized("\n".join(lines))
