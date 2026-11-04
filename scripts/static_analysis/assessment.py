import html
import json
from collections import Counter

from .common import AnalysisError
from .endpoints import sanitized
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
        records.page(identity=identity) if isinstance(records, Records) else records
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
        levels.append(finding.get("evidence_level"))
        cited_evidence.update(finding.get("evidence_ids", ()))
        if kind == "static_path" and finding.get("type") != "privacy_transmission_path":
            errors.append("A static path requires a modeled dataflow finding")
    for identity in claim.get("evidence_ids", ()):
        context = evidence_context(app, identity)
        if context is None:
            errors.append("Evidence is missing or belongs to another application group")
            continue
        parent, evidence = context
        levels.append(parent.get("evidence_level"))
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
    facts = _application_view(app)["facts"]
    installation = app.get("installation") or {}
    sensitive_role = bool(installation.get("shared_user")) or any(
        value is True for value in installation.get("special_access", {}).values()
    )
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
        for claim in claims:
            if not isinstance(claim, dict):
                errors.append(prefix + "invalid claim")
                continue
            identity = claim.get("id")
            if isinstance(identity, str):
                if identity in claim_ids:
                    errors.append(prefix + "duplicate claim ID")
                claim_ids.add(identity)
            errors.extend(prefix + error for error in validate_claim(app, claim))
        recommendations = row.get("recommendations", [])
        if not isinstance(recommendations, list):
            errors.append(prefix + "recommendations must be a list")
            recommendations = []
        for recommendation in recommendations:
            if not isinstance(recommendation, dict):
                errors.append(prefix + "invalid recommendation")
                continue
            errors.extend(
                prefix + error
                for error in validate_recommendation(app, recommendation, claim_ids)
            )
            if (
                state in ("pending", "deferred")
                and recommendation.get("action") != "defer"
            ):
                errors.append(
                    prefix + "outstanding review permits only a deferred action"
                )
    if indexed:
        errors.append("Assessment contains application groups outside this task")
    return {
        "validation_status": "FAILED" if errors else "PASS",
        "review_counts": dict(counts),
        "outstanding_review": counts["pending"] + counts["deferred"],
        "unavailable_code": sum(not app.get("artifacts") for app in report["apps"]),
        "analysis_status": report["run"]["status"],
        "errors": errors,
        "meaning": "Structural and source validation only; PASS does not mean complete review, safe remediation or observed runtime behavior",
    }


def markdown_text(value):
    text = html.escape(str(value)).replace("\n", " ").replace("\r", " ")
    for character in "\\`*_{}[]()#+-.!|":
        text = text.replace(character, f"&#{ord(character)};")
    return text


def render_assessment(report, assessment, language="en"):
    validation = validate_assessment(report, assessment)
    if validation["validation_status"] != "PASS":
        raise AnalysisError(
            "Assessment validation failed; inspect validation errors before rendering"
        )
    labels = {
        "en": (
            "Application Assessment",
            "Task",
            "Analysis status",
            "Review states",
            "Outstanding review",
            "Applications without APK",
            "Static evidence and captured context only; no actual transmission or remediation safety is established.",
            "Conditions",
            "Impact",
            "Verification",
            "Recovery",
        ),
        "zh-CN": (
            "逐应用评估",
            "任务",
            "分析状态",
            "评估状态计数",
            "待完成评估",
            "没有 APK 的应用",
            "结论限于静态证据与已捕获上下文；不代表实际传输或处置安全。",
            "条件",
            "影响",
            "验证",
            "恢复",
        ),
    }[language]
    lines = [
        "# " + labels[0],
        "",
        f"{labels[1]}: `{assessment['run_id']}`",
        f"{labels[2]}: `{validation['analysis_status']}`",
        f"{labels[3]}: `{validation['review_counts']}`",
        f"{labels[4]}: {validation['outstanding_review']}; {labels[5]}: {validation['unavailable_code']}",
        "",
        labels[6],
        "",
        "```json",
        json.dumps(assessment["facts"], ensure_ascii=False, indent=2),
        "```",
        "",
    ]
    for row in assessment["applications"]:
        identity = row["identity"]
        lines.extend(
            [
                f"## {markdown_text(identity['package'] or identity['app_id'])}",
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
        for recommendation in row["recommendations"]:
            lines.extend(
                [
                    f"- `{recommendation['action']}`; {labels[7]}: {markdown_text('; '.join(recommendation['conditions']))}",
                    f"  - {labels[8]}: {markdown_text(recommendation['impact'])}",
                    f"  - {labels[9]}: {markdown_text(recommendation['verification'])}",
                    f"  - {labels[10]}: {markdown_text(recommendation['recovery'])}",
                    "",
                ]
            )
    return sanitized("\n".join(lines))
