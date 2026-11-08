import html
import re
from collections import Counter

from .assessment import NO_APK_REASON, validate_assessment
from .common import AnalysisError, stable_id
from .endpoints import sanitized

REPORTING_VERSION = 1
CHANGE_ACTIONS = frozenset({"retain_restrict", "uninstall", "disable_optional"})
GROUP_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")

LABELS = {
    "en": {
        "title": "Application Privacy Review and Advice (AI assessment)",
        "scope": "This task registered {total} application groups; evidence conclusions have been recorded for {claims}.",
        "incomplete_review": "Some applications or evidence still await review. This report does not assess the safety of the whole device.",
        "missing_code": "APK code was unavailable for {count} application groups.",
        "no_claims": "No evidence conclusions have been recorded yet.",
        "no_actions": "No remediation recommendations have been recorded yet.",
        "boundary": "Static evidence does not establish actual collection or upload. Configuration snapshots describe the collection time, not current activity.",
        "analysis": "Analysis",
        "statuses": {
            "COMPLETE": "finished within the implemented analysis scope",
            "PARTIAL": "incomplete",
            "FAILED": "failed",
            "CANCELLED": "interrupted",
        },
        "stops": {
            "analysis_timeout": "the offline analysis time budget was reached",
            "memory_budget": "the memory budget was reached",
            "disk_budget": "the disk reserve was reached",
            "cancelled": "the task was interrupted",
        },
        "version": "Version",
        "user": "Android user",
        "unknown": "not captured",
        "group": "Record ID",
        "partial_app": "Code analysis for this application is incomplete; missing behavior remains unknown.",
        "no_app_code": "No APK was available for this application; its code behavior is unknown.",
        "review_gap": "Review scope and remaining questions",
        "findings": "Findings",
        "limitations": "Uncertainty",
        "permission": "Captured permission",
        "shared_grant": "This grant record applies to a shared UID and does not establish independent access by this application.",
        "grant_states": {True: "granted", False: "not granted"},
        "advice": "Recommendation",
        "conditions": "Applies when",
        "impact": "Expected impact",
        "verification": "How to check",
        "recovery": "Recovery",
        "prerequisites": "Recorded prerequisite checks",
        "prerequisite_types": {
            "dependency": "Dependencies",
            "role": "System role",
            "reversibility": "Reversibility",
        },
        "prerequisite_states": {
            "verified": "recorded as checked",
            "unverified": "not verified",
        },
        "actions": {
            "retain_restrict": "Retain and restrict unnecessary access",
            "retain": "Keep the existing configuration",
            "disable_optional": "Consider disabling the optional system feature",
            "uninstall": "Uninstall the application",
            "defer": "Defer changes until the missing checks are complete",
        },
        "records": "Full identities, evidence references, outstanding applications and exact statistics remain in the [assessment register](assessment.json). Analysis and review completion are recorded in the [delivery summary](delivery-summary.json).",
    },
    "zh-CN": {
        "title": "应用隐私检查与建议（AI 评估）",
        "scope": "本次登记 {total} 个应用组，其中 {claims} 个已有证据结论。",
        "incomplete_review": "部分应用或证据尚未核查，不能据此评价整台设备是否安全。",
        "missing_code": "其中 {count} 个应用组没有 APK，无法检查代码行为。",
        "no_claims": "当前尚未记录证据结论。",
        "no_actions": "当前尚未记录处置建议。",
        "boundary": "静态证据不代表实际采集或上传；配置快照只反映采集时的记录，不代表当前活动。",
        "analysis": "扫描情况",
        "statuses": {
            "COMPLETE": "已在工具支持的范围内执行完毕",
            "PARTIAL": "未全部完成",
            "FAILED": "执行失败",
            "CANCELLED": "已中断",
        },
        "stops": {
            "analysis_timeout": "已达到离线分析时间预算",
            "memory_budget": "已达到内存预算",
            "disk_budget": "已触及磁盘保留余量",
            "cancelled": "任务被中断",
        },
        "version": "版本",
        "user": "Android 用户",
        "unknown": "未采集",
        "group": "记录 ID",
        "partial_app": "该应用代码分析未全部完成，未覆盖的行为仍然未知。",
        "no_app_code": "该应用没有可用 APK，代码行为未知。",
        "review_gap": "核查范围与待确认事项",
        "findings": "发现与依据",
        "limitations": "尚不确定",
        "permission": "权限采集记录",
        "shared_grant": "该授权记录属于共享 UID 范围，不能解释为该应用独立获得访问。",
        "grant_states": {True: "已授予", False: "未授予"},
        "advice": "建议",
        "conditions": "适用条件",
        "impact": "预期影响",
        "verification": "如何验证",
        "recovery": "如何恢复",
        "prerequisites": "前提核查记录",
        "prerequisite_types": {
            "dependency": "依赖关系",
            "role": "系统角色",
            "reversibility": "可恢复性",
        },
        "prerequisite_states": {
            "verified": "填写者记录为已核查",
            "unverified": "尚未核实",
        },
        "actions": {
            "retain_restrict": "保留应用，并收紧不必要的访问",
            "retain": "维持现有配置",
            "disable_optional": "考虑停用可选系统功能",
            "uninstall": "卸载应用",
            "defer": "暂缓变更，先完成缺失核查",
        },
        "records": "完整身份、证据引用、其余应用登记和精确统计保留在[评估账本](assessment.json)；分析与核查完成情况见[交付摘要](delivery-summary.json)。",
    },
}


def markdown_text(value):
    text = sanitized(str(value)).replace("\n", " ").replace("\r", " ")
    escaped = "".join(
        f"&#{ord(character)};"
        if character in "\\`*[]#!|"
        else html.escape(character, quote=False)
        for character in text
    )
    return escaped.replace("://", "&#58;//")


def recommendation_key(app_id, recommendation):
    return stable_id("report-recommendation-v1", app_id, sanitized(recommendation))


def reporting_source_key(report, assessment):
    return stable_id(
        "reporting-source-v1",
        report["run"]["status"],
        report["run"].get("stop_reason"),
        sanitized(
            {key: value for key, value in assessment.items() if key != "reporting"}
        ),
    )


def record_index(assessment):
    records = {}
    for row in assessment["applications"]:
        app_id = row["identity"]["app_id"]
        for claim in row["claims"]:
            records[(app_id, "claim", claim["id"])] = (row, claim)
        for recommendation in row["recommendations"]:
            key = recommendation_key(app_id, recommendation)
            records[(app_id, "recommendation", key)] = (row, recommendation)
        for item in row.get("deferred_evidence", ()):
            records[(app_id, "deferred_category", item["key"])] = (row, item)
        if row["reason"].strip() and row["reason"] != NO_APK_REASON:
            records[(app_id, "review_scope", None)] = (row, row["reason"])
    return records


def reference_value(key):
    app_id, kind, identity = key
    value = {"app_id": app_id, "kind": kind}
    if identity is not None:
        value["key"] = identity
    return value


def reference_key(reference):
    if not isinstance(reference, dict):
        return None
    app_id, kind = reference.get("app_id"), reference.get("kind")
    if not isinstance(app_id, str) or not isinstance(kind, str):
        return None
    fields = {"app_id", "kind"}
    if kind == "review_scope":
        return (app_id, kind, None) if set(reference) == fields else None
    identity = reference.get("key")
    if (
        kind not in {"claim", "recommendation", "deferred_category"}
        or not isinstance(identity, str)
        or not identity
        or set(reference) != fields | {"key"}
    ):
        return None
    return app_id, kind, identity


def nonempty_text(value):
    return isinstance(value, str) and bool(value.strip())


def validate_reporting(report, assessment):
    records = record_index(assessment)
    required = {key for key in records if key[1] != "review_scope"}
    source_key = reporting_source_key(report, assessment)
    result = {
        "status": "missing",
        "source_key": source_key,
        "available_references": [reference_value(key) for key in records],
        "unassigned_references": [],
        "counts": {
            "groups": 0,
            "main_groups": 0,
            "detail_groups": 0,
            "action_groups": 0,
            "attention_groups": 0,
            "application_groups": 0,
            "routine_records": 0,
        },
        "errors": [],
    }
    if "reporting" not in assessment:
        result["unassigned_references"] = [
            reference_value(key) for key in records if key in required
        ]
        return result
    plan = assessment["reporting"]
    errors = result["errors"]
    if not isinstance(plan, dict):
        result.update(status="invalid", errors=["Reporting must be an object"])
        return result
    if set(plan) != {"schema_version", "source_key", "groups", "routine"}:
        errors.append("Reporting fields do not match the reporting contract")
    if (
        type(plan.get("schema_version")) is not int
        or plan["schema_version"] != REPORTING_VERSION
    ):
        errors.append("Unsupported reporting schema version")
    if plan.get("source_key") != source_key:
        errors.append(
            "Reporting source key is stale; confirm the current source before publication"
        )
    assigned = set()
    members = set()
    group_ids = set()

    def assign_refs(item, location, routine=False):
        references = item.get("refs")
        if not isinstance(references, list) or not references:
            errors.append(location + ": refs must be a nonempty list")
            return []
        selected = []
        for reference in references:
            key = reference_key(reference)
            if key is None or key not in records:
                errors.append(
                    location
                    + ": unknown or invalid source reference: "
                    + str(reference)
                )
                continue
            if key in assigned:
                errors.append(
                    location
                    + ": source reference has multiple primary destinations: "
                    + str(reference)
                )
            assigned.add(key)
            selected.append(key)
            if (
                routine
                and key[1] == "recommendation"
                and records[key][1]["action"] in CHANGE_ACTIONS
            ):
                errors.append(
                    location + ": a device-change recommendation cannot be routine"
                )
        return selected

    for field in ("groups", "routine"):
        values = plan.get(field)
        if not isinstance(values, list):
            errors.append("Reporting " + field + " must be a list")
            continue
        for index, item in enumerate(values):
            location = f"reporting.{field}[{index}]"
            if not isinstance(item, dict):
                errors.append(location + ": entry must be an object")
                continue
            fields = {"refs", "reason"}
            if field == "groups":
                fields |= {"id", "title", "summary", "kind", "placement"}
            if set(item) != fields:
                errors.append(location + ": unsupported or missing fields")
            for name in (
                ("reason", "title", "summary") if field == "groups" else ("reason",)
            ):
                if not nonempty_text(item.get(name)):
                    errors.append(location + ": nonempty text required for " + name)
            selected = assign_refs(item, location, routine=field == "routine")
            if field == "routine":
                result["counts"]["routine_records"] += len(selected)
                continue
            identity = item.get("id")
            if not isinstance(identity, str) or not GROUP_ID.fullmatch(identity):
                errors.append(
                    location
                    + ": group id must contain lowercase ASCII letters, digits or hyphens"
                )
            elif identity in group_ids:
                errors.append(location + ": duplicate group id")
            else:
                group_ids.add(identity)
            kind, placement = item.get("kind"), item.get("placement")
            if not isinstance(kind, str) or kind not in {"action", "attention"}:
                errors.append(location + ": kind must be action or attention")
            if not isinstance(placement, str) or placement not in {"main", "details"}:
                errors.append(location + ": placement must be main or details")
            changes = any(
                key[1] == "recommendation"
                and records[key][1]["action"] in CHANGE_ACTIONS
                for key in selected
            )
            if (kind == "action") != changes:
                errors.append(
                    location
                    + ": action groups must contain device-change recommendations; attention groups must not"
                )
            app_ids = {key[0] for key in selected}
            members.update(app_ids)
            result["counts"]["groups"] += 1
            result["counts"]["main_groups"] += placement == "main"
            result["counts"]["detail_groups"] += (
                placement == "details" or len(app_ids) > 1
            )
            result["counts"]["action_groups"] += kind == "action"
            result["counts"]["attention_groups"] += kind == "attention"
    missing = required - assigned
    result["unassigned_references"] = [
        reference_value(key) for key in records if key in missing
    ]
    if missing:
        errors.append(
            f"Reporting leaves {len(missing)} source records without a primary destination"
        )
    result["counts"]["application_groups"] = len(members)
    result["status"] = "invalid" if errors else "ready"
    return result


def validate_delivery(report, assessment):
    validation = validate_assessment(report, assessment)
    if validation["validation_status"] == "PASS":
        reporting = validate_reporting(report, assessment)
    else:
        reporting = {
            "status": "invalid",
            "errors": ["Resolve assessment errors before reporting validation"],
        }
    validation["reporting"] = reporting
    validation["delivery_summary"]["reporting_status"] = reporting["status"]
    if "counts" in reporting:
        validation["delivery_summary"]["reporting_counts"] = reporting["counts"]
    return sanitized(validation)


def claim_signature(claim):
    return {
        key: claim[key]
        for key in (
            "type",
            "text",
            "limitations",
            "permission",
            "granted",
            "grant_source",
            "grant_scope",
        )
        if key in claim
    }


def recommendation_signature(recommendation):
    return {key: value for key, value in recommendation.items() if key != "claim_ids"}


def identity_text(row, labels, identities):
    identity = row["identity"]
    package = identity["package"] or identity["app_id"]
    name = row.get("display_name")
    values = [
        markdown_text(name) + " (" + markdown_text(package) + ")"
        if name
        else markdown_text(package)
    ]
    for field, value in (
        ("version", identity["version_code"]),
        ("user", identity["user"]),
    ):
        values.append(
            labels[field]
            + ": "
            + markdown_text(value if value is not None else labels["unknown"])
        )
    key = identity["package"], identity["version_code"], identity["user"]
    if identities[key] > 1:
        values.append(labels["group"] + ": " + markdown_text(identity["app_id"]))
    return " | ".join(values)


def selection_rows(group, records):
    selected = {}
    for reference in group["refs"]:
        key = reference_key(reference)
        row, value = records[key]
        app_id, kind, _ = key
        entry = selected.setdefault(
            app_id, {"row": row, "claims": {}, "recommendations": {}, "reasons": []}
        )
        if kind == "claim":
            entry["claims"][value["id"]] = value
        elif kind == "recommendation":
            entry["recommendations"][key[2]] = value
            claims = {claim["id"]: claim for claim in row["claims"]}
            for claim_id in value.get("claim_ids", ()):
                entry["claims"][claim_id] = claims[claim_id]
        else:
            entry["reasons"].append(
                value["reason"] if kind == "deferred_category" else value
            )
    for entry in selected.values():
        row = entry["row"]
        if (
            row["state"] in {"pending", "deferred"}
            and row["reason"]
            and row["reason"] != NO_APK_REASON
        ):
            entry["reasons"].insert(0, row["reason"])
        entry["reasons"] = list(dict.fromkeys(entry["reasons"]))
    return list(selected.values())


def cohort_key(entry):
    row = entry["row"]
    installation = row["context"].get("installation") or {}
    return stable_id(
        [claim_signature(value) for value in entry["claims"].values()],
        [
            recommendation_signature(value)
            for value in entry["recommendations"].values()
        ],
        entry["reasons"],
        row["state"],
        row["context"].get("status"),
        bool(row["identity"]["artifact_sha256"]),
        {
            key: installation.get(key)
            for key in (
                "is_system",
                "package_metadata_status",
                "shared_user",
                "special_access",
                "appops",
            )
        },
    )


def render_entry(entry, labels, language):
    row = entry["row"]
    separator = "：" if language == "zh-CN" else ": "
    conjunction = "；" if language == "zh-CN" else "; "
    lines = []
    if not row["identity"]["artifact_sha256"]:
        lines.extend([labels["no_app_code"], ""])
    elif row["context"].get("status") != "COMPLETE":
        lines.extend([labels["partial_app"], ""])
    claims = {
        stable_id(claim_signature(value)): value for value in entry["claims"].values()
    }
    if claims:
        lines.extend(["**" + labels["findings"] + "**", ""])
        for claim in claims.values():
            text = markdown_text(claim["text"])
            if claim["type"] == "snapshot_grant":
                text += f" ({labels['permission']}{separator}{labels['grant_states'][claim['granted']]})"
                if claim["grant_scope"] == "shared_uid":
                    text += " — " + labels["shared_grant"]
            if claim.get("limitations"):
                text += f" — {labels['limitations']}{separator}" + markdown_text(
                    claim["limitations"]
                )
            lines.append("- " + text)
        lines.append("")
    if entry["reasons"]:
        lines.extend(["**" + labels["review_gap"] + "**", ""])
        lines.extend("- " + markdown_text(reason) for reason in entry["reasons"])
        lines.append("")
    recommendations = {
        stable_id(recommendation_signature(value)): value
        for value in entry["recommendations"].values()
    }
    for recommendation in recommendations.values():
        lines.extend(
            [
                f"**{labels['advice']}{separator}{labels['actions'][recommendation['action']]}**",
                "",
            ]
        )
        for field in ("conditions", "impact", "verification", "recovery"):
            value = recommendation[field]
            if field == "conditions":
                value = conjunction.join(value)
            lines.append(f"- **{labels[field]}**{separator}{markdown_text(value)}")
        lines.append("")
        if recommendation.get("prerequisites"):
            lines.extend(["**" + labels["prerequisites"] + "**", ""])
            for item in recommendation["prerequisites"]:
                lines.append(
                    f"- {labels['prerequisite_types'][item['type']]}{separator}{labels['prerequisite_states'][item['status']]} — "
                    + markdown_text(item["basis"])
                )
            lines.append("")
    return lines


def render_group(group, entries, labels, language, identities, include_summary=True):
    lines = [
        f'<a id="issue-{group["id"]}"></a>',
        "",
        "## " + markdown_text(group["title"]),
        "",
    ]
    if include_summary:
        lines.extend([markdown_text(group["summary"]), ""])
    cohorts = {}
    for entry in entries:
        cohorts.setdefault(cohort_key(entry), []).append(entry)
    for number, cohort in enumerate(cohorts.values(), 1):
        if len(cohorts) > 1:
            row = cohort[0]["row"]
            title = (
                row.get("display_name")
                or row["identity"]["package"]
                or row["identity"]["app_id"]
            )
            lines.extend(
                [
                    "### "
                    + (
                        markdown_text(title)
                        if len(cohort) == 1
                        else ("适用情况 " if language == "zh-CN" else "Variant ")
                        + str(number)
                    ),
                    "",
                ]
            )
        lines.extend(
            "- " + identity_text(entry["row"], labels, identities) for entry in cohort
        )
        lines.append("")
        lines.extend(render_entry(cohort[0], labels, language))
    return lines


def render_assessment(report, assessment, language="en", validation=None):
    validation = (
        validation if validation is not None else validate_delivery(report, assessment)
    )
    if (
        validation["validation_status"] != "PASS"
        or validation["reporting"]["status"] == "invalid"
    ):
        raise AnalysisError(
            "Assessment or reporting validation failed; inspect errors before rendering"
        )
    if language not in LABELS:
        raise AnalysisError("Unsupported advice language")
    labels = LABELS[language]
    chinese = language == "zh-CN"
    delivery = validation["delivery_summary"]
    rows = assessment["applications"]
    records = record_index(assessment)
    identities = Counter(
        (
            row["identity"]["package"],
            row["identity"]["version_code"],
            row["identity"]["user"],
        )
        for row in rows
    )
    lines = [
        "# " + labels["title"],
        "",
        labels["scope"].format(
            total=len(rows), claims=delivery["application_groups_with_claims"]
        ),
        "",
    ]
    if not delivery["review_complete"]:
        lines.extend([labels["incomplete_review"], ""])
    lines.extend(["## 本次结论" if chinese else "## Conclusions", ""])
    if not delivery["claim_count"]:
        lines.extend([labels["no_claims"], ""])
    if not delivery["recommendation_count"]:
        lines.extend([labels["no_actions"], ""])
    elif not any(
        recommendation["action"] in CHANGE_ACTIONS
        for row in rows
        for recommendation in row["recommendations"]
    ):
        lines.extend(
            [
                "本轮没有形成可直接执行的设备变更建议。"
                if chinese
                else "No device-change recommendations have been recorded.",
                "",
            ]
        )
    detail_lines = []
    detail_sections = []
    if validation["reporting"]["status"] == "missing":
        lines.extend(
            [
                "已有记录尚未整理为处理重点；以下详情保留原有内容，不代表已完成重点编排。"
                if chinese
                else "Recorded material has not been organized into decision priorities; the details preserve uncurated content.",
                "",
            ]
        )
        references_by_app = {}
        for key in records:
            references_by_app.setdefault(key[0], []).append(reference_value(key))
        for row in rows:
            if not (
                row["claims"] or row["recommendations"] or row.get("deferred_evidence")
            ):
                continue
            app_id = row["identity"]["app_id"]
            group = {
                "id": "legacy-" + stable_id(app_id),
                "title": row.get("display_name")
                or row["identity"]["package"]
                or app_id,
                "summary": "未编排记录" if chinese else "Uncurated records",
                "refs": references_by_app[app_id],
            }
            entries = selection_rows(group, records)
            detail_sections.append((group, entries))
            detail_lines.extend(
                render_group(group, entries, labels, language, identities)
            )
    else:
        plan = assessment["reporting"]
        counts = validation["reporting"]["counts"]
        lines.extend(
            [
                (
                    "本次整理出 {groups} 个问题，涉及 {apps} 个应用组。"
                    if chinese
                    else "Issues: {groups}; affected application groups: {apps}."
                ).format(
                    groups=counts["groups"],
                    apps=counts["application_groups"],
                ),
                "",
            ]
        )
        if counts["action_groups"]:
            lines.extend(
                [
                    (
                        "其中 {count} 个问题包含设备变更建议。"
                        if chinese
                        else "Issues with device-change recommendations: {count}."
                    ).format(count=counts["action_groups"]),
                    "",
                ]
            )
        for group in plan["groups"]:
            if group["placement"] == "main":
                lines.extend(["- " + markdown_text(group["summary"]), ""])
        if not plan["groups"]:
            lines.extend(
                [
                    "本轮没有选出需要单独说明的问题；常规记录不构成安全结论。"
                    if chinese
                    else "No issues were selected for individual discussion; routine records are not a safety verdict.",
                    "",
                ]
            )
        main_groups = []
        detail_count = 0
        for group in plan["groups"]:
            entries = selection_rows(group, records)
            detailed = group["placement"] == "details" or len(entries) > 1
            if detailed:
                detail_count += 1
                detail_sections.append((group, entries))
                detail_lines.extend(
                    render_group(group, entries, labels, language, identities)
                )
            else:
                main_groups.append((group, entries))
        if counts["main_groups"]:
            lines.extend(["## 处理重点" if chinese else "## Priorities", ""])
            for group in plan["groups"]:
                if group["placement"] != "main":
                    continue
                entries = selection_rows(group, records)
                destination = "report-details.md" if len(entries) > 1 else ""
                lines.append(
                    f"- [{markdown_text(group['title'])}]({destination}#issue-{group['id']})"
                )
            lines.append("")
        if detail_count:
            lines.extend(
                [
                    (
                        "完整问题详情包含 {count} 个问题；请同时查看其中的适用条件和未确认事项。"
                        if chinese
                        else "The complete details contain {count} issues, including their conditions and uncertainties."
                    ).format(count=detail_count),
                    "",
                ]
            )
        for group, entries in main_groups:
            lines.extend(
                render_group(
                    group, entries, labels, language, identities, include_summary=False
                )
            )
    if detail_lines:
        lines.extend(
            [
                "[查看问题详情](report-details.md)"
                if chinese
                else "[Read the issue details](report-details.md)",
                "",
            ]
        )
    lines.extend(["## 范围与依据" if chinese else "## Scope and sources", ""])
    status = report["run"]["status"]
    status_text = labels["statuses"].get(status, markdown_text(status))
    stop = report["run"].get("stop_reason")
    if stop:
        status_text += ("；" if chinese else "; ") + labels["stops"].get(
            stop, markdown_text(stop)
        )
    lines.extend(
        [
            labels["analysis"]
            + ("：" if chinese else ": ")
            + status_text
            + ("。" if chinese else "."),
            "",
        ]
    )
    if validation["unavailable_code"]:
        lines.extend(
            [labels["missing_code"].format(count=validation["unavailable_code"]), ""]
        )
    lines.extend([labels["boundary"], "", labels["records"], ""])
    documents = {"user-advice.md": sanitized("\n".join(lines))}
    if detail_lines:
        navigation = []
        if len(detail_sections) > 1:
            navigation = ["## 内容导航" if chinese else "## Contents", ""]
            for group, entries in detail_sections:
                suffix = (
                    identity_text(entries[0]["row"], labels, identities)
                    if len(entries) == 1
                    else (
                        "涉及 {count} 个应用组"
                        if chinese
                        else "Application groups: {count}"
                    ).format(count=len(entries))
                )
                navigation.append(
                    f"- [{markdown_text(group['title'])}](#issue-{group['id']}) — {suffix}"
                )
            navigation.append("")
        documents["report-details.md"] = sanitized(
            "\n".join(
                [
                    "# 问题详情" if chinese else "# Issue details",
                    "",
                    "[返回主报告](user-advice.md)"
                    if chinese
                    else "[Back to the main report](user-advice.md)",
                    "",
                    labels["boundary"],
                    "",
                    *navigation,
                    *detail_lines,
                    labels["records"],
                    "",
                ]
            )
        )
    return documents
