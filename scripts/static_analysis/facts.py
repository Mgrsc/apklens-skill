from collections import Counter

from .common import aggregate_status, check_resources
from .privacy_models import SENSITIVE_SIGNALS

FACTS_VERSION = 1
DATAFLOW_STAGES = frozenset({"method_dataflow_E3", "interprocedural_dataflow_E4"})


def system_classification(app):
    installation = app.get("installation")
    if not installation:
        return None
    flags = installation.get("flags")
    complete = any(
        item["stage"] == "package_permissions" and item["status"] == "COMPLETE"
        for item in installation.get("stages", ())
    )
    return "SYSTEM" in flags if complete and isinstance(flags, list) and flags else None


def permission_facts(app):
    permissions = app.get("permissions", ())
    return {
        "unit": "permission_record",
        "manifest_records": sum(
            item.get("declaration") != "snapshot_only" for item in permissions
        ),
        "snapshot_only_records": sum(
            item.get("declaration") == "snapshot_only" for item in permissions
        ),
        "distinct_names": len({item["name"] for item in permissions}),
        "grant_source_records": dict(
            sorted(
                Counter(
                    item.get("grant_source", "unknown") for item in permissions
                ).items()
            )
        ),
        "meaning": "Declarations, snapshot grants and shared-UID grants are distinct; AppOps and effective access remain separate",
    }


def artifact_state(statuses):
    if not statuses:
        return "UNKNOWN"
    for status in ("CANCELLED", "FAILED"):
        if status in statuses:
            return status
    return aggregate_status({"status": status} for status in statuses)


def application_facts(app, signals):
    sdk_counts = Counter(item["name"] for item in app.get("sdks", ()))
    artifacts = {}
    dataflow = {}
    body_selection = []
    for item in app.get("coverage", ()):
        if item.get("artifact"):
            artifacts.setdefault(item["artifact"], set()).add(item["status"])
        metrics = item.get("metrics", {})
        if item["stage"] in DATAFLOW_STAGES:
            dataflow[item["stage"]] = {
                "status": item["status"],
                **{key: value for key, value in metrics.items() if key != "gaps"},
                "gap_sample_count": len(metrics.get("gaps", ())),
            }
        if item["stage"] == "dex_body_selection":
            body_selection.append({"status": item["status"], **metrics})
    reasons = sorted(
        name
        for name, value in signals.items()
        if name in SENSITIVE_SIGNALS and value["evidence_level"] >= "E2"
    )
    return {
        "version": FACTS_VERSION,
        "scope": "app",
        "deduplication_key": "app_id",
        "has_artifacts": bool(app.get("artifacts")),
        "system_classification": system_classification(app),
        "permissions": permission_facts(app),
        "sdks": {
            "unit": "match_record",
            "records": sum(sdk_counts.values()),
            "by_name": dict(sorted(sdk_counts.items())),
        },
        "artifact_statuses": {
            key: artifact_state(value) for key, value in sorted(artifacts.items())
        },
        "body_selection": body_selection or None,
        "body_selection_unknown_reason": None
        if body_selection
        else "This result has no explicit method-body selection metrics",
        "dataflow": dataflow,
        "review": {
            "required": bool(reasons),
            "reasons": reasons,
            "meaning": "Investigation candidates, not dataflow, execution or misuse findings",
        },
    }


def report_facts(report, views, cancel=None, budget=None):
    applications = Counter()
    sdk_records = Counter()
    sdk_apps = Counter()
    permissions = Counter()
    endpoints = 0
    artifacts = {}
    users = set()
    inventory = set()
    for app, view in views:
        check_resources(cancel, budget)
        facts = view["facts"]
        applications["groups"] += 1
        applications["with_apk" if facts["has_artifacts"] else "without_apk"] += 1
        applications[
            "system"
            if facts["system_classification"] is True
            else "non_system"
            if facts["system_classification"] is False
            else "classification_unknown"
        ] += 1
        if app.get("installation") is not None:
            inventory.add((app.get("user"), app.get("package")))
            users.add(app.get("user"))
        endpoints += view["summary"]["endpoint_count"]
        sdk_records.update(facts["sdks"]["by_name"])
        sdk_apps.update(facts["sdks"]["by_name"].keys())
        for key in ("manifest_records", "snapshot_only_records"):
            permissions[key] += facts["permissions"][key]
        artifacts.update(facts["artifact_statuses"])
    supplied = {item["sha256"]: item for item in report.get("artifacts", ())}
    for identity, item in supplied.items():
        artifacts[identity] = item.get("status") or artifacts.get(identity, "UNKNOWN")
    snapshot = report.get("snapshot")
    inventory_known = snapshot is not None or bool(inventory)
    return {
        "version": FACTS_VERSION,
        "counting_policy": {
            "applications": "app_id",
            "inventory": "user/package",
            "artifacts": "sha256",
            "endpoints": "app-scope candidate records only",
            "sdks": "app-scope match records only",
            "coverage_counts": "stage records, not application completion rates",
        },
        "applications": {
            **{
                key: applications[key]
                for key in (
                    "groups",
                    "with_apk",
                    "without_apk",
                    "system",
                    "non_system",
                    "classification_unknown",
                )
            },
            "inventory_targets": len(inventory) if inventory_known else None,
            "inventory_users": sorted(user for user in users if user is not None),
            "inventory_complete": None,
            "inventory_meaning": "Captured targets only; enumeration completeness and factory-install origin are not inferred",
        },
        "artifacts": {
            "unique": len(supplied),
            "status_counts": dict(
                sorted(
                    Counter(
                        artifacts.get(identity, "UNKNOWN") for identity in supplied
                    ).items()
                )
            ),
        },
        "endpoints": {"scope": "app", "unit": "candidate_record", "records": endpoints},
        "sdks": {
            "scope": "app",
            "unit": "match_record",
            "records": sum(sdk_records.values()),
            "distinct_names": len(sdk_records),
            "by_name": {
                name: {
                    "records": sdk_records[name],
                    "application_groups": sdk_apps[name],
                }
                for name in sorted(sdk_records)
            },
        },
        "permissions": {"scope": "app", "unit": "permission_record", **permissions},
    }
