import html
import json
import re
from collections import Counter
from pathlib import Path

from . import SCHEMA_VERSION
from .common import AnalysisError, atomic_json, atomic_text, read_json
from .endpoints import sanitized

SECTIONS = (
    "apps",
    "permissions",
    "capabilities",
    "endpoints",
    "sdks",
    "signals",
    "findings",
    "coverage",
    "evidence",
)


def load_report(path):
    value = read_json(path)
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or not isinstance(value.get("apps"), list)
        or not isinstance(value.get("run"), dict)
    ):
        raise AnalysisError("Unsupported analysis report schema")
    return value


def app_summary(app):
    return {
        "id": app["id"],
        "package": app["package"],
        "version_code": app["version_code"],
        "user": app["user"],
        "status": app["status"],
        "artifact_count": len(app["artifacts"]),
        "permission_count": len(app["permissions"]),
        "endpoint_count": len(app["endpoints"]),
        "sdk_candidates": sorted({item["name"] for item in app["sdks"]}),
        "signal_types": sorted({item["type"] for item in app["signals"]}),
        "finding_count": len(app["findings"]),
        "priority": app["priority"],
    }


def summary(report):
    statuses = Counter(item["status"] for item in report.get("stages", []))
    statuses.update(
        item["status"] for app in report["apps"] for item in app["coverage"]
    )
    ranked = sorted(
        report["apps"], key=lambda app: (-app["priority"]["score"], app["id"])
    )
    return sanitized(
        {
            "schema_version": report["schema_version"],
            "engine_version": report["engine_version"],
            "run": report["run"],
            "totals": report["totals"],
            "coverage_counts": dict(sorted(statuses.items())),
            "limitations": report["limitations"],
            "apps": [app_summary(app) for app in ranked[:20]],
            "apps_view_truncated": len(ranked) > 20,
            "apps_total": len(ranked),
        }
    )


def section_rows(report, section, package=None):
    if section == "coverage" and package is None:
        for item in report.get("stages", []):
            yield {"scope": "run", **item}
    for app in report["apps"]:
        if package and app["package"] != package:
            continue
        owner = {"app_id": app["id"], "package": app["package"], "user": app["user"]}
        if section == "apps":
            yield app_summary(app)
        elif section == "evidence":
            seen = set()
            for category in ("endpoints", "sdks", "signals"):
                for item in app[category]:
                    for evidence in item.get("evidence", []):
                        if evidence["id"] not in seen:
                            seen.add(evidence["id"])
                            yield {**owner, **evidence}
        else:
            for item in app[section]:
                yield {**owner, **item}


def query(
    report,
    section,
    package=None,
    offset=0,
    limit=50,
    identity=None,
    contains=None,
    include_sensitive=False,
):
    total = 0
    selected = []
    for row in section_rows(report, section, package):
        if identity and row.get("id") != identity:
            continue
        if (
            contains
            and contains.casefold()
            not in json.dumps(row, ensure_ascii=False).casefold()
        ):
            continue
        if offset <= total < offset + limit:
            selected.append(row)
        total += 1
    result = {
        "schema_version": SCHEMA_VERSION,
        "section": section,
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": selected,
    }
    return result if include_sensitive else sanitized(result)


def markdown(report, limit=100):
    template = Path(__file__).resolve().parents[2] / "references" / "report-template.md"

    def cell(value):
        return (
            html.escape(str(value))
            .replace("|", "\\|")
            .replace("\n", " ")
            .replace("\r", " ")
            .replace("`", "&#96;")
        )

    tables = {
        key: []
        for key in (
            "apps",
            "endpoints",
            "gaps",
            "components",
            "permissions",
            "findings",
            "sdks",
            "signals",
            "capabilities",
        )
    }
    gap_count = 0

    def append(name, values):
        if len(tables[name]) < limit:
            tables[name].append(
                "| " + " | ".join(cell(sanitized(value)) for value in values) + " |"
            )

    for app in report["apps"]:
        package = app["package"] or app["id"]
        append(
            "apps",
            (
                package,
                app["status"],
                len(app["artifacts"]),
                len(app["permissions"]),
                len(app["endpoints"]),
                ", ".join(sorted({item["name"] for item in app["sdks"]})),
            ),
        )
        for permission in app["permissions"]:
            append(
                "permissions",
                (
                    package,
                    permission["name"],
                    permission["declaration"],
                    permission["granted"],
                    permission["grant_source"],
                    permission["max_sdk"],
                ),
            )
        for capability in app["capabilities"]:
            append(
                "capabilities",
                (
                    package,
                    capability["type"],
                    capability["evidence_level"],
                    capability["meaning"],
                ),
            )
        for finding in app["findings"]:
            append(
                "findings",
                (
                    package,
                    finding["type"],
                    finding["evidence_level"],
                    finding["id"],
                    ", ".join(finding["evidence_ids"][:3]),
                ),
            )
        for sdk in app["sdks"]:
            append(
                "sdks",
                (
                    package,
                    sdk["name"],
                    sdk["purpose"],
                    sdk["match_basis"],
                    ", ".join(evidence["id"] for evidence in sdk["evidence"][:3]),
                ),
            )
        for name, count in sorted(
            Counter(signal["type"] for signal in app["signals"]).items()
        ):
            append(
                "signals",
                (
                    package,
                    name,
                    count,
                    max(
                        signal["evidence_level"]
                        for signal in app["signals"]
                        if signal["type"] == name
                    ),
                ),
            )
        for endpoint in app["endpoints"]:
            append(
                "endpoints",
                (
                    package,
                    endpoint["kind"],
                    endpoint["value"],
                    endpoint["evidence_level"],
                    endpoint["id"],
                ),
            )
        for item in app["coverage"]:
            if item["status"] not in {"COMPLETE", "NOT_APPLICABLE", "EXCLUDED"}:
                gap_count += 1
                append(
                    "gaps",
                    (
                        package,
                        item["stage"],
                        item["status"],
                        item.get("source", ""),
                        item.get("reason", ""),
                    ),
                )
        for manifest in app["manifests"]:
            for component in manifest["components"]:
                if component["exported"] is True or component["exported"] is None:
                    append(
                        "components",
                        (
                            package,
                            component["kind"],
                            component["name"],
                            component["exported"],
                            component["permission"],
                            component["exported_basis"],
                        ),
                    )
    for item in report.get("stages", []):
        if item["status"] not in {"COMPLETE", "NOT_APPLICABLE", "EXCLUDED"}:
            gap_count += 1
            append(
                "gaps",
                (
                    "run",
                    item["stage"],
                    item["status"],
                    item.get("source", ""),
                    item.get("reason", ""),
                ),
            )
    replacements = {
        "run_id": report["run"]["id"],
        "run_status": report["run"]["status"],
        "mode": report["run"]["mode"],
        "app_count": len(report["apps"]),
        "endpoint_count": report["totals"]["endpoints"],
        "gap_count": gap_count,
        "view_limit": limit,
        **{name: "\n".join(rows) for name, rows in tables.items()},
        "limitations": "\n".join("- " + cell(item) for item in report["limitations"]),
    }
    return re.sub(
        r"\{\{([a-z_]+)\}\}",
        lambda match: str(replacements[match[1]]),
        template.read_text(encoding="utf-8"),
    )


def export_reports(report, output, view_limit=100, write_analysis=True):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    if write_analysis:
        atomic_json(output / "analysis.json", report)
    atomic_json(output / "summary.json", summary(report))
    atomic_text(output / "report.md", markdown(report, view_limit))
    hosts = {
        item["host"]
        for app in report["apps"]
        for item in app["endpoints"]
        if item.get("host")
    }
    telemetry = {
        item["host"]
        for app in report["apps"]
        for item in app["endpoints"]
        if item.get("host")
        and set(item["tags"])
        & {"telemetry_path_candidate", "sdk_telemetry_domain_candidate"}
    }
    atomic_text(
        output / "domains.txt", "\n".join(sorted(hosts)) + ("\n" if hosts else "")
    )
    atomic_text(
        output / "telemetry-domains.txt",
        "\n".join(sorted(telemetry)) + ("\n" if telemetry else ""),
    )
    return {
        name: str(output / name)
        for name in (
            "analysis.json",
            "summary.json",
            "report.md",
            "domains.txt",
            "telemetry-domains.txt",
        )
        if write_analysis or name != "analysis.json"
    }
