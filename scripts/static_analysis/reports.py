import html
import json
import re
from collections import Counter
from functools import partial
from itertools import islice
from pathlib import Path

from . import SCHEMA_VERSION
from .common import (
    AnalysisError,
    atomic_json,
    atomic_text,
    atomic_writer,
    check_resources,
    read_json,
)
from .endpoints import sanitized
from .facts import application_facts, report_facts, system_classification
from .storage import (
    COMPLETE_COVERAGE_STATUSES,
    EVIDENCE_SECTIONS,
    INDEXED_STORE_VERSION,
    AnalysisStore,
    Apps,
    Records,
    application_view,
)

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
    "methods",
    "fields",
)
RECOMMENDATION_FINDING_SAMPLE_LIMIT = 3
REVIEW_ACTION_LABELS = {
    "review_static_evidence": "Inspect findings and supporting evidence",
    "review_granted_permissions_in_system_settings": "Review granted permissions against required features",
}


def load_report(path):
    path = Path(path)
    if path.suffix == ".sqlite3":
        store = AnalysisStore(path, readonly=True)
        try:
            return store.report()
        except Exception:
            store.close()
            raise
    value = read_json(path)
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != SCHEMA_VERSION
        or not isinstance(value.get("apps"), list)
        or not isinstance(value.get("run"), dict)
    ):
        raise AnalysisError("Unsupported analysis report schema")
    return value


def close_report(report):
    if isinstance(report.get("apps"), Apps):
        report["apps"].store.close()


def _application_view(app):
    records = app.get("signals")
    view = (
        records.store.app_view(app)
        if isinstance(records, Records)
        else application_view(app)
    )
    if "facts" not in view:
        view = {**view, "facts": application_facts(app, view["signals"])}
    return view


def installation_context(app):
    installation = app.get("installation")
    if installation is None:
        return None
    metadata_status = next(
        (
            item["status"]
            for item in installation.get("stages", ())
            if item["stage"] == "package_permissions"
        ),
        "UNAVAILABLE",
    )
    return {
        "user": installation.get("user", app["user"]),
        **{
            key: installation.get(key)
            for key in ("uid", "app_id", "installer", "shared_user", "flags")
        },
        "is_system": system_classification(app),
        "package_metadata_status": metadata_status,
        "appops": installation.get("appops", {}),
        "special_access": installation.get("special_access", {}),
        "stages": installation.get("stages", []),
    }


def recommendation_context(app):
    recommendations = []
    for item in app.get("recommendations", ()):
        value = {key: field for key, field in item.items() if key != "finding_ids"}
        if "finding_ids" in item:
            identities = item["finding_ids"]
            finding_count = len(identities)
            value.update(
                finding_count=finding_count,
                finding_id_sample=list(
                    islice(identities, RECOMMENDATION_FINDING_SAMPLE_LIMIT)
                ),
                finding_ids_truncated=finding_count
                > RECOMMENDATION_FINDING_SAMPLE_LIMIT,
            )
        recommendations.append(value)
    return recommendations


def app_summary(app):
    view = _application_view(app)
    return {
        **view["summary"],
        "facts": view["facts"],
        "signal_summary": view["signals"],
        "installation": installation_context(app),
        "recommendations": recommendation_context(app),
    }


def summary(report, cancel=None, budget=None):
    check_resources(cancel, budget)
    statuses = Counter(item["status"] for item in report.get("stages", []))
    review_total = 0
    ranked = []

    def applications():
        nonlocal review_total
        for app in report["apps"]:
            check_resources(cancel, budget)
            view = _application_view(app)
            statuses.update(view["coverage_counts"])
            review_total += bool(view["summary"]["priority"].get("reasons"))
            ranked.append(view["summary"])
            ranked.sort(key=lambda value: (-value["priority"]["score"], value["id"]))
            del ranked[20:]
            yield app, view

    facts = report_facts(report, applications(), cancel, budget)
    return sanitized(
        {
            "schema_version": report["schema_version"],
            "engine_version": report["engine_version"],
            "run": report["run"],
            "totals": report["totals"],
            "facts": facts,
            "coverage_counts": dict(sorted(statuses.items())),
            "limitations": report["limitations"],
            "apps": ranked,
            "apps_view_truncated": len(report["apps"]) > 20,
            "apps_total": len(report["apps"]),
            "apps_not_shown": max(0, len(report["apps"]) - len(ranked)),
            "review_required_total": review_total,
            "review_required_not_shown": max(
                0,
                review_total
                - sum(bool(item["priority"].get("reasons")) for item in ranked),
            ),
        }
    )


def section_rows(report, section, package=None, identity=None):
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
            if isinstance(report["apps"], Apps):
                store = report["apps"].store
                evidence_rows = (
                    store.evidence_page(app["id"], identity=identity)
                    if store.version >= INDEXED_STORE_VERSION
                    else store.evidence(app["id"])
                )
                for evidence in evidence_rows:
                    yield {**owner, **evidence}
                continue
            seen = set()
            for category in EVIDENCE_SECTIONS:
                for item in app.get(category, ()):
                    for evidence in item.get("evidence", []):
                        if evidence["id"] not in seen:
                            seen.add(evidence["id"])
                            yield {**owner, **evidence}
        else:
            values = app.get(section, ())
            if (
                identity
                and isinstance(values, Records)
                and section != "coverage"
                and (
                    section != "findings"
                    or values.store.version >= INDEXED_STORE_VERSION
                )
            ):
                values = values.page(identity=identity)
            for item in values:
                yield {**owner, **item}


def _indexed_query(report, section, package, offset, limit, identity):
    selected = []
    total = 0

    def take(rows):
        nonlocal total
        for row in rows:
            if identity and row.get("id") != identity:
                continue
            if offset <= total < offset + limit:
                selected.append(row)
            total += 1

    if section == "coverage" and package is None:
        take({"scope": "run", **item} for item in report.get("stages", []))
    for app in report["apps"]:
        if package and app["package"] != package:
            continue
        if section == "apps":
            if identity and app["id"] != identity:
                continue
            if offset <= total < offset + limit:
                selected.append(app_summary(app))
            total += 1
            continue
        owner = {"app_id": app["id"], "package": app["package"], "user": app["user"]}
        if section == "evidence":
            store = report["apps"].store
            count = store.evidence_count(app["id"], identity)
            page = partial(store.evidence_page, app["id"], identity=identity)
        elif isinstance(app.get(section), Records):
            records = app[section]
            count = records.count_records(identity)
            page = partial(records.page, identity=identity)
        else:
            take({**owner, **item} for item in app.get(section, ()))
            continue
        start = max(0, offset - total)
        remaining = max(0, limit - len(selected))
        if remaining and start < count:
            selected.extend({**owner, **item} for item in page(start, remaining))
        total += count
    return total, selected


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
    identity = identity or None
    store = report["apps"].store if isinstance(report["apps"], Apps) else None
    indexed = (
        store
        and not contains
        and not (identity and section == "coverage")
        and not (store.version < INDEXED_STORE_VERSION and section == "evidence")
        and not (
            store.version < INDEXED_STORE_VERSION and identity and section == "findings"
        )
    )
    if indexed:
        total, selected = _indexed_query(
            report, section, package, offset, limit, identity
        )
    else:
        total = 0
        selected = []
        for row in section_rows(report, section, package, identity):
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
        "has_more": offset + len(selected) < total,
        "next_offset": offset + len(selected)
        if offset + len(selected) < total
        else None,
    }
    return result if include_sensitive else sanitized(result)


def markdown(report, limit=100, cancel=None, budget=None, *, facts=None):
    check_resources(cancel, budget)
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
            "recommendations",
        )
    }
    gap_count = 0
    table_totals = Counter()

    def append(name, values):
        check_resources(cancel, budget)
        if len(tables[name]) < limit:
            tables[name].append(
                "| " + " | ".join(cell(sanitized(value)) for value in values) + " |"
            )

    for app in report["apps"]:
        check_resources(cancel, budget)
        package = app["package"] or app["id"]
        view = _application_view(app)
        gap_count += view["gap_count"]
        table_totals.update(
            {
                "apps": 1,
                "recommendations": 1,
                "permissions": len(app["permissions"]),
                "capabilities": len(app["capabilities"]),
                "findings": len(app["findings"]),
                "sdks": len(app["sdks"]),
                "signals": len(view["signals"]),
                "endpoints": len(app["endpoints"]),
                "gaps": view["gap_count"],
                "components": sum(
                    component["exported"] is not False
                    for manifest in app["manifests"]
                    for component in manifest["components"]
                ),
            }
        )
        append(
            "apps",
            (
                package,
                app["status"],
                len(app["artifacts"]),
                len(app["permissions"]),
                len(app["endpoints"]),
                ", ".join(view["summary"]["sdk_candidates"]),
            ),
        )
        if len(tables["recommendations"]) < limit:
            installation = installation_context(app)
            recommendations = recommendation_context(app)
            system = installation["is_system"] if installation else None
            special_access = installation["special_access"] if installation else {}
            append(
                "recommendations",
                (
                    package,
                    "Unknown"
                    if system is None
                    else "System"
                    if system
                    else "Third-party",
                    installation.get("shared_user") or "Unknown / not reported"
                    if installation
                    else "Unknown",
                    ", ".join(
                        f"{name}={value}"
                        for name, value in sorted(special_access.items())
                    )
                    or "Unknown / not captured",
                    "; ".join(
                        REVIEW_ACTION_LABELS.get(item["action"], item["action"])
                        for item in recommendations
                    )
                    or "No recorded review prompt; assess needs and missing context",
                    ", ".join(
                        identity
                        for item in recommendations
                        for identity in item.get("finding_id_sample", ())
                    ),
                    app["status"],
                ),
            )
        for permission in islice(
            app["permissions"], max(0, limit - len(tables["permissions"]))
        ):
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
        for capability in islice(
            app["capabilities"], max(0, limit - len(tables["capabilities"]))
        ):
            append(
                "capabilities",
                (
                    package,
                    capability["type"],
                    capability["evidence_level"],
                    capability["meaning"],
                ),
            )
        for finding in islice(app["findings"], max(0, limit - len(tables["findings"]))):
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
        for sdk in islice(app["sdks"], max(0, limit - len(tables["sdks"]))):
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
        for name, stats in islice(
            sorted(view["signals"].items()), max(0, limit - len(tables["signals"]))
        ):
            append(
                "signals",
                (
                    package,
                    name,
                    stats["count"],
                    stats["evidence_level"],
                ),
            )
        for endpoint in islice(
            app["endpoints"], max(0, limit - len(tables["endpoints"]))
        ):
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
        gaps = (
            item
            for item in app["coverage"]
            if item["status"] not in COMPLETE_COVERAGE_STATUSES
        )
        for item in islice(gaps, max(0, limit - len(tables["gaps"]))):
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
            if len(tables["components"]) >= limit:
                break
            for component in manifest["components"]:
                if len(tables["components"]) >= limit:
                    break
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
        check_resources(cancel, budget)
        if item["status"] not in COMPLETE_COVERAGE_STATUSES:
            gap_count += 1
            table_totals["gaps"] += 1
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
        "table_coverage": "\n".join(
            f"- {name}: total={table_totals[name]}, shown={len(rows)}, not_shown={max(0, table_totals[name] - len(rows))}."
            for name, rows in tables.items()
        ),
        "facts": json.dumps(
            facts if facts is not None else summary(report, cancel, budget)["facts"],
            ensure_ascii=True,
            indent=2,
        ).replace("`", "\\u0060"),
        **{name: "\n".join(rows) for name, rows in tables.items()},
        "limitations": "\n".join("- " + cell(item) for item in report["limitations"]),
    }
    return re.sub(
        r"\{\{([a-z_]+)\}\}",
        lambda match: str(replacements[match[1]]),
        template.read_text(encoding="utf-8"),
    )


def export_reports(
    report, output, view_limit=100, write_analysis=True, cancel=None, budget=None
):
    check_resources(cancel, budget)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    if write_analysis:
        atomic_json(output / "analysis.json", report, cancel, budget)
    overview = summary(report, cancel, budget)
    atomic_json(output / "summary.json", overview, cancel, budget)
    atomic_text(
        output / "report.md",
        markdown(report, view_limit, cancel, budget, facts=overview["facts"]),
        cancel,
        budget,
    )

    def write_domains(filename, hosts):
        with atomic_writer(output / filename, cancel=cancel, budget=budget) as handle:
            for host in hosts:
                check_resources(cancel, budget)
                handle.write(host + "\n")

    if isinstance(report["apps"], Apps):
        for filename, condition in (
            ("domains.txt", ""),
            ("telemetry-domains.txt", "WHERE telemetry=1"),
        ):
            check_resources(cancel, budget)
            cursor = report["apps"].store.connection.execute(
                f"SELECT host FROM domains {condition} ORDER BY host"
            )
            try:
                write_domains(filename, (row[0] for row in cursor))
            finally:
                cursor.close()
        check_resources(cancel, budget)
        return report_files(output, write_analysis)
    hosts = set()
    telemetry = set()
    for app in report["apps"]:
        check_resources(cancel, budget)
        for item in app["endpoints"]:
            check_resources(cancel, budget)
            if item.get("host"):
                hosts.add(item["host"])
                if set(item["tags"]) & {
                    "telemetry_path_candidate",
                    "sdk_telemetry_domain_candidate",
                }:
                    telemetry.add(item["host"])
    write_domains("domains.txt", sorted(hosts))
    write_domains("telemetry-domains.txt", sorted(telemetry))
    check_resources(cancel, budget)
    return report_files(output, write_analysis)


def report_files(output, write_analysis):
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
