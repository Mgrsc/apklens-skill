import copy
import hashlib
import json
import re
import struct
import time
import xml.etree.ElementTree as ET
import zipfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from functools import lru_cache
from pathlib import Path

from . import ENGINE_VERSION, SCHEMA_VERSION
from .binary import (
    checked_range,
    dex_index,
    printable_strings,
    resource_strings,
    xml_nodes,
)
from .common import (
    AnalysisError,
    Budget,
    BudgetExceeded,
    Cancelled,
    JsonRecords,
    MemoryBudgetExceeded,
    aggregate_status,
    atomic_json,
    available_memory,
    check_resources,
    json_checksum,
    read_json,
    resident_bytes,
    run_command,
    stable_id,
    stage,
)
from .dataflow import MODEL_VERSION, analyze_dataflow, evidence_path_key
from .endpoints import EndpointCollector, host_matches
from .manifest import analyze_manifest
from .privacy_models import SENSITIVE_SIGNALS
from .rules import (
    RULE_VERSION,
    SDK_RULES,
    capabilities,
    sdk_domain_matches,
    sdk_matches,
    signal_matches,
)
from .storage import Apps, ArtifactResults, FindingIds, artifact_status

DEX_NAME = re.compile(r"(?:.*/)?classes(?:[0-9]+)?\.dex\Z")
TEXT_SUFFIXES = {
    ".xml",
    ".json",
    ".js",
    ".html",
    ".htm",
    ".txt",
    ".csv",
    ".properties",
    ".yaml",
    ".yml",
    ".config",
    ".ini",
    ".url",
}
NON_CANDIDATE_PREFIXES = ("META-INF/",)
SDK_HOST_CACHE_SIZE = 4096
CACHE_MEMORY_MULTIPLIER = 8


def cache_key(identity, limits, mode):
    value = {
        "artifact": identity,
        "engine": ENGINE_VERSION,
        "schema": SCHEMA_VERSION,
        "rules": RULE_VERSION,
        "dataflow_model": MODEL_VERSION,
        "limits": limits.signature(),
        "mode": mode,
    }
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def cache_read(path, budget=None):
    check_resources(budget=budget)
    if budget is not None:
        headroom = available_memory()
        if budget.limits.memory_bytes:
            resident = resident_bytes()
            if resident is not None:
                remaining = max(0, budget.limits.memory_bytes - resident)
                headroom = remaining if headroom is None else min(headroom, remaining)
        if (
            headroom is not None
            and Path(path).stat().st_size * CACHE_MEMORY_MULTIPLIER > headroom
        ):
            return None
    value = read_json(path, budget=budget)
    payload = value["result"]
    checksum = json_checksum(payload, budget=budget)
    if value.get("checksum") != checksum or not isinstance(payload.get("stages"), list):
        raise AnalysisError("Cached result failed validation")
    return payload


def cache_write(path, result, cancel=None, budget=None):
    check_resources(cancel, budget)
    checksum = json_checksum(result, cancel=cancel, budget=budget)
    value = {
        key: JsonRecords(item)
        if key in {"endpoints", "signals", "sdks", "stages"}
        else item
        for key, item in result.items()
    }
    atomic_json(path, {"checksum": checksum, "result": value}, cancel, budget)


def analyze_artifact(artifact, limits, mode, cancel, cache_directory=None):
    started = time.monotonic()
    budget = Budget(limits, cancel)
    identity = artifact["sha256"]
    key = cache_key(identity, limits, mode)
    cache_file = Path(cache_directory) / f"{key}.json" if cache_directory else None
    cache_issue = None
    if cache_file and cache_file.exists():
        try:
            result = cache_read(cache_file, budget)
            if result is None:
                cache_issue = "Cache read was skipped to preserve memory headroom"
                cache_file = None
            else:
                if result.get("sha256") != identity or result.get("cache_key") != key:
                    raise AnalysisError("Cached identity does not match the artifact")
                result["cache"] = {"hit": True, "key": key}
                result["elapsed_seconds"] = round(time.monotonic() - started, 3)
                budget.check()
                return result
        except (Cancelled, BudgetExceeded):
            raise
        except (OSError, ValueError, KeyError, TypeError, AnalysisError):
            cache_issue = "Invalid cache entry was ignored"
    collector = EndpointCollector(limits, budget)
    result = {
        "sha256": identity,
        "size": artifact["size"],
        "cache_key": key,
        "manifest": None,
        "endpoints": [],
        "signals": [],
        "sdks": [],
        "methods": [],
        "fields": [],
        "stages": [],
        "statistics": {
            "entries": 0,
            "bytes_read": 0,
            "dex_files": 0,
            "dex_strings": 0,
            "scanned_methods": 0,
        },
    }
    stages = result["stages"]
    descriptors = []
    structure_budget = {"methods": 0, "units": 0}
    total_read = 0
    signal_ids = set()
    signals_truncated = False

    def add_signals(value, source, level="E1"):
        nonlocal signals_truncated
        for signal in signal_matches(value, source, level):
            if signal["id"] in signal_ids:
                continue
            if len(result["signals"]) >= limits.max_results:
                signals_truncated = True
                return
            signal_ids.add(signal["id"])
            result["signals"].append(signal)

    def consume(value, source, references=None):
        budget.check()
        if len(value.encode("utf-8", "replace")) > limits.max_string_bytes:
            stages.append(
                stage(
                    "string_analysis",
                    "PARTIAL",
                    source["entry"],
                    "String length exceeds the budget",
                )
            )
            return
        collector.add_text(value, source, references)
        add_signals(value, source)

    try:
        with zipfile.ZipFile(artifact["path"]) as archive:
            entries = archive.infolist()
            result["statistics"]["entries"] = len(entries)
            if len(entries) > limits.max_entries:
                raise BudgetExceeded("Archive entry count exceeds the budget")
            duplicates = len(entries) - len({entry.filename for entry in entries})
            stages.append(
                stage(
                    "archive",
                    "PARTIAL" if duplicates else "COMPLETE",
                    identity,
                    "Duplicate archive paths make member identity ambiguous"
                    if duplicates
                    else None,
                    entries=len(entries),
                )
            )
            if duplicates:
                raise AnalysisError("Duplicate archive member names are unsupported")
            manifest_entries = [
                entry for entry in entries if entry.filename == "AndroidManifest.xml"
            ]
            if not manifest_entries:
                stages.append(
                    stage(
                        "manifest", "FAILED", identity, "AndroidManifest.xml is missing"
                    )
                )
            for entry in entries:
                budget.check()
                name = entry.filename
                if entry.is_dir():
                    continue
                suffix = Path(name).suffix.lower()
                if name.startswith(NON_CANDIDATE_PREFIXES):
                    stages.append(
                        stage(
                            "archive_member",
                            "EXCLUDED",
                            name,
                            "Signature or archive metadata",
                        )
                    )
                    continue
                kind = (
                    "manifest"
                    if name == "AndroidManifest.xml"
                    else "dex"
                    if DEX_NAME.fullmatch(name)
                    else "resources"
                    if name == "resources.arsc"
                    else "binary_xml"
                    if name.startswith("res/") and suffix == ".xml"
                    else "native_strings"
                    if suffix == ".so"
                    else "asset_strings"
                    if name.startswith(("assets/", "res/raw/"))
                    or suffix in TEXT_SUFFIXES
                    else None
                )
                if kind is None:
                    stages.append(
                        stage(
                            "archive_member",
                            "EXCLUDED",
                            name,
                            "Member type is outside the implemented static string sources",
                        )
                    )
                    continue
                if mode == "quick" and kind in {"native_strings", "asset_strings"}:
                    stages.append(
                        stage(kind, "DEFERRED", name, "Quick mode excludes this source")
                    )
                    continue
                if entry.flag_bits & 1:
                    stages.append(
                        stage(kind, "UNAVAILABLE", name, "Encrypted archive member")
                    )
                    continue
                if (
                    entry.file_size > limits.max_entry_bytes
                    or total_read + entry.file_size > limits.max_total_bytes
                ):
                    stages.append(
                        stage(kind, "PARTIAL", name, "Archive byte budget exceeded")
                    )
                    continue
                item_started = time.monotonic()
                try:
                    with archive.open(entry) as handle:
                        data = handle.read(limits.max_entry_bytes + 1)
                    if len(data) > limits.max_entry_bytes:
                        raise BudgetExceeded("Archive member exceeds the byte budget")
                    total_read += len(data)
                    result["statistics"]["bytes_read"] = total_read
                    source = {"artifact": identity, "entry": name, "kind": kind}
                    if kind == "manifest":
                        nodes = xml_nodes(data, limits, budget)
                        result["manifest"] = analyze_manifest(nodes)
                        for index, node in enumerate(nodes):
                            for key, value in node["attrs"].items():
                                if isinstance(value, str):
                                    consume(
                                        value,
                                        {
                                            **source,
                                            "node_index": index,
                                            "attribute": key,
                                        },
                                    )
                            for key in ("text", "tail"):
                                if node.get(key):
                                    consume(
                                        node[key],
                                        {
                                            **source,
                                            "node_index": index,
                                            "attribute": key,
                                        },
                                    )
                    elif kind == "dex":
                        result["statistics"]["dex_files"] += 1
                        try:
                            index = dex_index(
                                data,
                                limits,
                                budget,
                                inspect_code=mode != "quick",
                                structure_budget=structure_budget,
                            )
                        except (AnalysisError, UnicodeError) as error:
                            if isinstance(error, (Cancelled, MemoryBudgetExceeded)):
                                raise
                            for item in printable_strings(data):
                                consume(
                                    item["value"],
                                    {
                                        **source,
                                        "kind": "dex_raw_fallback",
                                        "offset": item["offset"],
                                    },
                                )
                            stages.append(
                                stage("dex_structure", "PARTIAL", name, str(error))
                            )
                            continue
                        result["statistics"]["dex_strings"] += len(index["strings"])
                        result["statistics"]["scanned_methods"] += index[
                            "scanned_methods"
                        ]
                        descriptors.append((name, index["types"]))
                        for body in index["bodies"]:
                            budget.check()
                            result["methods"].append(
                                {
                                    "id": stable_id(
                                        "method",
                                        identity,
                                        name,
                                        body["signature"],
                                        body.get("code_offset"),
                                    ),
                                    "artifact": identity,
                                    "entry": name,
                                    **body,
                                }
                            )
                        fields_truncated = False
                        for field_index, field in enumerate(index["fields"]):
                            if field_index % 256 == 0:
                                budget.check()
                            if len(result["fields"]) < limits.max_results:
                                result["fields"].append(
                                    {
                                        "id": stable_id(
                                            "field", identity, name, field_index
                                        ),
                                        "signature": field,
                                        "artifact": identity,
                                        "entry": name,
                                    }
                                )
                            else:
                                fields_truncated = True
                            add_signals(
                                field,
                                {
                                    **source,
                                    "kind": "dex_field",
                                    "field_index": field_index,
                                },
                            )
                        if fields_truncated:
                            index["structure_gaps"].append(
                                "DEX field index budget exceeded"
                            )
                        stages.append(
                            stage(
                                "dex_structure_index",
                                "DEFERRED"
                                if mode == "quick"
                                else "PARTIAL"
                                if index["structure_gaps"] or index["gaps"]
                                else "COMPLETE",
                                name,
                                "Quick mode excludes method bodies"
                                if mode == "quick"
                                else "; ".join(index["structure_gaps"] + index["gaps"])
                                or None,
                                methods=len(index["bodies"]),
                                fields=len(index["fields"]),
                            )
                        )
                        for item in index["strings"]:
                            consume(
                                item["value"],
                                {
                                    **source,
                                    "kind": "dex_string",
                                    "offset": item["offset"],
                                    "string_index": item["string_index"],
                                },
                                index["references"].get(item["string_index"]),
                            )
                        for method_index in checked_range(
                            len(index["methods"]), budget
                        ):
                            add_signals(
                                index["methods"][method_index],
                                {
                                    **source,
                                    "kind": "dex_method_id",
                                    "method_index": method_index,
                                },
                            )
                        for call_index in checked_range(len(index["calls"]), budget):
                            call = index["calls"][call_index]
                            add_signals(
                                call["target"],
                                {**source, **call, "kind": "dex_invocation"},
                                "E2",
                            )
                        stages.append(
                            stage(
                                "dex_references",
                                "DEFERRED"
                                if mode == "quick"
                                else "PARTIAL"
                                if index["gaps"]
                                else "COMPLETE",
                                name,
                                "Quick mode excludes instruction references"
                                if mode == "quick"
                                else "; ".join(index["gaps"]) or None,
                                methods=index["scanned_methods"],
                            )
                        )
                    elif kind == "resources":
                        for item in resource_strings(data, limits, budget):
                            consume(
                                item["value"],
                                {
                                    **source,
                                    "offset": item["offset"],
                                    "string_index": item["string_index"],
                                },
                            )
                    elif kind == "binary_xml":
                        nodes = xml_nodes(data, limits, budget)
                        for node_index, node in enumerate(nodes):
                            for key, value in node["attrs"].items():
                                if isinstance(value, str):
                                    consume(
                                        value,
                                        {
                                            **source,
                                            "node_index": node_index,
                                            "attribute": key,
                                        },
                                    )
                            for key in ("text", "tail"):
                                if node.get(key):
                                    consume(
                                        node[key],
                                        {
                                            **source,
                                            "node_index": node_index,
                                            "attribute": key,
                                        },
                                    )
                    else:
                        if data.startswith((b"PK\x03\x04", b"\x1f\x8b")):
                            stages.append(
                                stage(
                                    "nested_container",
                                    "UNAVAILABLE",
                                    name,
                                    "Nested compressed containers are not recursively unpacked",
                                )
                            )
                        if suffix in TEXT_SUFFIXES:
                            try:
                                encoding = (
                                    "utf-16"
                                    if data.startswith((b"\xff\xfe", b"\xfe\xff"))
                                    else "utf-8-sig"
                                )
                                text = data.decode(encoding)
                                for line_number, line in enumerate(
                                    text.splitlines(), 1
                                ):
                                    consume(
                                        line,
                                        {
                                            **source,
                                            "line": line_number,
                                            "encoding": encoding,
                                        },
                                    )
                            except UnicodeError:
                                stages.append(
                                    stage(
                                        "text_decode",
                                        "PARTIAL",
                                        name,
                                        "Text could not be decoded; printable-string fallback used",
                                    )
                                )
                                for item in printable_strings(data):
                                    consume(
                                        item["value"],
                                        {
                                            **source,
                                            "offset": item["offset"],
                                            "encoding": item["encoding"],
                                        },
                                    )
                        else:
                            for item in printable_strings(data):
                                consume(
                                    item["value"],
                                    {
                                        **source,
                                        "offset": item["offset"],
                                        "encoding": item["encoding"],
                                    },
                                )
                    stages.append(
                        stage(
                            kind,
                            source=name,
                            bytes=len(data),
                            elapsed_seconds=round(time.monotonic() - item_started, 4),
                        )
                    )
                except (Cancelled, MemoryBudgetExceeded):
                    raise
                except (
                    AnalysisError,
                    ValueError,
                    UnicodeError,
                    OSError,
                    EOFError,
                    zipfile.BadZipFile,
                    RuntimeError,
                    ET.ParseError,
                    struct.error,
                ) as error:
                    stages.append(
                        stage(
                            kind,
                            "PARTIAL"
                            if isinstance(error, BudgetExceeded)
                            else "FAILED",
                            name,
                            str(error),
                        )
                    )
    except MemoryBudgetExceeded as error:
        result["resource_limited"] = True
        cancel.set()
        stages.append(stage("artifact_analysis", "PARTIAL", identity, str(error)))
    except Cancelled as error:
        stages.append(stage("artifact_analysis", "CANCELLED", identity, str(error)))
    except (
        AnalysisError,
        ValueError,
        OSError,
        EOFError,
        zipfile.BadZipFile,
        RuntimeError,
    ) as error:
        stages.append(
            stage(
                "artifact_analysis",
                "PARTIAL" if isinstance(error, BudgetExceeded) else "FAILED",
                identity,
                str(error),
            )
        )
    result["endpoints"] = collector.results()
    if not cancel.is_set():
        try:
            domain_matches = sdk_domain_matches(result["endpoints"], budget)
            for name, types in descriptors or [("archive", [])]:
                result["sdks"].extend(
                    sdk_matches(
                        types,
                        result["endpoints"],
                        identity,
                        name,
                        domain_matches,
                        budget,
                    )
                )
            budget.check()
        except MemoryBudgetExceeded as error:
            result["resource_limited"] = True
            cancel.set()
            stages.append(stage("sdk_matching", "PARTIAL", identity, str(error)))
        except (Cancelled, BudgetExceeded) as error:
            stages.append(
                stage(
                    "sdk_matching",
                    "CANCELLED" if isinstance(error, Cancelled) else "PARTIAL",
                    identity,
                    str(error),
                )
            )
    stages.append(
        stage(
            "endpoint_extraction",
            "PARTIAL"
            if collector.truncated or collector.evidence_truncated
            else "COMPLETE",
            identity,
            "Endpoint or evidence count exceeds the budget"
            if collector.truncated or collector.evidence_truncated
            else None,
            results=len(result["endpoints"]),
        )
    )
    stages.append(
        stage(
            "signal_matching",
            "PARTIAL" if signals_truncated else "COMPLETE",
            identity,
            "Signal count exceeds the budget" if signals_truncated else None,
            results=len(result["signals"]),
        )
    )
    if (
        cancel.is_set()
        and not result.get("resource_limited")
        and not any(item["status"] == "CANCELLED" for item in stages)
    ):
        stages.append(
            stage(
                "artifact_analysis",
                "CANCELLED",
                identity,
                "Analysis cancelled before artifact completion",
            )
        )
    for item in stages:
        item["artifact"] = identity
    result["cache"] = {"hit": False, "key": key}
    if cache_issue:
        result["cache"]["notice"] = cache_issue
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    if cache_file and not any(
        item["status"] in {"PARTIAL", "FAILED", "CANCELLED", "UNAVAILABLE"}
        for item in stages
    ):
        try:
            cache_write(cache_file, result, cancel, budget)
        except MemoryBudgetExceeded as error:
            result["resource_limited"] = True
            cancel.set()
            stages.append(
                stage(
                    "result_cache", "PARTIAL", identity, str(error), artifact=identity
                )
            )
        except (Cancelled, BudgetExceeded) as error:
            stages.append(
                stage(
                    "result_cache",
                    "CANCELLED" if isinstance(error, Cancelled) else "PARTIAL",
                    identity,
                    str(error),
                    artifact=identity,
                )
            )
        except OSError:
            result["cache"]["notice"] = "Result cache could not be written"
    return result


def analyze_many(
    artifacts,
    limits,
    mode,
    cancel,
    jobs,
    cache_directory,
    progress,
    store=None,
    resume_store=None,
    retry_incomplete=False,
    source_tool=None,
):
    unique = {artifact["sha256"]: artifact for artifact in artifacts}
    pending = iter(sorted(unique.values(), key=lambda artifact: artifact["sha256"]))
    results = ArtifactResults(store) if store else {}
    active = {}
    counts = {"complete": 0, "partial": 0, "failed": 0, "cancelled": 0}
    done = 0

    def record_completion(artifact, result, resumed=False):
        nonlocal done
        status = artifact_status(result)
        counts[status.lower()] += 1
        done += 1
        progress(
            {
                "event": "artifact_complete",
                "done": done,
                "total": len(unique),
                "artifact": artifact["sha256"],
                "status": status,
                "cache_hit": result["cache"]["hit"],
                "resumed": resumed,
                "persisted": store is not None,
                **counts,
            }
        )

    with ThreadPoolExecutor(max_workers=jobs) as executor:
        try:
            while True:
                while not cancel.is_set() and len(active) < jobs:
                    artifact = next(pending, None)
                    if artifact is None:
                        break
                    if resume_store and resume_store.reusable(
                        artifact["sha256"],
                        cache_key(artifact["sha256"], limits, mode),
                        retry_incomplete,
                        source_tool,
                    ):
                        store.import_artifact(resume_store, artifact["sha256"])
                        record_completion(
                            artifact, results[artifact["sha256"]], resumed=True
                        )
                        continue
                    active[
                        executor.submit(
                            analyze_artifact,
                            artifact,
                            limits,
                            mode,
                            cancel,
                            cache_directory,
                        )
                    ] = artifact
                if not active:
                    break
                completed, _ = wait(active, timeout=0.2, return_when=FIRST_COMPLETED)
                for future in completed:
                    artifact = active.pop(future)
                    try:
                        result = future.result()
                    except (
                        AnalysisError,
                        OSError,
                        ValueError,
                        TypeError,
                        KeyError,
                        IndexError,
                        RuntimeError,
                        EOFError,
                        ET.ParseError,
                        struct.error,
                    ) as error:
                        result = {
                            "sha256": artifact["sha256"],
                            "manifest": None,
                            "endpoints": [],
                            "signals": [],
                            "sdks": [],
                            "stages": [
                                stage(
                                    "artifact_analysis",
                                    "CANCELLED"
                                    if isinstance(error, Cancelled)
                                    else "PARTIAL"
                                    if isinstance(error, BudgetExceeded)
                                    else "FAILED",
                                    artifact["sha256"],
                                    f"{type(error).__name__}: {error}",
                                )
                            ],
                            "cache": {"hit": False},
                            "statistics": {},
                            "resource_limited": isinstance(error, MemoryBudgetExceeded),
                        }
                    if result.get("resource_limited"):
                        cancel.set()
                    results[artifact["sha256"]] = result
                    record_completion(artifact, result)
                    del result
        except BaseException:
            cancel.set()
            for future in active:
                future.cancel()
            raise
    for identity in unique.keys() - results.keys():
        results[identity] = {
            "sha256": identity,
            "manifest": None,
            "endpoints": [],
            "signals": [],
            "sdks": [],
            "methods": [],
            "fields": [],
            "stages": [
                stage(
                    "artifact_analysis",
                    "CANCELLED",
                    identity,
                    "Artifact was not started",
                )
            ],
            "cache": {"hit": False},
            "statistics": {},
        }
    return results


def source_view(artifact, output, executable, limits, cancel):
    started = time.monotonic()
    resource_limited = False
    result = run_command(
        [executable, "--no-res", "-d", str(output), artifact["path"]],
        timeout=limits.timeout,
        cancel=cancel,
    )
    budget = Budget(limits, cancel)
    collector = EndpointCollector(limits, budget)
    signals = []
    total_bytes = 0
    files = 0
    stages = [
        stage("decompilation", result["status"], artifact["sha256"], result["reason"])
    ]
    try:
        if output.is_dir():
            for path in output.rglob("*"):
                budget.check()
                if (
                    path.suffix not in {".java", ".kt"}
                    or not path.is_file()
                    or path.is_symlink()
                ):
                    continue
                files += 1
                if (
                    files > limits.max_entries
                    or path.stat().st_size > limits.max_entry_bytes
                    or total_bytes + path.stat().st_size > limits.max_total_bytes
                ):
                    raise BudgetExceeded(
                        "Decompiled source scan exceeds the file or byte budget"
                    )
                data = path.read_bytes()
                total_bytes += len(data)
                for line_number, line in enumerate(
                    data.decode("utf-8").splitlines(), 1
                ):
                    budget.check()
                    source = {
                        "artifact": artifact["sha256"],
                        "entry": str(path.relative_to(output)),
                        "kind": "decompiled_source",
                        "line": line_number,
                    }
                    collector.add_text(line, source)
                    matches = signal_matches(line, source)
                    if len(signals) + len(matches) > limits.max_results:
                        raise BudgetExceeded("Source signal count exceeds the budget")
                    signals.extend(matches)
            stages.append(
                stage(
                    "source_view",
                    "PARTIAL"
                    if collector.truncated
                    or collector.evidence_truncated
                    or result["status"] != "COMPLETE"
                    else "COMPLETE",
                    artifact["sha256"],
                    "Source output or endpoint evidence is partial"
                    if collector.truncated
                    or collector.evidence_truncated
                    or result["status"] != "COMPLETE"
                    else None,
                    files=files,
                    bytes=total_bytes,
                )
            )
        else:
            stages.append(
                stage(
                    "source_view",
                    "UNAVAILABLE",
                    artifact["sha256"],
                    "No decompiled sources were produced",
                )
            )
    except (AnalysisError, OSError, UnicodeError) as error:
        if isinstance(error, MemoryBudgetExceeded):
            resource_limited = True
            cancel.set()
        stages.append(
            stage(
                "source_view",
                "CANCELLED" if isinstance(error, Cancelled) else "PARTIAL",
                artifact["sha256"],
                str(error),
            )
        )
    return {
        "endpoints": collector.results(),
        "signals": signals,
        "stages": stages,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "resource_limited": resource_limited,
    }


def merge_records(records, limits):
    merged = {}
    truncated = False
    for item in records:
        key = item["id"]
        if key not in merged:
            merged[key] = copy.deepcopy(item)
            continue
        target = merged[key]
        if item.get("evidence_level", "E0") > target.get("evidence_level", "E0"):
            target["evidence_level"] = item["evidence_level"]
        existing = {evidence["id"] for evidence in target.get("evidence", [])}
        for evidence in item.get("evidence", []):
            if evidence["id"] in existing:
                continue
            if len(target["evidence"]) >= limits.max_evidence:
                truncated = True
                break
            target["evidence"].append(evidence)
            existing.add(evidence["id"])
    return list(merged.values()), truncated


def build_apps(artifacts, results, snapshot, limits, mode, store=None, progress=None):
    groups = {}
    for artifact in artifacts:
        if store:
            store.check_cancel()
        result = results[artifact["sha256"]]
        manifest = result["manifest"]
        package = artifact.get("package_hint") or (
            manifest["package"] if manifest else None
        )
        version = (
            None
            if snapshot
            else str(manifest.get("version_code"))
            if manifest
            else None
        )
        key = (package or "unknown:" + artifact["sha256"], version)
        group = groups.setdefault(
            key, {"package": package, "version_code": version, "artifacts": []}
        )
        if artifact["sha256"] not in {item["sha256"] for item in group["artifacts"]}:
            group["artifacts"].append(artifact)
    if snapshot:
        for package in snapshot["packages"]:
            groups.setdefault(
                (package, None),
                {"package": package, "version_code": None, "artifacts": []},
            )
    apps = Apps(store) if store else []
    for _, group in sorted(groups.items(), key=lambda pair: str(pair[0])):
        if store:
            store.check_cancel()
        package = group["package"]
        installation = snapshot["packages"].get(package) if snapshot else None
        app = {
            "id": stable_id(
                "app",
                package,
                group["version_code"],
                {"serial": snapshot["serial"], "user": snapshot["user"]}
                if snapshot
                else None,
                sorted(item["sha256"] for item in group["artifacts"]),
            ),
            "package": package,
            "version_code": group["version_code"],
            "user": snapshot["user"] if snapshot else None,
            "artifacts": group["artifacts"],
            "manifests": [],
            "methods": [],
            "fields": [],
            "permissions": [],
            "endpoints": [],
            "signals": [],
            "sdks": [],
            "findings": [],
            "coverage": [],
            "installation": installation,
        }
        permission_map = {}
        truncated_categories = set()
        if store:
            store.begin_app(app)
        base_count = 0
        splits = []
        versions = set()
        for artifact in group["artifacts"]:
            result = results[artifact["sha256"]]
            app["coverage"].extend(result["stages"])
            for category in ("endpoints", "signals", "sdks", "methods", "fields"):
                if store:
                    if store.merge(
                        app["id"], category, result.get(category, ()), limits
                    ):
                        truncated_categories.add(category)
                else:
                    app[category].extend(result.get(category, ()))
            manifest = result["manifest"]
            if manifest:
                app["manifests"].append({"artifact": artifact["sha256"], **manifest})
                base_count += not bool(manifest["split"])
                if manifest["split"]:
                    splits.append(manifest["split"])
                versions.add(str(manifest.get("version_code")))
                if package and manifest["package"] != package:
                    app["coverage"].append(
                        stage(
                            "artifact_identity",
                            "PARTIAL",
                            artifact["sha256"],
                            "Manifest package does not match the device inventory",
                        )
                    )
                for permission in manifest["permissions"]:
                    key = (
                        permission["name"],
                        permission["max_sdk"],
                        permission["declaration"],
                    )
                    fact = permission_map.setdefault(
                        key, {**permission, "artifacts": []}
                    )
                    fact["artifacts"].append(artifact["sha256"])
        if installation:
            app["coverage"].extend(installation["stages"])
            app["version_code"] = installation.get("version_code")
            for fact in permission_map.values():
                granted = installation.get("permissions", {}).get(fact["name"])
                fact["granted"] = granted["granted"] if granted else None
                fact["grant_source"] = granted["source"] if granted else "not_reported"
            for name, value in installation.get("permissions", {}).items():
                if name not in {key[0] for key in permission_map}:
                    permission_map[(name, None, "snapshot_only")] = {
                        "name": name,
                        "max_sdk": None,
                        "declaration": "snapshot_only",
                        "granted": value["granted"],
                        "grant_source": value["source"],
                        "artifacts": [],
                    }
        app["permissions"] = sorted(
            permission_map.values(),
            key=lambda item: (item["name"], str(item["max_sdk"]), item["declaration"]),
        )
        for category in ("endpoints", "signals", "sdks", "methods", "fields"):
            if store:
                truncated = category in truncated_categories
            else:
                app[category], truncated = merge_records(app[category], limits)
            if truncated:
                app["coverage"].append(
                    stage(
                        "evidence_merge",
                        "PARTIAL",
                        category,
                        "Merged evidence count exceeds the budget",
                    )
                )
        complete_set = (
            base_count == 1 and len(splits) == len(set(splits)) and len(versions) <= 1
        )
        app["coverage"].append(
            stage(
                "artifact_set",
                "COMPLETE" if complete_set else "PARTIAL",
                package,
                None
                if complete_set
                else "Missing or duplicate base/split, or conflicting artifact versions; completeness cannot be established",
                available_artifacts=len(group["artifacts"]),
                parsed_manifests=len(app["manifests"]),
                base_count=base_count,
                supplied_splits=len(splits),
                installed_split_total_known=bool(
                    snapshot and installation and complete_set
                ),
            )
        )
        if not snapshot:
            app["coverage"].append(
                stage(
                    "installed_split_inventory",
                    "UNAVAILABLE",
                    package,
                    "Local input cannot establish whether all installed splits were supplied",
                )
            )
            app["coverage"].append(
                stage(
                    "permission_grants",
                    "UNAVAILABLE",
                    package,
                    "Local APK does not contain device grant or AppOps state",
                )
            )
        app["coverage"].extend(
            [
                stage(
                    "resource_reference_resolution",
                    "UNAVAILABLE",
                    package,
                    "String pools are parsed; resource IDs and qualified effective values are not resolved",
                ),
                stage(
                    "native_semantics",
                    "UNAVAILABLE",
                    package,
                    "Native libraries are inspected for strings only",
                ),
                stage(
                    "runtime_behavior",
                    "EXCLUDED",
                    package,
                    "Static analysis does not observe actual collection or transmission",
                ),
            ]
        )
        if mode != "decompile":
            app["coverage"].append(
                stage(
                    "source_view",
                    "DEFERRED",
                    package,
                    "Decompiled source scan requires explicit decompile mode",
                )
            )
        app["capabilities"] = capabilities(app["permissions"], app["signals"])
        if mode == "quick":
            app["coverage"].extend(
                stage(name, "DEFERRED", package, "Quick mode excludes dataflow")
                for name in ("method_dataflow_E3", "interprocedural_dataflow_E4")
            )
        else:
            flows, coverage = analyze_dataflow(
                app["methods"], limits, store.cancel if store else None
            )
            app["findings"].extend(flows)
            app["coverage"].extend(coverage)
        build_findings(app, store)
        app["status"] = aggregate_status(app["coverage"])
        if store:
            store.save_app(app)
        else:
            apps.append(app)
        if progress:
            progress(
                {
                    "event": "app_complete",
                    "done": len(apps),
                    "total": len(groups),
                    "app_id": app["id"],
                    "status": app["status"],
                }
            )
    return apps


def build_findings(app, store=None):
    findings = app["findings"]
    flow_count = len(findings)
    evidence_path_count = len(
        {
            evidence_path_key(
                item["data_category"], item["evidence_ids"], item["sink"]["endpoints"]
            )
            for item in findings
        }
    )

    @lru_cache(maxsize=SDK_HOST_CACHE_SIZE)
    def sdk_candidates(host):
        return tuple(
            name
            for name, purpose, _, domains in SDK_RULES
            if purpose in {"analytics", "attribution", "diagnostics", "advertising"}
            and any(host_matches(host, suffix) for suffix in domains)
        )

    def endpoint_findings():
        for endpoint in app["endpoints"]:
            if "telemetry_path_candidate" in endpoint["tags"]:
                yield {
                    "id": stable_id("finding", app["id"], endpoint["id"]),
                    "type": "telemetry_endpoint_candidate",
                    "evidence_level": endpoint["evidence_level"],
                    "endpoint_id": endpoint["id"],
                    "evidence_ids": [item["id"] for item in endpoint["evidence"]],
                    "meaning": "Path naming suggests telemetry; data collection and transmission are unproven",
                }
            if endpoint.get("host"):
                matches = list(sdk_candidates(endpoint["host"]))
                if matches:
                    endpoint["tags"] = sorted(
                        set(endpoint["tags"]) | {"sdk_telemetry_domain_candidate"}
                    )
                    if store:
                        store.update_record(app["id"], "endpoints", endpoint)
                    yield {
                        "id": stable_id("sdk_endpoint", app["id"], endpoint["id"]),
                        "type": "sdk_endpoint_candidate",
                        "evidence_level": endpoint["evidence_level"],
                        "sdk_candidates": matches,
                        "endpoint_id": endpoint["id"],
                        "evidence_ids": [item["id"] for item in endpoint["evidence"]],
                        "meaning": "Host matches a maintained SDK rule; ownership and actual network use are unverified",
                    }

    findings.extend(endpoint_findings())
    important = {}
    for signal in app["signals"]:
        if signal["type"] in SENSITIVE_SIGNALS:
            previous = important.get(signal["type"])
            if (
                previous is None
                or signal["evidence_level"] > previous["evidence_level"]
            ):
                important[signal["type"]] = signal
    for name, signal in sorted(important.items()):
        findings.append(
            {
                "id": stable_id("privacy_capability", app["id"], name),
                "type": "privacy_capability_candidate",
                "data_category": name,
                "relation": "capability_only",
                "evidence_level": signal["evidence_level"],
                "evidence_ids": [item["id"] for item in signal["evidence"]],
                "meaning": "Sensitive static capability requires review; no transmission association or actual use is established",
            }
        )
    declared_categories = {
        "installed_apps": "installed_apps_api",
        "device_identity": "device_identifier",
        "screen": "screen_capture",
        "microphone": "audio_capture",
    }
    for capability in app["capabilities"]:
        name = declared_categories.get(capability["type"])
        if name and name not in important:
            evidence = [
                {
                    "id": stable_id("declared_privacy", app["id"], permission),
                    "kind": "manifest_or_snapshot_permission",
                    "excerpt": permission,
                    "artifacts": sorted(
                        {
                            artifact
                            for item in app["permissions"]
                            if item["name"] == permission
                            for artifact in item.get("artifacts", ())
                        }
                    ),
                }
                for permission in capability.get("permissions", ())
            ]
            important[name] = {"evidence_level": "E0"}
            findings.append(
                {
                    "id": stable_id("privacy_capability", app["id"], name),
                    "type": "privacy_capability_candidate",
                    "data_category": name,
                    "relation": "declared_capability_only",
                    "evidence_level": "E0",
                    "evidence": evidence,
                    "evidence_ids": [item["id"] for item in evidence],
                    "meaning": "Declared or captured permission capability requires review; API use and data transmission are unproven",
                }
            )
    events = []
    event_level = "E0"
    for item in app["signals"]:
        if item["type"] in {"telemetry_event", "diagnostic_field"}:
            event_level = max(event_level, item["evidence_level"])
            if len(events) < 20:
                events.append(item)
    if events:
        findings.append(
            {
                "id": stable_id("telemetry_implementation", app["id"]),
                "type": "telemetry_implementation_candidate",
                "evidence_level": event_level,
                "evidence_ids": [
                    evidence["id"]
                    for item in events[:20]
                    for evidence in item["evidence"]
                ],
                "meaning": "Event APIs or diagnostic fields exist; endpoint association and actual execution are unproven",
            }
        )
    sensitive = len({item["type"] for item in app["capabilities"]})
    manifest_flags = sum(
        manifest["application"]["debuggable"] is True for manifest in app["manifests"]
    )
    app["priority"] = {
        "score": sensitive
        + min(len(findings) - flow_count + evidence_path_count, 10)
        + manifest_flags * 2
        + min(len(important), 10) * 3
        + min(evidence_path_count, 10) * 5,
        "reasons": sorted(important),
        "meaning": "Review ordering heuristic, not a measured leakage or exploit probability",
    }
    app["recommendations"] = []
    if findings:
        app["recommendations"].append(
            {
                "action": "review_static_evidence",
                "finding_ids": FindingIds(findings)
                if store
                else [item["id"] for item in findings],
                "requires_device_change": False,
            }
        )
    if any(item["granted"] is True for item in app["permissions"]):
        app["recommendations"].append(
            {
                "action": "review_granted_permissions_in_system_settings",
                "requires_device_change": True,
                "execution": "manual_only",
            }
        )
