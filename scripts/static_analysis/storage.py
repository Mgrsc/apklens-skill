import json
import shutil
import sqlite3
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from itertools import islice
from pathlib import Path

from . import SCHEMA_VERSION
from .common import (
    MEMORY_BUDGET_MESSAGE,
    AnalysisError,
    Cancelled,
    DiskBudgetExceeded,
    JsonRecords,
    MemoryBudgetExceeded,
    check_resources,
)
from .endpoints import telemetry_candidate
from .evidence import merge_evidence
from .facts import application_facts, artifact_state
from .metrics import phase

STORE_VERSION = 4
SHARED_STORE_VERSION = 4
INDEXED_STORE_VERSION = 2
READABLE_STORE_VERSIONS = (1, 2, 3, STORE_VERSION)
SQLITE_PRIMARY_CODE_MASK = 0xFF
SQLITE_READONLY_PRIMARY_CODE = 8
STORE_CACHE_KIB = 8192
EVIDENCE_CACHE_KIB = 1024
ARTIFACT_SECTIONS = ("endpoints", "signals", "sdks", "stages", "methods", "fields")
APP_SECTIONS = (
    "endpoints",
    "signals",
    "sdks",
    "coverage",
    "findings",
    "methods",
    "fields",
)
SECTION_CODES = {
    name: index
    for index, name in enumerate(dict.fromkeys((*ARTIFACT_SECTIONS, *APP_SECTIONS)), 1)
}
EVIDENCE_SECTIONS = ("endpoints", "sdks", "signals", "findings")
EVIDENCE_INSERT_BATCH = 512
RECORD_BATCH_ROWS = 512
RECORD_BATCH_CHARACTERS = 1024 * 1024
INSERT_STATEMENT_ROWS = 100
COMPLETE_COVERAGE_STATUSES = {"COMPLETE", "NOT_APPLICABLE", "EXCLUDED"}


def application_view(app, signal_stats=None, sdk_names=None):
    if signal_stats is None:
        signal_stats = {}
        for signal in app["signals"]:
            stats = signal_stats.setdefault(
                signal["type"], {"count": 0, "evidence_level": "E0"}
            )
            stats["count"] += 1
            stats["evidence_level"] = max(
                stats["evidence_level"], signal["evidence_level"]
            )
    if sdk_names is None:
        sdk_names = {item["name"] for item in app["sdks"]}
    facts = application_facts(app, signal_stats)
    coverage_counts = Counter(item["status"] for item in app["coverage"])
    return {
        "summary": {
            "id": app["id"],
            "package": app["package"],
            "version_code": app["version_code"],
            "user": app["user"],
            "status": app["status"],
            "artifact_count": len(app["artifacts"]),
            "permission_count": len(app["permissions"]),
            "endpoint_count": len(app["endpoints"]),
            "sdk_candidates": sorted(sdk_names),
            "sdk_components": facts["sdks"].get("component_candidates"),
            "sdk_vendor_references": facts["sdks"].get("vendor_references"),
            "sdk_service_references": facts["sdks"].get("service_references"),
            "signal_types": sorted(signal_stats),
            "finding_count": len(app["findings"]),
            "priority": app["priority"],
        },
        "signals": signal_stats,
        "coverage_counts": dict(coverage_counts),
        "gap_count": sum(
            count
            for status, count in coverage_counts.items()
            if status not in COMPLETE_COVERAGE_STATUSES
        ),
        "facts": facts,
    }


@contextmanager
def checkpoint_source(path, output):
    try:
        store = AnalysisStore(path, readonly=True)
    except AnalysisError as error:
        cause = error.__cause__
        error_code = getattr(cause, "sqlite_errorcode", None)
        journal = Path(str(path) + "-journal")
        if (
            not isinstance(cause, sqlite3.Error)
            or not journal.is_file()
            or (
                error_code is not None
                and error_code & SQLITE_PRIMARY_CODE_MASK
                != SQLITE_READONLY_PRIMARY_CODE
            )
        ):
            raise
        with tempfile.TemporaryDirectory(prefix=".recovery-", dir=output) as directory:
            recovered = Path(directory) / "analysis.sqlite3"
            sources = (
                (Path(path), recovered),
                (journal, Path(str(recovered) + "-journal")),
            )
            before = [
                (source.stat().st_size, source.stat().st_mtime_ns)
                for source, _ in sources
            ]
            for source, target in sources:
                shutil.copy2(source, target)
            after = [
                (source.stat().st_size, source.stat().st_mtime_ns)
                for source, _ in sources
            ]
            if before != after:
                raise AnalysisError(
                    "Checkpoint changed during recovery; stop the original task before resuming"
                ) from error
            connection = sqlite3.connect(recovered)
            try:
                connection.execute("SELECT COUNT(*) FROM metadata").fetchone()
            finally:
                connection.close()
            store = AnalysisStore(recovered, readonly=True)
            try:
                yield store
            finally:
                store.close()
        return
    try:
        yield store
    finally:
        store.close()


def artifact_status(result):
    return artifact_state({item["status"] for item in result["stages"]})


class Records(JsonRecords):
    def __init__(self, store, scope, owner, section):
        self.store = store
        self.scope = scope
        self.owner = owner
        self.section = section

    def __len__(self):
        return self.count_records()

    def count_records(self, identity=None):
        if self.store.version >= SHARED_STORE_VERSION:
            condition = " AND identity=?" if identity is not None else ""
            return self.store.connection.execute(
                "SELECT COUNT(*) FROM record_refs WHERE owner_id=(SELECT owner_id FROM owners WHERE scope=? AND identity=?) AND section_code=?"
                + condition,
                (self.scope, self.owner, SECTION_CODES.get(self.section))
                + ((identity,) if identity is not None else ()),
            ).fetchone()[0]
        condition = " AND identity=?" if identity is not None else ""
        return self.store.connection.execute(
            "SELECT COUNT(*) FROM records WHERE scope=? AND owner=? AND section=?"
            + condition,
            (self.scope, self.owner, self.section)
            + ((identity,) if identity is not None else ()),
        ).fetchone()[0]

    def __iter__(self):
        return self.page()

    def page(self, offset=0, limit=None, identity=None):
        condition = " AND identity=?" if identity is not None else ""
        cursor = self.store.connection.execute(
            "SELECT payload FROM records WHERE scope=? AND owner=? AND section=?"
            + condition
            + " ORDER BY ordinal LIMIT ? OFFSET ?",
            (self.scope, self.owner, self.section)
            + ((identity,) if identity is not None else ())
            + (-1 if limit is None else limit, offset),
        )
        try:
            for row in cursor:
                if self.scope == "app":
                    self.store.check_cancel()
                yield json.loads(row[0])
        finally:
            cursor.close()

    def __getitem__(self, index):
        if isinstance(index, slice):
            start, stop, step = index.indices(len(self))
            if step < 0:
                return [self[position] for position in range(start, stop, step)]
            if stop <= start:
                return []
            return list(islice(self.page(start, stop - start), 0, None, step))
        if index < 0:
            index += len(self)
        if index < 0:
            raise IndexError(index)
        row = self.store.connection.execute(
            "SELECT payload FROM records WHERE scope=? AND owner=? AND section=? ORDER BY ordinal LIMIT 1 OFFSET ?",
            (self.scope, self.owner, self.section, index),
        ).fetchone()
        if row is None:
            raise IndexError(index)
        return json.loads(row[0])

    def append(self, value):
        self.extend((value,))

    def extend(self, values):
        self.store.append_records(self.scope, self.owner, self.section, values)


class FindingIds(Sequence):
    def __init__(self, records):
        self.records = records

    def __len__(self):
        return len(self.records)

    def __iter__(self):
        if (
            isinstance(self.records, Records)
            and self.records.store.version >= INDEXED_STORE_VERSION
        ):
            return self.records.store.finding_ids(self.records.owner)
        return (item["id"] for item in self.records)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [item["id"] for item in self.records[index]]
        return self.records[index]["id"]


class ArtifactResults(Mapping):
    def __init__(self, store):
        self.store = store

    def __iter__(self):
        cursor = self.store.connection.execute(
            "SELECT identity FROM artifacts ORDER BY identity"
        )
        try:
            for row in cursor:
                yield row[0]
        finally:
            cursor.close()

    def __len__(self):
        return self.store.connection.execute(
            "SELECT COUNT(*) FROM artifacts"
        ).fetchone()[0]

    def __getitem__(self, identity):
        return self.store.artifact(identity)

    def __setitem__(self, identity, value):
        self.store.save_artifact(identity, value)


class Apps(Sequence):
    def __init__(self, store):
        self.store = store

    def __len__(self):
        return self.store.connection.execute("SELECT COUNT(*) FROM apps").fetchone()[0]

    def __iter__(self):
        cursor = self.store.connection.execute(
            "SELECT identity FROM apps ORDER BY ordinal"
        )
        try:
            for row in cursor:
                self.store.check_cancel()
                yield self.store.app(row[0])
        finally:
            cursor.close()

    def __getitem__(self, index):
        if isinstance(index, slice):
            start, stop, step = index.indices(len(self))
            return [self[position] for position in range(start, stop, step)]
        if index < 0:
            index += len(self)
        if index < 0:
            raise IndexError(index)
        row = self.store.connection.execute(
            "SELECT identity FROM apps ORDER BY ordinal LIMIT 1 OFFSET ?", (index,)
        ).fetchone()
        if row is None:
            raise IndexError(index)
        return self.store.app(row[0])


class AnalysisStore:
    def __init__(self, path, readonly=False, cancel=None, budget=None, metrics=None):
        self.path = Path(path).resolve()
        self.readonly = readonly
        self.cancel = cancel
        self.budget = budget
        self.metrics = metrics
        self.positions = {}
        self.version = STORE_VERSION
        self.json_functions = None
        try:
            existing = self.path.is_file() and self.path.stat().st_size > 0
            if readonly:
                self.connection = sqlite3.connect(
                    self.path.as_uri() + "?mode=ro", uri=True
                )
            else:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.connection = sqlite3.connect(self.path)
            self.connection.execute(f"PRAGMA cache_size=-{STORE_CACHE_KIB}")
            self.connection.execute("PRAGMA temp_store=FILE")
            if readonly:
                self.connection.execute("BEGIN")
                self.version = self.metadata("store_version")
                if self.version not in READABLE_STORE_VERSIONS:
                    raise AnalysisError("Unsupported analysis database version")
            else:
                self.connection.execute("PRAGMA foreign_keys=ON")
                if existing and self.metadata("store_version") != STORE_VERSION:
                    raise AnalysisError(
                        "Existing database requires read-only access; resume into a new directory"
                    )
                self.connection.executescript(
                    "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, payload TEXT NOT NULL);"
                    "CREATE TABLE IF NOT EXISTS artifacts (identity TEXT PRIMARY KEY, status TEXT NOT NULL, payload TEXT NOT NULL);"
                    "CREATE TABLE IF NOT EXISTS apps (identity TEXT PRIMARY KEY, ordinal INTEGER NOT NULL, payload TEXT NOT NULL);"
                    "CREATE TABLE IF NOT EXISTS owners (owner_id INTEGER PRIMARY KEY, scope TEXT NOT NULL, identity TEXT NOT NULL, UNIQUE(scope,identity));"
                    "CREATE TABLE IF NOT EXISTS sections (code INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);"
                    "CREATE TABLE IF NOT EXISTS facts (fact_id INTEGER PRIMARY KEY, payload TEXT NOT NULL);"
                    "CREATE TABLE IF NOT EXISTS record_refs (owner_id INTEGER NOT NULL REFERENCES owners(owner_id), section_code INTEGER NOT NULL REFERENCES sections(code), ordinal INTEGER NOT NULL, identity TEXT NOT NULL, fact_id INTEGER NOT NULL REFERENCES facts(fact_id), PRIMARY KEY(owner_id,section_code,ordinal), UNIQUE(owner_id,section_code,identity)) WITHOUT ROWID;"
                    "CREATE INDEX IF NOT EXISTS record_refs_fact ON record_refs(fact_id);"
                    "CREATE VIEW IF NOT EXISTS records AS SELECT o.scope AS scope,o.identity AS owner,s.name AS section,r.ordinal AS ordinal,r.identity AS identity,f.payload AS payload FROM record_refs r JOIN owners o ON o.owner_id=r.owner_id JOIN sections s ON s.code=r.section_code JOIN facts f ON f.fact_id=r.fact_id;"
                    "CREATE TABLE IF NOT EXISTS domains (host TEXT PRIMARY KEY, telemetry INTEGER NOT NULL);"
                    "CREATE TABLE IF NOT EXISTS evidence_refs (app_id TEXT NOT NULL, identity TEXT NOT NULL, ordinal INTEGER NOT NULL, section TEXT NOT NULL, parent TEXT NOT NULL, position INTEGER NOT NULL, PRIMARY KEY(app_id,identity)) WITHOUT ROWID;"
                    "CREATE INDEX IF NOT EXISTS evidence_order ON evidence_refs(app_id,ordinal);"
                )
                self.connection.executemany(
                    "INSERT OR IGNORE INTO sections(code,name) VALUES (?,?)",
                    ((code, name) for name, code in SECTION_CODES.items()),
                )
                self.connection.execute(
                    "CREATE TEMP TABLE orphan_candidates (fact_id INTEGER PRIMARY KEY) WITHOUT ROWID"
                )
                self.set_metadata("store_version", STORE_VERSION)
                self.connection.commit()
        except (sqlite3.Error, AnalysisError) as error:
            if hasattr(self, "connection"):
                self.connection.close()
            raise AnalysisError(f"Cannot open analysis database: {error}") from error

    def close(self):
        self.connection.close()

    @contextmanager
    def transaction(self):
        try:
            with self.connection:
                yield
        except BaseException:
            self.positions.clear()
            raise

    def check_cancel(self):
        try:
            check_resources(self.cancel, self.budget)
        except (Cancelled, MemoryBudgetExceeded, DiskBudgetExceeded):
            if not self.readonly:
                self.connection.rollback()
                self.positions.clear()
            raise

    def metadata(self, key):
        row = self.connection.execute(
            "SELECT payload FROM metadata WHERE key=?", (key,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def set_metadata(self, key, value):
        self.connection.execute(
            "INSERT OR REPLACE INTO metadata VALUES (?,?)",
            (key, json.dumps(value, ensure_ascii=False, allow_nan=False)),
        )

    def records(self, scope, owner, section):
        return Records(self, scope, owner, section)

    def _owner_id(self, scope, identity):
        row = self.connection.execute(
            "SELECT owner_id FROM owners WHERE scope=? AND identity=?",
            (scope, identity),
        ).fetchone()
        if row is not None:
            return row[0]
        return self.connection.execute(
            "INSERT INTO owners(scope,identity) VALUES (?,?)", (scope, identity)
        ).lastrowid

    def _insert_payloads(self, key, rows):
        if not rows:
            return
        if self.budget is not None:
            self.budget.check_disk()
        owner_id = self._owner_id(key[0], key[1])
        code = SECTION_CODES[key[2]]
        first = self.connection.execute(
            "SELECT COALESCE(MAX(fact_id),0)+1 FROM facts"
        ).fetchone()[0]
        for offset in range(0, len(rows), INSERT_STATEMENT_ROWS):
            batch = rows[offset : offset + INSERT_STATEMENT_ROWS]
            self.connection.execute(
                "INSERT INTO facts(fact_id,payload) VALUES "
                + ",".join("(?,?)" for _ in batch),
                [
                    value
                    for fact_id, row in enumerate(batch, first + offset)
                    for value in (fact_id, row[2])
                ],
            )
            self.connection.execute(
                "INSERT INTO record_refs VALUES "
                + ",".join("(?,?,?,?,?)" for _ in batch),
                [
                    value
                    for fact_id, row in enumerate(batch, first + offset)
                    for value in (owner_id, code, row[0], row[1], fact_id)
                ],
            )

    def _delete_records(self, scope, identity):
        row = self.connection.execute(
            "SELECT owner_id FROM owners WHERE scope=? AND identity=?",
            (scope, identity),
        ).fetchone()
        if row is None:
            return
        self.connection.execute(
            "INSERT OR IGNORE INTO orphan_candidates SELECT fact_id FROM record_refs WHERE owner_id=?",
            row,
        )
        self.connection.execute("DELETE FROM record_refs WHERE owner_id=?", row)

    def _cleanup_facts(self):
        self.connection.execute(
            "DELETE FROM facts WHERE fact_id IN (SELECT fact_id FROM orphan_candidates) AND NOT EXISTS (SELECT 1 FROM record_refs WHERE record_refs.fact_id=facts.fact_id)"
        )
        self.connection.execute("DELETE FROM orphan_candidates")

    def append_records(self, scope, owner, section, values):
        key = (scope, owner, section)
        if key not in self.positions:
            self.positions[key] = self.connection.execute(
                "SELECT COALESCE(MAX(ordinal),-1)+1 FROM records WHERE scope=? AND owner=? AND section=?",
                key,
            ).fetchone()[0]

        rows = []
        characters = 0
        for value in values:
            if scope == "app":
                self.check_cancel()
            ordinal = self.positions[key]
            payload = json.dumps(value, ensure_ascii=False, allow_nan=False)
            self.positions[key] += 1
            rows.append(
                (
                    ordinal,
                    value["id"]
                    if scope == "app" and section == "findings"
                    else str(ordinal),
                    payload,
                )
            )
            characters += len(payload)
            if len(rows) >= RECORD_BATCH_ROWS or characters >= RECORD_BATCH_CHARACTERS:
                self._insert_payloads(key, rows)
                rows.clear()
                characters = 0
        self._insert_payloads(key, rows)

    def save_artifact(self, identity, result):
        value = {
            key: item for key, item in result.items() if key not in ARTIFACT_SECTIONS
        }
        with self.transaction():
            self._delete_records("artifact", identity)
            for section in ARTIFACT_SECTIONS:
                self.positions.pop(("artifact", identity, section), None)
                self.append_records(
                    "artifact", identity, section, result.get(section, ())
                )
            self._save_artifact_metadata(identity, value)
            self._cleanup_facts()

    def _save_artifact_metadata(self, identity, value):
        self.connection.execute(
            "INSERT OR REPLACE INTO artifacts VALUES (?,?,?)",
            (
                identity,
                artifact_status(
                    {"stages": self.records("artifact", identity, "stages")}
                ),
                json.dumps(value, ensure_ascii=False, allow_nan=False),
            ),
        )

    def has_json_functions(self):
        if self.json_functions is None:
            try:
                self.json_functions = self.connection.execute(
                    "SELECT json_valid('{}'), json_extract('{\"id\":\"x\"}', '$.id')"
                ).fetchone() == (1, "x")
            except sqlite3.OperationalError:
                self.json_functions = False
        return self.json_functions

    def raw_records(self, records, business_ids=False, check=None):
        check = check or self.check_cancel
        columns = "payload,json_valid(payload)"
        if business_ids:
            columns += ",json_extract(payload,'$.id'),json_type(payload,'$.id')"
        cursor = records.store.connection.execute(
            "SELECT "
            + columns
            + " FROM records WHERE scope=? AND owner=? AND section=? ORDER BY ordinal",
            (records.scope, records.owner, records.section),
        )
        try:
            for row in cursor:
                check()
                if row[1] != 1:
                    raise AnalysisError("Checkpoint contains invalid JSON facts")
                yield row
        finally:
            cursor.close()

    def artifact(self, identity):
        row = self.connection.execute(
            "SELECT payload FROM artifacts WHERE identity=?", (identity,)
        ).fetchone()
        if row is None:
            raise KeyError(identity)
        result = json.loads(row[0])
        for section in ARTIFACT_SECTIONS:
            result[section] = self.records("artifact", identity, section)
        return result

    def reusable(self, identity, key, retry_incomplete, source_tool=None):
        row = self.connection.execute(
            "SELECT status,payload FROM artifacts WHERE identity=?", (identity,)
        ).fetchone()
        if row is None or row[0] not in (
            {"COMPLETE"} if retry_incomplete else {"COMPLETE", "PARTIAL"}
        ):
            return False
        if (
            retry_incomplete
            and artifact_status(
                {"stages": self.records("artifact", identity, "stages")}
            )
            != "COMPLETE"
        ):
            return False
        payload = json.loads(row[1])
        if row[0] == "PARTIAL" and any(
            item["stage"] in {"dex_structure", "dex_references"}
            and MEMORY_BUDGET_MESSAGE in item.get("reason", "").split("; ")
            for item in self.records("artifact", identity, "stages")
        ):
            return False
        return (
            not payload.get("resource_limited")
            and payload.get("cache_key") == key
            and (
                not payload.get("source_view_complete")
                or payload.get("source_view_tool") == source_tool
            )
        )

    def import_artifact(self, source, identity, check=None):
        check = check or self.check_cancel

        def records(values):
            for value in values:
                check()
                yield value

        check()
        result = source.artifact(identity)
        if source.has_json_functions() and all(
            isinstance(result.get(section), Records) for section in ARTIFACT_SECTIONS
        ):
            try:
                with self.transaction():
                    self._delete_records("artifact", identity)
                    for section in ARTIFACT_SECTIONS:
                        key = ("artifact", identity, section)
                        self.positions.pop(key, None)
                        rows = []
                        characters = 0
                        ordinal = 0
                        for row in self.raw_records(result[section], check=check):
                            rows.append((ordinal, str(ordinal), row[0]))
                            characters += len(row[0])
                            ordinal += 1
                            if (
                                len(rows) >= RECORD_BATCH_ROWS
                                or characters >= RECORD_BATCH_CHARACTERS
                            ):
                                self._insert_payloads(key, rows)
                                rows.clear()
                                characters = 0
                        self._insert_payloads(key, rows)
                        self.positions[key] = ordinal
                    self._save_artifact_metadata(
                        identity,
                        {
                            key: value
                            for key, value in result.items()
                            if key not in ARTIFACT_SECTIONS
                        },
                    )
                    self._cleanup_facts()
                    check()
            except BaseException:
                self.positions.clear()
                raise
            check()
            return
        for section in ARTIFACT_SECTIONS:
            result[section] = records(result[section])
        self.save_artifact(identity, result)
        check()

    def update_artifact_metadata(self, identity, fields):
        result = self.artifact(identity)
        result.update(fields)
        value = {
            key: item for key, item in result.items() if key not in ARTIFACT_SECTIONS
        }
        self.connection.execute(
            "UPDATE artifacts SET status=?,payload=? WHERE identity=?",
            (
                artifact_status(result),
                json.dumps(value, ensure_ascii=False, allow_nan=False),
                identity,
            ),
        )

    def begin_app(self, app):
        identity = app["id"]
        self._delete_records("app", identity)
        self.connection.execute("DELETE FROM evidence_refs WHERE app_id=?", (identity,))
        self.connection.execute(
            "DELETE FROM metadata WHERE key=?", ("app_view:" + identity,)
        )
        for section in APP_SECTIONS:
            self.positions.pop(("app", identity, section), None)
            app[section] = self.records("app", identity, section)

    def merge(self, app_id, section, values, limits):
        with phase(self.metrics, "app_merge"):
            return self._merge(app_id, section, values, limits)

    def _merge_inputs(self, values):
        if isinstance(values, Records) and values.store is self:
            cursor = self.connection.execute(
                "SELECT f.payload,r.fact_id FROM record_refs r JOIN facts f ON f.fact_id=r.fact_id WHERE r.owner_id=? AND r.section_code=? ORDER BY r.ordinal",
                (
                    self._owner_id(values.scope, values.owner),
                    SECTION_CODES[values.section],
                ),
            )
            try:
                for payload, fact_id in cursor:
                    self.check_cancel()
                    yield json.loads(payload), fact_id
            finally:
                cursor.close()
        else:
            for value in values:
                yield value, None

    def _merge(self, app_id, section, values, limits):
        truncated = False
        key = ("app", app_id, section)
        owner_id = self._owner_id("app", app_id)
        ordinal = self.connection.execute(
            "SELECT COALESCE(MAX(ordinal),-1)+1 FROM records WHERE scope=? AND owner=? AND section=?",
            key,
        ).fetchone()[0]
        if (
            ordinal == 0
            and isinstance(values, Records)
            and values.store is self
            and self.has_json_functions()
            and self._seed_records(app_id, section, values)
        ):
            return False
        for value, source_fact in self._merge_inputs(values):
            self.check_cancel()
            row = self.connection.execute(
                "SELECT payload FROM records WHERE scope=? AND owner=? AND section=? AND identity=?",
                (*key, value["id"]),
            ).fetchone()
            if row is None:
                if source_fact is not None:
                    self.connection.execute(
                        "INSERT INTO record_refs VALUES (?,?,?,?,?)",
                        (
                            owner_id,
                            SECTION_CODES[section],
                            ordinal,
                            value["id"],
                            source_fact,
                        ),
                    )
                else:
                    self._insert_payloads(
                        key,
                        [
                            (
                                ordinal,
                                value["id"],
                                json.dumps(value, ensure_ascii=False, allow_nan=False),
                            )
                        ],
                    )
                ordinal += 1
                continue
            target = json.loads(row[0])
            truncated |= merge_evidence(target, value, limits.max_evidence)
            self.update_record(app_id, section, target)
        return truncated

    def _seed_records(self, app_id, section, values):
        if not self.connection.in_transaction:
            self.connection.execute("BEGIN")
        self.connection.execute("SAVEPOINT seed_records")
        source_owner = self._owner_id(values.scope, values.owner)
        target_owner = self._owner_id("app", app_id)
        code = SECTION_CODES[section]
        cursor = self.connection.execute(
            "SELECT r.fact_id,json_extract(f.payload,'$.id'),json_type(f.payload,'$.id') FROM record_refs r JOIN facts f ON f.fact_id=r.fact_id WHERE r.owner_id=? AND r.section_code=? ORDER BY r.ordinal",
            (source_owner, SECTION_CODES[values.section]),
        )
        rows = []
        try:
            for ordinal, row in enumerate(cursor):
                self.check_cancel()
                if row[2] != "text":
                    raise ValueError("Fact business identity is not text")
                rows.append((target_owner, code, ordinal, row[1], row[0]))
                if len(rows) >= RECORD_BATCH_ROWS:
                    self.connection.executemany(
                        "INSERT INTO record_refs VALUES (?,?,?,?,?)", rows
                    )
                    rows.clear()
            self.connection.executemany(
                "INSERT INTO record_refs VALUES (?,?,?,?,?)", rows
            )
            self.connection.execute("RELEASE seed_records")
            return True
        except (sqlite3.IntegrityError, ValueError):
            self.connection.execute("ROLLBACK TO seed_records")
            self.connection.execute("RELEASE seed_records")
            return False
        finally:
            cursor.close()

    def update_record(self, app_id, section, value):
        owner_id = self._owner_id("app", app_id)
        code = SECTION_CODES[section]
        row = self.connection.execute(
            "SELECT r.fact_id,f.payload FROM record_refs r JOIN facts f ON f.fact_id=r.fact_id WHERE r.owner_id=? AND r.section_code=? AND r.identity=?",
            (owner_id, code, value["id"]),
        ).fetchone()
        if row is None:
            return
        payload = json.dumps(value, ensure_ascii=False, allow_nan=False)
        if payload == row[1]:
            return
        fact_id = self.connection.execute(
            "INSERT INTO facts(payload) VALUES (?)", (payload,)
        ).lastrowid
        self.connection.execute(
            "UPDATE record_refs SET fact_id=? WHERE owner_id=? AND section_code=? AND identity=?",
            (fact_id, owner_id, code, value["id"]),
        )
        self.connection.execute(
            "INSERT OR IGNORE INTO orphan_candidates VALUES (?)", (row[0],)
        )

    def save_app(self, app):
        with phase(self.metrics, "projection"), self.transaction():
            self._save_app(app)
            self._cleanup_facts()

    def _save_app(self, app):
        value = {key: item for key, item in app.items() if key not in APP_SECTIONS}
        value["recommendations"] = [
            {key: item for key, item in recommendation.items() if key != "finding_ids"}
            for recommendation in value["recommendations"]
        ]
        ordinal = self.connection.execute("SELECT COUNT(*) FROM apps").fetchone()[0]
        self.connection.execute(
            "INSERT INTO apps VALUES (?,?,?)",
            (
                app["id"],
                ordinal,
                json.dumps(value, ensure_ascii=False, allow_nan=False),
            ),
        )
        signal_stats = {}
        sdk_names = set()
        references = []
        domains = {}
        ordinal = 0
        for section in EVIDENCE_SECTIONS:
            for record in app[section]:
                self.check_cancel()
                if section == "signals":
                    stats = signal_stats.setdefault(
                        record["type"], {"count": 0, "evidence_level": "E0"}
                    )
                    stats["count"] += 1
                    stats["evidence_level"] = max(
                        stats["evidence_level"], record["evidence_level"]
                    )
                elif section == "sdks":
                    sdk_names.add(record["name"])
                elif record.get("host"):
                    telemetry = telemetry_candidate(record)
                    host = record["host"]
                    domains[host] = max(domains.get(host, 0), int(telemetry))
                    if len(domains) >= EVIDENCE_INSERT_BATCH:
                        self._insert_domains(domains.items())
                        domains.clear()
                for position, evidence in enumerate(record.get("evidence", [])):
                    references.append(
                        (
                            app["id"],
                            evidence["id"],
                            ordinal,
                            section,
                            record["id"],
                            position,
                        )
                    )
                    ordinal += 1
                    if len(references) >= EVIDENCE_INSERT_BATCH:
                        self._insert_evidence_refs(references)
                        references.clear()
        self._insert_evidence_refs(references)
        self._insert_domains(domains.items())
        self.set_metadata(
            "app_view:" + app["id"], application_view(app, signal_stats, sdk_names)
        )
        self.check_cancel()

    def _insert_evidence_refs(self, values):
        self.connection.executemany(
            "INSERT OR IGNORE INTO evidence_refs VALUES (?,?,?,?,?,?)", values
        )

    def _insert_domains(self, values):
        self.connection.executemany(
            "INSERT INTO domains VALUES (?,?) ON CONFLICT(host) DO UPDATE SET telemetry=MAX(telemetry,excluded.telemetry)",
            values,
        )

    def app_view(self, app):
        if self.version < INDEXED_STORE_VERSION:
            return application_view(app)
        value = self.metadata("app_view:" + app["id"])
        if not isinstance(value, dict):
            raise AnalysisError("Application facts have no committed projection")
        return value

    def finding_ids(self, app_id):
        if self.version >= SHARED_STORE_VERSION:
            cursor = self.connection.execute(
                "SELECT identity FROM record_refs WHERE owner_id=(SELECT owner_id FROM owners WHERE scope='app' AND identity=?) AND section_code=? ORDER BY ordinal",
                (app_id, SECTION_CODES["findings"]),
            )
        else:
            cursor = self.connection.execute(
                "SELECT identity FROM records WHERE scope='app' AND owner=? AND section='findings' ORDER BY ordinal",
                (app_id,),
            )
        try:
            for row in cursor:
                self.check_cancel()
                yield row[0]
        finally:
            cursor.close()

    def evidence_count(self, app_id, identity=None):
        condition = " AND identity=?" if identity is not None else ""
        return self.connection.execute(
            "SELECT COUNT(*) FROM evidence_refs WHERE app_id=?" + condition,
            (app_id,) + ((identity,) if identity is not None else ()),
        ).fetchone()[0]

    def evidence_page(self, app_id, offset=0, limit=None, identity=None):
        condition = " AND identity=?" if identity is not None else ""
        cursor = self.connection.execute(
            "SELECT section,parent,position,identity FROM evidence_refs WHERE app_id=?"
            + condition
            + " ORDER BY ordinal LIMIT ? OFFSET ?",
            (app_id,)
            + ((identity,) if identity is not None else ())
            + (-1 if limit is None else limit, offset),
        )
        previous = None
        parent = None
        try:
            for section, key, position, evidence_id in cursor:
                self.check_cancel()
                if previous != (section, key):
                    row = self.connection.execute(
                        "SELECT payload FROM records WHERE scope='app' AND owner=? AND section=? AND identity=?",
                        (app_id, section, key),
                    ).fetchone()
                    if row is None:
                        raise AnalysisError(
                            "Evidence index references missing application facts"
                        )
                    parent = json.loads(row[0])
                    previous = (section, key)
                values = parent.get("evidence", [])
                if (
                    position < 0
                    or position >= len(values)
                    or values[position].get("id") != evidence_id
                ):
                    raise AnalysisError(
                        "Evidence index does not match application facts"
                    )
                yield values[position]
        finally:
            cursor.close()

    def app(self, identity):
        row = self.connection.execute(
            "SELECT payload FROM apps WHERE identity=?", (identity,)
        ).fetchone()
        if row is None:
            raise KeyError(identity)
        app = json.loads(row[0])
        for section in APP_SECTIONS:
            app[section] = self.records("app", identity, section)
        for recommendation in app["recommendations"]:
            if recommendation["action"] == "review_static_evidence":
                recommendation["finding_ids"] = FindingIds(app["findings"])
        return app

    def evidence(self, app_id):
        if self.version >= INDEXED_STORE_VERSION:
            yield from self.evidence_page(app_id)
            return
        seen = sqlite3.connect("")
        try:
            seen.execute(f"PRAGMA cache_size=-{EVIDENCE_CACHE_KIB}")
            seen.execute("CREATE TABLE evidence (identity TEXT PRIMARY KEY)")
            for section in ("endpoints", "sdks", "signals"):
                for value in self.records("app", app_id, section):
                    for item in value.get("evidence", []):
                        cursor = seen.execute(
                            "INSERT OR IGNORE INTO evidence VALUES (?)", (item["id"],)
                        )
                        if cursor.rowcount:
                            yield item
        finally:
            seen.close()

    def report(self):
        value = self.metadata("report")
        if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
            raise AnalysisError(
                "Analysis database has checkpoints but no completed report; resume the task first"
            )
        value["apps"] = Apps(self)
        return value

    def save_report(self, report):
        self.set_metadata(
            "report", {key: value for key, value in report.items() if key != "apps"}
        )
        self.connection.commit()
