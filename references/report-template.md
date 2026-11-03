# Static Analysis Report

- Task: `{{run_id}}`
- Status: `{{run_status}}`
- Mode: `{{mode}}`
- Applications: {{app_count}}; Endpoint and Domain Candidates: {{endpoint_count}}; Coverage Gaps: {{gap_count}}.

This report is derived from static artifacts and optional one-time device snapshots. It does not prove that applications actually collected or transmitted data. URL query parameters and credentials are redacted in this view; local JSON, SQLite, and device snapshots may contain sensitive details. Markdown tables show up to {{view_limit}} items per category; query the task's `analysis.sqlite3` in pages for large results, or use a supported legacy `analysis.json` input.

## Application Overview

| Application | Status | Artifacts | Permissions | Endpoint Candidates | SDK Candidates |
|---|---|---|---|---|---|
{{apps}}

## Permission Declarations and Snapshots

`granted=None` indicates unknown status; local APKs do not have runtime grant state. Maximum SDK, declaration type, and grant source cannot be omitted; declaration does not equal granted, and granted does not equal actual usage.

| Application | Permission | Declaration | granted | Grant Source | Max SDK |
|---|---|---|---|---|---|
{{permissions}}

## Data Access Capabilities

| Application | Capability | Evidence Level | Meaning |
|---|---|---|---|
{{capabilities}}

## SDK Candidates

| Application | SDK | Purpose | Match Basis | Evidence ID Sample |
|---|---|---|---|---|
{{sdks}}

## Privacy Paths, Capabilities and Endpoint Findings

Retrieve the complete finding with `query_results.py --section findings --id ID`, and each supporting location with `--section evidence --id ID`. Capability candidates do not establish dataflow. E3/E4 paths are modeled static possibilities; inspect conditions, endpoint status and coverage gaps. Neither category proves actual collection, upload or a privacy violation. Zero findings does not establish safety.

For `privacy_capability_candidate`, E0 declaration candidates embed permission evidence as well as `evidence_ids`; E1/E2 signal candidates reference signal evidence through `evidence_ids`. Both forms support the evidence query above.

A path's `resolved_candidate` endpoint status means that at least one retained destination passed the model's checks. It does not guarantee that all destination alternatives were retained. Rejected alternatives appear in the same application's dataflow coverage gaps with `PARTIAL` status; query `--section coverage --package PACKAGE --contains dataflow` and inspect `metrics.gaps` alongside the finding. There is no separate completeness flag on each finding.

| Application | Type | Evidence Level | Finding ID | Evidence ID Sample |
|---|---|---|---|---|
{{findings}}

## Static Signals

Counts reflect the number of matched static locations (strings, method tables, bytecode instructions, or source lines); they do not represent execution counts or distinct runtime actions.

| Application | Signal | Matches | Max Evidence Level |
|---|---|---|---|
{{signals}}

## Endpoint and Domain Candidates

`url` denotes candidates with explicit protocols, `scheme_relative` has unspecified protocol, `domain` denotes bare domain clues, and `unresolved_template` contains unresolved placeholders. Bare domains may originate from package names, documentation, tests, or samples, and should not be used directly as blocklists.

Literal endpoint extraction and library dataflow models have separate protocol scopes. A `ws`, `wss` or `mqtt` string candidate alone does not imply a modeled sending path; a modeled destination also need not appear in the literal endpoint collection.

| Application | Type | Value | Evidence Level | ID |
|---|---|---|---|---|
{{endpoints}}

## Exported or Unknown-State Components

An exported component is not automatically a vulnerability; assess in combination with component permissions, provider read/write/path permissions, platform rules, and actual attack surface. Unresolved resource references remain marked as unknown.

| Application | Type | Component | exported | Permission | Inference Basis |
|---|---|---|---|---|---|
{{components}}

## Incomplete and Unavailable Items

`PARTIAL` indicates partial completion, `FAILED` indicates failure, `UNAVAILABLE` indicates currently unattainable, and `DEFERRED` indicates not executed in this mode. None of these should be interpreted as absence of issues.

| Application | Stage | Status | Source | Reason |
|---|---|---|---|---|
{{gaps}}

## Limitations

{{limitations}}

`domains.txt` contains all valid host and bare domain candidates; `telemetry-domains.txt` contains only candidates supported by telemetry paths or SDK rules. Neither proves actual network traffic; do not apply directly to firewalls or blocklists without review.
