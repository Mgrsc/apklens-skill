# Static Analysis Report

- Task: `{{run_id}}`
- Status: `{{run_status}}`
- Mode: `{{mode}}`
- Applications: {{app_count}}; Endpoint and Domain Candidates: {{endpoint_count}}; Coverage Gaps: {{gap_count}}.

This report is derived from static artifacts and optional one-time device snapshots. It does not prove that applications actually collected or transmitted data. URL query parameters and credentials are redacted in this view; local JSON, SQLite, and device snapshots may contain sensitive details. Markdown tables show up to {{view_limit}} items per category; query the task's `analysis.sqlite3` in pages for large results, or use a supported legacy `analysis.json` input.

## Counting and Coverage Facts

Application and artifact scopes must never be added together. SDK matches are records, not distinct SDKs or applications. Inventory targets, supplied APKs, parser outcomes, method-body selection and assessment completion are separate measures. System classification does not establish factory installation or user intent.

```json
{{facts}}
```

Table display coverage follows; these limits do not establish which applications were assessed:

{{table_coverage}}

## User Actions and Review Context

The table provides recorded review prompts and captured context. For a user-facing assessment, give application-specific recommendations to retain and restrict unnecessary access, uninstall an unwanted third-party app, consider disabling an unused optional system feature after dependency review, or defer a device change pending missing evidence. Explain the reason, finding/evidence IDs, prerequisites, expected feature loss, verification and recovery. The Skill's `references/user-advice.md` defines the decision criteria; the AI assessment is saved separately as `user-advice.md` when the analysis is performed through the Skill.

Review priority, permission counts, SDK matches and static API references alone do not establish that disabling an app is appropriate. Usage requirements and dependency safety have not been established by these scripts. An incomplete analysis does not show that an app is safe or malicious. Changes to the device require separate explicit authorization.

System classification is unknown when package metadata is incomplete or flags are absent/empty. A system classification does not identify a critical service or prove dependency safety; a third-party classification does not imply an app is unnecessary. Shared UID absence is not proof of isolation. Special access values are snapshot facts: `None` means unknown, and AppOps `default` is not permission approval. Query `--section apps --package PACKAGE` for metadata statuses, AppOps and bounded recommendation finding samples, then query permissions, findings, evidence and coverage for the decision.

| Application | System Classification | Shared UID | Special Access Snapshot | Review Prompts | Finding ID Sample | App Status |
|---|---|---|---|---|---|---|
{{recommendations}}

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
