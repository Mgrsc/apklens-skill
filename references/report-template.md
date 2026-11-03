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

## Telemetry and Endpoint Findings

Evidence IDs referenced by findings can be queried using `query_results.py --section evidence --id ID`. All entries here are static candidates and do not prove data was transmitted.

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
