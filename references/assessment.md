# Application Assessment Contract

The AI fills this task-specific register after inspecting evidence. It complements the deterministic report; it is not a runtime observation store or a proof that every decision is correct. Use scripts and references from the same checkout.

## Prepare, Review, Validate and Render

```sh
python3 scripts/assess_results.py prepare TASK/analysis.sqlite3 \
  --output TASK/assessment-draft --skill-revision VERIFIED_COMMIT

python3 scripts/assess_results.py validate TASK/analysis.sqlite3 \
  --assessment TASK/assessment-draft/assessment.json

python3 scripts/assess_results.py render TASK/analysis.sqlite3 \
  --assessment TASK/assessment-draft/assessment.json \
  --output TASK/assessment-final --language zh-CN
```

Omit `--skill-revision` when it is not verifiable; do not invent a commit. Both preparation and rendering require new output directories and preserve source reports. Fill the draft before validating and rendering. Rendering saves the validated `assessment.json` and derived `user-advice.md`; link both in the final response. Rendering an untouched draft is permitted but explicitly shows outstanding review, not a finished assessment. JSON reports are also accepted within the existing 256 MiB input limit; prefer SQLite for large tasks.

Preparation creates one row per application group, including targets without APKs. Preserve `schema_version`, `run_id`, `producer`, `facts`, each `identity` and captured `context`. The source report is authoritative for counts and identity; assessment IDs do not transfer to another task. Context provides installation state, sensitive candidate reasons, counts and coverage without expanding all raw evidence. Review all rows, then query exact findings, evidence and coverage as needed. Top 20, SDK matches and telemetry labels are not scope filters.

| Row state | Meaning |
|---|---|
| `pending` | Evidence has not yet been assessed; default for groups with artifacts |
| `reviewed` | Available evidence was assessed; does not establish complete code coverage or safety |
| `metadata_only` | No APK is available; code behavior remains unknown |
| `deferred` | Assessment awaits identified inputs or checks |

Set a meaningful `reason` for every non-pending state. A group without APKs cannot become code-reviewed; a group with APKs cannot hide under metadata-only. `pending` and `deferred` rows permit only deferred recommendations. Empty claims can be appropriate when no supported conclusion exists; explain the reviewed scope and unknowns in the reason. Validation returns review-state counts, `outstanding_review`, `unavailable_code` and the original `analysis_status`.

## Claims

Each claim has a unique row-local `id`, a supported `type`, a concise `text`, and relevant `finding_ids` / `evidence_ids`. Retrieve and inspect cited locations rather than copying a score.

| Type | Required support |
|---|---|
| `declaration` | E0 declaration evidence or findings |
| `static_clue` | E1/E2 clue evidence; wording remains a clue |
| `direct_call` | E2 plus an explicit `dex_invocation` or `dex_string_reference` evidence ID |
| `static_path` | E3/E4 `privacy_transmission_path` finding, with textual `limitations` covering conditions, unresolved destinations, gaps and unverified execution |
| `snapshot_grant` | Exact `permission`, boolean `granted`, `grant_source`, and `grant_scope` (`app` or `shared_uid`) from captured permission facts; no finding/evidence references |

All references must belong to this application group and its artifacts. When both findings and evidence are cited, the evidence must support those findings. Runtime observation claims are unsupported. Shared-UID grants do not establish independent per-app access, AppOps approval or effective access. A string reference and a network invocation cannot be promoted into a static path by co-occurrence.

## Recommendations

Every recommendation includes `action`, a nonempty string list `conditions`, row-local `claim_ids`, and textual `impact`, `verification` and `recovery`. Actions are `retain_restrict`, `uninstall`, `disable_optional`, `defer` or `retain`. Restrictions require supporting claims. Uninstall requires known non-system classification, and dependency review for captured shared or active roles. Unknown classification is not a third-party determination.

`prerequisites` is a list of objects with `type` (`dependency`, `role` or `reversibility`), `status` (`verified` or `unverified`) and nonempty `basis`. The basis identifies actual checks/evidence or the missing information. Optional-system disabling requires all three prerequisite types verified; otherwise defer the change and state a concrete next check. The validator checks these fields, not the truth or completeness of a dependency investigation. Do not invent a verified prerequisite to make validation pass.

## Validation Limits and Publication Review

Exit code 0 / `PASS` means structure, immutable source fields, reference ownership and supported claim levels passed. It does not mean every row is reviewed, every free-text statement is justified, disabling is safe, or an app actually transmitted data. A partial analysis stays partial after review. Rendering formats the AI-authored claims and their validated reference IDs; it does not embed evidence bodies. Retrieve those records for publication review.

Before delivery, compare every substantive sentence with the inspected evidence. Use authoritative facts for numbers. Distinguish declared permissions, string clues, code references and modeled paths. Default enablement, startup timing, background frequency, exact firmware menus, disable consequences and attribution of real-world events each need independent evidence. Keep missing APKs, omitted bodies, unstarted roots, unmodeled operations and pending assessment visible. The renderer escapes input text and redacts common URL secrets; it is not a general-purpose personal-data sanitizer.
