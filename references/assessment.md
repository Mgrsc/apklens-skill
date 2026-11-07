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

Preparation creates one row per application group, including targets without APKs. Preserve `schema_version`, `run_id`, `producer`, `facts`, each `identity`, captured `context` and derived `evidence_inventory`. The source report is authoritative for counts and identity; assessment IDs do not transfer to another task. Context provides installation state, sensitive candidate reasons, counts and coverage without expanding all raw evidence. Review all rows, then query exact findings, evidence and coverage as needed. Top 20, SDK matches and telemetry labels are not scope filters.

| Row state | Meaning |
|---|---|
| `pending` | Evidence has not yet been assessed; default for groups with artifacts |
| `reviewed` | Available evidence was assessed; does not establish complete code coverage or safety |
| `metadata_only` | No APK is available; code behavior remains unknown |
| `deferred` | Assessment awaits identified inputs or checks |

Set a meaningful `reason` for every non-pending state. A group without APKs cannot become code-reviewed; a group with APKs cannot hide under metadata-only. `pending` and `deferred` rows permit only deferred recommendations. Empty claims can be appropriate when no supported conclusion exists; explain the reviewed scope and unknowns in the reason. Validation returns review-state counts, `outstanding_review`, `unavailable_code` and the original `analysis_status`.

## Rendered Advice

The advice starts with a readable scope summary, followed by recorded conclusions, their limitations, recommendations and prerequisites. Rows with claims, recommendations, category deferrals or a `reviewed` state appear first, regardless of their original register order. Remaining groups stay in a collapsible register with group ID, package, user, version, state and reason. Full facts and source statistics follow in a separate collapsible section. The complete identities, artifact hashes and original row order remain in the accompanying `assessment.json`.

The summary separates groups with nonempty claims from groups marked `reviewed`. A selected question or captured permission claim does not complete the application assessment. Evidence totals remain application/category pairs from validation: multiple claims can address one category, while a snapshot grant does not itself cover a code-evidence category. Do not label category totals as question or claim counts. A `reviewed` group may still have explicit category deferrals; it never implies exhaustive code coverage or observed execution.

Rendering derives this presentation without editing the register, source report, review states or evidence counts. When no conclusions or recommendations exist, say so rather than inventing a result. Markdown viewers without collapsible-section support still receive the full text; all groups and reasons remain in the file.

## Evidence Category Review

`evidence_inventory` groups findings by `type:data_category`, or by `type` for older findings without a category. Each item contains its `key`, source `section`, total `records`, `highest_evidence_level`, up to three `record_id_sample` values and `record_ids_truncated`. When findings and endpoints coexist, `endpoint_candidates` also requires review, including ordinary addresses with no telemetry tags. Samples disclose only a starting point; page through the source section to inspect the relevant records.

A `reviewed` row must address every inventory category with a valid claim citing a finding or supporting evidence at that category's highest available level, or explicitly defer that category. An E0 declaration cannot replace available E2 calls. Finding references also credit the evidence supporting that finding. Evidence-only claims can credit their source category. Category coverage means a source-supported claim exists, not that every location, address, condition or statement was reviewed.

Use the row's `deferred_evidence` list for unresolved categories:

```json
{
  "deferred_evidence": [
    {
      "key": "privacy_capability_candidate:usage_stats",
      "reason": "The caller and time-window fields require further inspection"
    }
  ]
}
```

Deferrals require a known key and a nonempty, specific reason. Duplicate keys, already-covered categories and modified inventories fail validation. Old schema-1 registers may omit these two additive fields; validation still derives the checklist from the source and rejects silent omissions in reviewed rows. Preserve historical registers; correct decisions in a new output directory rather than filling arbitrary claims or blanket deferrals merely to get PASS.

Validation returns `evidence_review_counts` (`covered`, `deferred`, `unreviewed`), counting application/category pairs across the task. Deferred categories remain outstanding evidence even if their application state is reviewed. Pending, deferred and metadata-only application states retain their existing meanings. Rendering displays these totals and each explicit category deferral.

`source_statistics` is computed from application-scope source records during validation and rendering. It preserves `input_kind` and capability-record totals by evidence level. Use it for capability numbers instead of assuming all capability records are E0 or adding artifact-scope copies. Existing `facts` and immutable context are unchanged.

The default AI review scope and follow-up budget are defined in [review scope and stopping rules](user-advice.md#review-scope-and-stopping-rules). Full registration does not require unlimited review: record actual pending/deferred work, reasons and reopening conditions. Neither the validator nor a schema field enforces the AI's elapsed time or selected scope; the agent must apply and disclose those boundaries.

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

Every recommendation includes `action`, a nonempty string list `conditions`, row-local `claim_ids`, and textual `impact`, `verification` and `recovery`. Actions are `retain_restrict`, `uninstall`, `disable_optional`, `defer` or `retain`. Restrictions require supporting claims. Uninstall requires known non-system classification, known captured role states, and dependency review for captured shared or active roles. Unknown classification is not a third-party determination.

`prerequisites` is a list of objects with `type` (`dependency`, `role` or `reversibility`), `status` (`verified` or `unverified`) and nonempty `basis`. The basis identifies actual checks/evidence or the missing information. Optional-system disabling requires all three prerequisite types verified; otherwise defer the change and state a concrete next check. The validator checks these fields, not the truth or completeness of a dependency investigation. Do not invent a verified prerequisite to make validation pass.

Missing or non-boolean captured accessibility-service, notification-listener or default-IME states prevent `role=verified`, even when an AppOps entry says allow. Known active roles can be verified as active; they still require the relevant dependency review before uninstalling. `retain_restrict` may retain explicit unverified prerequisites. Each prerequisite type appears at most once. Rendering includes its type, status and basis so missing checks cannot disappear from the user advice.

## Validation Limits and Publication Review

Exit code 0 / `PASS` means structure, immutable source fields, reference ownership and supported claim levels passed. It does not mean every row is reviewed, every free-text statement is justified, disabling is safe, or an app actually transmitted data. A partial analysis stays partial after review. Rendering formats the AI-authored claims and their validated reference IDs; it does not embed evidence bodies. Retrieve those records for publication review.

Before delivery, compare every substantive sentence with the inspected evidence. Use authoritative facts and derived source statistics for numbers. Distinguish declared permissions, string clues, code references and modeled paths. Default enablement, startup timing, background frequency, exact firmware menus, disable consequences and attribution of real-world events each need independent evidence. A source API and an address in one app do not establish a shared payload or upload. A usage query does not establish a 24-hour window without argument/field initialization evidence. Claims that restriction preserves a feature or recovery restores data need their own supporting checks; otherwise state the uncertainty. Keep missing APKs, omitted bodies, unstarted roots, unmodeled operations and outstanding evidence review visible. The renderer escapes input text and redacts common URL secrets; it is not a general-purpose personal-data sanitizer.
