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

Omit `--skill-revision` when it is not verifiable; do not invent a commit. Both preparation and rendering require new output directories and preserve source reports. Fill the evidence register first, run validation to obtain reporting reference keys, complete the optional `reporting` plan described below, and validate again before rendering. Rendering saves the validated `assessment.json`, `user-advice.md` and, when needed, `report-details.md`; deliver the main report and link the ledger. Rendering an untouched draft is permitted but explicitly shows outstanding review and missing editorial planning, not a finished assessment. JSON reports are also accepted within the existing 256 MiB input limit; prefer SQLite for large tasks.

Preparation creates one row per application group, including targets without APKs. Preserve `schema_version`, `run_id`, `producer`, `facts`, each `identity`, captured `context` and derived `evidence_inventory`. The source report is authoritative for counts and identity; assessment IDs do not transfer to another task. Context provides installation state, sensitive candidate reasons, counts and coverage without expanding all raw evidence. Review all rows, then query exact findings, evidence and coverage as needed. Top 20, SDK matches and telemetry labels are not scope filters.

| Row state | Meaning |
|---|---|
| `pending` | Evidence has not yet been assessed; default for groups with artifacts |
| `reviewed` | Available evidence was assessed; does not establish complete code coverage or safety |
| `metadata_only` | No APK is available; code behavior remains unknown |
| `deferred` | Assessment awaits identified inputs or checks |

Set a meaningful `reason` for every non-pending state. A group without APKs cannot become code-reviewed; a group with APKs cannot hide under metadata-only. `pending` and `deferred` rows permit only deferred recommendations. Empty claims can be appropriate when no supported conclusion exists; explain the reviewed scope and unknowns in the reason. Validation returns review-state counts, `outstanding_review`, `unavailable_code` and the original `analysis_status`.

## Rendered Advice

Preparation and rendering also save `delivery-summary.json`; validation returns the same object as `delivery_summary`. It contains `analysis_status`, `stop_reason`, `validation_status`, `review_counts`, `evidence_review_counts`, `claim_count`, `application_groups_with_claims`, `recommendation_count` and `review_complete`. Counts come from the current source-bound register. `review_complete` is true only for a valid, nonempty register with every group reviewed and no deferred/unreviewed evidence category; it is ledger coverage, not exhaustive code coverage or observed behavior. It remains false for metadata-only groups. A successful prepare/render or validation PASS cannot substitute for this distinction. With zero recorded claims/recommendations, the final response must state that none were recorded, rather than inventing conclusions or advice outside the register.

`delivery_summary` is authoritative for delivery; same-named top-level validation fields are compatibility views derived from the same counters. `claim_count` and `application_groups_with_claims` count valid source-supported claims, and `recommendation_count` counts individually valid recommendations permitted by the row's review state and referencing valid claims. Invalid entries remain visible through validation errors and are excluded from these counts, including when validation is FAILED.

The advice opens with a brief review scope, then conclusions, priorities, selected issue cards and scope/source links. Issues are selected explicitly for user decisions rather than expanded from application review states. Routine reviewed rows do not produce cards. Main-page groups with multiple applications link to their complete member details; groups placed in details are disclosed through the total issue count and details entry. A single-application main group is explained on the main page. Details with multiple sections include a complete linked contents list with member identities/counts. Each full finding/action body has one destination; the overview only indexes it. Conditional actions retain impact, verification/recovery and prerequisite checks beside their instructions.

Version and Android user identify every displayed member; a record ID is shown when visible identities collide. An optional row-level `display_name` supplies an author-verified application name; it must be nonempty text and never replaces package/version/user identity. Older rows without it use their package. The validator checks its shape, not the truth of the name; never infer a name or business purpose from a namespace.

Do not reproduce the full application register, raw JSON facts, evidence-category counters, SDK/permission statistics, AppOps inventories, evidence-level glossary or a duplicate recommendations table in `user-advice.md`. Full identities, artifact hashes, evidence IDs, review states and original row order remain in `assessment.json`; exact completion counters remain in `delivery-summary.json`. The advice links both files. Identical claim text of the same type and scope may be displayed once, but different limitations or permission states must remain visible; every original claim and reference stays in the ledger. No display limit may silently discard a substantive conclusion.

The summary separates groups with nonempty claims from groups marked `reviewed`. A selected question or captured permission claim does not complete the application assessment. Evidence totals remain application/category pairs from validation: multiple claims can address one category, while a snapshot grant does not itself cover a code-evidence category. Do not label category totals as question or claim counts. A `reviewed` group may still have explicit category deferrals; it never implies exhaustive code coverage or observed execution.

Rendering derives this presentation without editing the register, source report, review states or evidence counts. When no conclusions or recommendations exist, state each absence explicitly rather than inventing a result. Missing APKs and outstanding review are disclosed briefly, with complete per-target details in the ledger. A checked prerequisite is an author-recorded check, not a renderer guarantee of safety or recovery. Rendering does not correct unsupported historical prose: inspect and amend such claims in a new ledger before publishing a revised assessment.

## Reporting Plan

The optional top-level `reporting` object has its own `schema_version: 1`. It changes presentation, not evidence or the assessment schema. Complete it for a curated user delivery; it is not required to read or validate historical registers. Run `validate` after completing the evidence content. Its `reporting` diagnostics return the current `source_key`, `available_references`, `unassigned_references`, counts and errors. Copy reference keys from these diagnostics; do not guess hashes or use array positions.

```json
{
  "reporting": {
    "schema_version": 1,
    "source_key": "SOURCE_KEY_FROM_VALIDATION",
    "groups": [
      {
        "id": "optional-access",
        "title": "Review optional access",
        "summary": "A recorded capability warrants a conditional access decision",
        "reason": "This affects the user's requested privacy decision",
        "kind": "action",
        "placement": "main",
        "refs": [
          {"app_id": "APP_ID", "kind": "claim", "key": "CLAIM_ID"},
          {"app_id": "APP_ID", "kind": "recommendation", "key": "RECOMMENDATION_KEY_FROM_VALIDATION"}
        ]
      }
    ],
    "routine": [
      {
        "reason": "This supported library clue does not establish a separate user decision",
        "refs": [{"app_id": "APP_ID", "kind": "claim", "key": "OTHER_CLAIM_ID"}]
      }
    ]
  }
}
```

Replace all example IDs and keys with actual diagnostic values. Groups require exactly `id`, `title`, `summary`, `reason`, `kind`, `placement` and nonempty `refs`. Text fields must be nonempty. IDs match `[a-z][a-z0-9-]{0,63}` and are unique; they provide explicit document anchors. Array order sets reading order. `kind` is `action` for a group containing a validated device-change recommendation (`retain_restrict`, `uninstall`, `disable_optional`), or `attention` for an important finding, retain warning or decision-relevant gap. An attention group cannot hide a device-change recommendation. `placement` is `main` or `details`. Explain selection and placement in `reason`; do not turn engine scores into severity or invent summary facts or instructions outside the ledger.

Each reference requires `app_id`, `kind` and `key`, except `review_scope`, which omits `key`:

| Kind | Source key |
|---|---|
| `claim` | Row-local claim ID |
| `recommendation` | Stable content key returned by validation, bound to this application |
| `deferred_category` | Explicit `deferred_evidence` category key |
| `review_scope` | Application state/reason; available only for a nonempty recorded reason other than the generic missing-APK reason |

Every claim, unique recommendation content record and explicit category deferral needs exactly one primary destination: a group or a `routine` entry with nonempty `reason` and `refs`. A routine entry may cover multiple records/applications with the same actual reason. Device-change recommendations cannot be routine. Empty reviewed applications need no synthetic routine records. Review-scope references are optional; general pending/missing-code state remains in scope counts. Duplicate assignments, unknown references, stale source bindings and invalid groups fail reporting validation. Required unassigned references are returned for correction.

Recommendations can depend on claims assigned elsewhere; this does not duplicate primary ownership. Rendering brings those supporting claims and their limitations into the action body. Identical duplicate recommendations share one content reference, retain all original occurrences and counts, and display once. Recommendation content changes invalidate its key. The source key binds the source task status/stop reason and all ledger content except `reporting`; edits require reconfirming the plan against the newly returned key.

Group by a concrete question, not a vendor, SDK label, permission count or matching action name. Complete instructions merge only when findings, permission scopes, limitations, conditions, impact, verification/recovery, prerequisites and relevant captured context match. Otherwise variants retain their members and differences. Every affected member remains reachable; no Top N or display cap silently drops a finding. Routine records are not a safety allowlist. Deferred work belongs on the report only when resolving it can change an identified decision.

The delivery summary adds `reporting_status` (`missing`, `ready`, `invalid`) and `reporting_counts`. These counts describe selected issue groups, main selections, groups with detail bodies, action/attention groups, distinct affected application groups and routine references. A main selection with multiple members has its full body in details, so main/detail counts are not a partition. These fields never change the meaning of `review_complete`, claim/recommendation counts or category coverage. Evidence `validation_status` and reporting status remain separate; CLI validation/rendering exits nonzero if either evidence fails or a supplied plan is invalid. Resolve `reporting.errors` even when evidence status is PASS.

Without a plan, historical evidence remains validatable. Rendering makes a conservative main report and, only for actual claims, recommendations or explicit category deferrals, uncurated details. Empty reviewed/deferred rows are not expanded. It does not guess which existing findings are routine. A supplied invalid plan blocks rendering before the output directory is created; there is no silent fallback. `prepare` creates an unplanned register. No detail file or link is emitted when no detail body exists. Source files and historical ledgers remain unchanged.

Source/reference checks do not establish the truth of group summaries, importance judgments or equivalence of business behavior. Review those meanings before delivery; a `ready` plan can coexist with partial analysis and unfinished evidence review.

## Evidence Category Review

`evidence_inventory` groups findings by `type:data_category`, or by `type` for older findings without a category. Each item contains its `key`, source `section`, total `records`, `highest_evidence_level`, up to three `record_id_sample` values and `record_ids_truncated`. When findings and endpoints coexist, `endpoint_candidates` also requires review, including ordinary addresses with no telemetry tags. Samples disclose only a starting point; page through the source section to inspect the relevant records.

A `reviewed` row must address every inventory category with a valid claim citing a finding or supporting evidence at that category's highest available level, or explicitly defer that category. An E0 declaration cannot replace available E2 calls. Finding references also credit the evidence supporting that finding. Evidence-only claims can credit their source category. Category coverage means a source-supported claim exists, not that every location, address, condition or statement was reviewed.

Evidence strength comes from the cited position's kind, not its strongest parent record. An E1 string inside an E2 endpoint cannot cover an E2 category. E2 findings without retained instruction support cannot complete that category through a finding ID alone; retain the limitation or reparse into a new task. E3/E4 strength belongs to the modeled path relation, not each individual position along it, and `static_path` claims still require the corresponding finding.

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

Validation returns `evidence_review_counts` (`covered`, `deferred`, `unreviewed`), counting application/category pairs across the task. Deferred categories remain outstanding evidence even if their application state is reviewed. Pending, deferred and metadata-only application states retain their existing meanings. Exact totals remain in the delivery summary; each explicit deferral needs a report or reasoned routine destination, with decision-relevant gaps beside the affected advice.

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
