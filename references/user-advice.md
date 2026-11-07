# User Advice After Static Analysis

## Default Deliverable

An analysis assessment should answer what was established, which applications deserve action, and what the user should do next. Lead with the most useful actions in the user's language, then give application-specific decisions and their evidence. Do not substitute a ranking of permissions, SDKs or endpoint counts for advice, or end by asking the user to request an action list separately.

For an analysis task, prepare the full application register with `assess_results.py`, fill evidence-based decisions in `assessment.json`, validate it and render a new `user-advice.md` in a new directory. Follow the [assessment contract](assessment.md). Identify it as an AI assessment and link the underlying task and evidence. Preserve the deterministic `report.md`. For short follow-ups, answer directly unless persistence is requested.

Keep recorded conclusions, conditions and material unknowns ahead of raw statistics and the outstanding register. Report groups with evidence claims separately from `reviewed` groups and application/category coverage; these measure different things. A partial review can yield useful conclusions while no application is marked reviewed. The renderer preserves the full register and statistics after the focused advice, without upgrading states or adding analysis.

The scripts produce facts and review prompts; they do not establish the user's needs, complete system dependencies or safe remediation. Keep that distinction visible while still making useful recommendations. Do not claim every installed app was individually assessed when only a sample or summary was inspected. Page through applications for the requested scope; distinguish assessed apps, outstanding review and unavailable targets. Avoid repeating the same generic advice for hundreds of apps.

Use the authoritative `facts` projection for numbers. App-scope endpoint candidates and SDK match records must not be added to artifact-scope records. Manifest declarations, snapshot-only permissions and shared-UID grants are separate facts. Count captured targets, targets with APKs and completed artifacts separately. SYSTEM/non-SYSTEM flags do not establish factory preload or deliberate user installation. A high score, a known SDK or an address label only changes review order; direct sensitive calls and ordinary registration URLs can deserve investigation outside the displayed summary.

Use validation/rendering `source_statistics` for capability-record totals by evidence level and the original input kind. Work through each row's `evidence_inventory`: reviewed rows need source-supported claims at the highest available level or specific `deferred_evidence` reasons for every category. Review untagged endpoint candidates when findings coexist. Preserve category deferrals and `evidence_review_counts` in the final advice; one supported claim in a category does not establish exhaustive location or endpoint review.

## Review Scope and Stopping Rules

Register all targets, then distinguish automated static coverage from AI evidence review. Unless the user specifies a broader review, focus on at most three applications, with one or two decision-relevant questions each. Prefer the user's named concern and strongest available evidence; a priority score is only a discovery aid. Keep all other rows pending or deferred with the actual scope reason. The limit does not authorize sampling a few categories and marking the whole application reviewed: address the source checklist or record specific unresolved categories.

Use existing SQLite evidence first. Bound any additional local extraction or decompilation to a total of five minutes for the assessment, with per-command timeouts and no repeated retry after the same missing input or unsupported boundary. Stop when the question is supported, the budget expires, or progress requires uncollected runtime evidence, missing code or an unsupported model. Record the precise gap and what new input or explicit targeted request would justify reopening it. Missing paths are not a reason to expand automatically into every caller, native code, other applications or runtime inspection. Broader or longer review requires a user-selected scope; it is not needed to deliver the current partial assessment.

Offline scripts default to `--analysis-timeout 1800`. The budget starts after collection, verification and preflight. It stops new artifact dispatch, remaining decompilation and further dataflow work, while active artifacts finish within their existing cooperative timeout and all targets are aggregated and exported. Thus 30 minutes is an analysis-work budget, not a promise for collection, finalization or AI wall time. Deadline expiry produces a partial report with `stop_reason: analysis_timeout`; user cancellation and memory/disk stops still preserve checkpoints and may require a later resume for export. Prefer targeted follow-up to rerunning the full device scan.

## Evidence and Device Context

For each application supporting a recommendation:

1. Query `--section apps --package PACKAGE` for identity, user, application status, `installation` and recorded `recommendations`. When a package matches multiple version/artifact groups, preserve each overview's `id` and version; subsequent fact rows carry `app_id` so evidence can be attributed to the correct group. The lightweight summary omits this context. Local APKs cannot establish installed status, grants or dependencies.
2. Query relevant `permissions`, `capabilities`, `findings`, `evidence` and `coverage`. Verify the actual supporting locations. For E3/E4, inspect data categories, ordered source-to-sink evidence, conditions, endpoint resolution and dataflow gaps. Reuse known evidence; do not rescan merely to write advice.
3. Inspect `installation.package_metadata_status`, flags, shared UID, AppOps, special access and collection stage reasons. Query permissions separately for grant state and grant source. `installation=null` means no captured installation context. `is_system=null` means classification is unknown; it is derived only from complete package metadata with nonempty captured flags. The raw snapshot's false marker alone is not authoritative when metadata was missing. Empty AppOps/special-access maps are not proof that access is denied; `default` and unknown values retain their original meanings.
4. Establish the role and dependency information needed for the proposed action. Captured system flags, shared UID and special access are clues, not a complete dependency graph. The collector captures the default IME and selected special access, not every Android default role, active service or vendor dependency. Missing roles, enabled state and observed usage must not be invented from package names, prefixes, labels or scores. If the decision requires further checks, describe the exact read-only check or missing information; do not silently expand device collection.
5. Use verified display names where available; otherwise use package names. State the selected Android user and relevant version/artifact scope. An APK-only target is not evidence that the app is installed on the user's phone.

Missing captured role states cannot support a verified role prerequisite, and an AppOps approval cannot replace a service-enabled check. Preserve each recommendation prerequisite's status and basis in the advice. Support feature-preservation and restoration claims independently; a proposed verification command or nonempty recovery field does not prove that functionality or local data will be restored.

Recorded recommendations are review prompts. Their `finding_count`, up to three `finding_id_sample` values and `finding_ids_truncated` disclose bounded references; retrieve all relevant findings through the paginated findings section. A sample is not an exhaustive basis for declaring the whole app safe or malicious. No recorded recommendation is not a safety conclusion.

## Choosing an Action

Separate privacy concern from the cost and uncertainty of remediation. A static clue may justify minimizing optional access without proving misuse. Conversely, strong static dataflow evidence does not establish that a system service can safely be disabled.

| Recommendation | Appropriate basis | Required conditions and impact |
|---|---|---|
| Retain and restrict unnecessary access | The app serves a needed purpose, with optional access or features the user can reduce | Identify the actual permission, special authorization, app setting or background control to review, its captured state and affected functionality. Do not assume every declared or signature permission can be revoked in Settings, that every device exposes the same controls, or that removing one permission blocks every modeled path. |
| Uninstall or temporarily disable an unwanted third-party app | Installation classification is supported and the app is not needed, or the user explicitly wants to remove it | If usage is unknown, make the recommendation conditional. Explain the observed concern or redundancy, data/account preservation requirements and lost functionality. If the user wants to retain the app/data, assess a supported reversible disable method and its dependencies instead of assuming uninstall is appropriate. Do not label the app malicious solely to justify removal. |
| Consider disabling an unused optional system feature | The app's optional role is verified, the user does not need it, and relevant dependencies/default roles/shared responsibilities have been assessed | State remaining uncertainty, what will stop working, a reversible method available on that exact device/user, and recovery requirements. If dependency safety is unverified, recommend closing optional features and completing the specific checks before any trial disable. |
| Defer a device change and investigate | Identity, system role, dependencies, grants, evidence or necessary inputs remain unresolved | Give an actionable next step and the condition that would change the recommendation. Do not equate this with either a clean result or a requirement to investigate indefinitely. |
| Retain without a specific change from this review | Reviewed evidence and the user's requirements do not support a useful change | Describe the reviewed scope and residual uncertainty; do not declare the app safe, malware-free or incapable of unmodeled behavior. |

Treat shared-UID members, current input methods, accessibility/notification services, default-role holders and user-critical applications as dependency-sensitive. Core framework, telephony/SIM, system UI, package management, security/update and account/integration services need role-specific assessment. These are assessment criteria, not a universal package allowlist or blacklist; OEM names and responsibilities vary. A dependency-sensitive app can still deserve a privacy finding. Describe the concern and practical alternatives without inventing safety assurances.

For unfamiliar vendor AI, health, car integration, sharing, quick-app or similar features, verify which function the exact package provides before presenting it as optional. For banking, work, messaging and other third-party apps, preserve required user workflows and data. Do not infer use frequency from a static API reference or transfer a finding from another vendor, firmware or social-media post to the current device.

## Recommendation Format

Each substantive action should identify:

- Application and package, relevant version/user, and system/third-party/unknown classification.
- Proposed action and priority based on privacy benefit, user need, disruption and uncertainty; keep this separate from the engine's review score.
- What was established, the evidence level and relevant finding/evidence IDs; state separately what is still unverified.
- Prerequisites and a concrete next step. If user requirements are missing, say "if you do not use this feature" rather than inventing usage. Ask only when the missing answer determines the next action; continue independent assessment.
- Expected benefit, possible feature/data impact, how to check the outcome and how to recover. State when recovery has not been verified.

A compact table can use `Application | Action and conditions | Evidence and reason | Impact | Verification/recovery`. Expand rows when a trade-off needs explanation. If an application is recommended for removal solely because the user does not want it, say so rather than fabricating a privacy finding.

## Execution and Wording Boundaries

The request to analyze and recommend does not authorize changing the device. Do not execute disable, uninstall, permission/AppOps, firewall, account or configuration changes without separate explicit authorization. Do not install remediation tools. Recommendations should normally start with controls available in the user's device/app settings. Supply shell commands only when the user requests them, after confirming the exact package, serial, user, preconditions and corresponding recovery method. No batch disabling by score, package prefix or a generic debloat list. A trial should change one assessed target at a time and stop on a failed prerequisite or observed regression; do not treat a successful command as proof of dependency safety.

Do not claim that a guessed restore command will recover deleted data, account state, removed updates or every firmware's package behavior. If a reversible method is unavailable or unverified, disclose that before recommending execution.

Keep conclusions proportional to the evidence:

- An E2 clipboard invocation is a code-level capability, not proof of continuous monitoring or reading copied passwords.
- A URL literal or SDK match is not proof of active background transmission, payload contents or enabled tracking. E3/E4 are modeled static paths, not observed execution or authorization decisions.
- High permission counts or system privileges do not by themselves establish misuse, severity or removal suitability. Missing paths do not prove there is no upload.
- `PARTIAL` is incomplete coverage; job completion does not turn it into complete analysis. Explain failed/unreadable items using recorded causes rather than inventing vendor encryption or protection explanations.
- Static analysis is not a comprehensive malware verdict. Do not conclude "no malware" or attribute police contact, reporting to authorities or another real-world event without evidence establishing that claim.
- Extracted domains are candidates. Do not turn them into a firewall list without endpoint-purpose and shared-service review, or contact those endpoints to validate advice.
