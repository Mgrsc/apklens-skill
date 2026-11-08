# Privacy Models and Limits

This is a static APK analysis capability. It does not run applications, capture traffic, hook processes, probe endpoints, install dependencies or alter device settings. Models use the Python standard library; optional jadx text does not create E3/E4 evidence.

## Evidence and Queries

`privacy_capability_candidate` indicates a declared capability or static clue. It does not require a known SDK or a telemetry-like URL. `privacy_transmission_path` indicates a modeled static possible source-to-network path, with E3 for one method and E4 when evidence spans methods. User-authorized transmission is still detected; legality, consent and business necessity are separate questions.

Signal-derived capabilities retain the strongest evidence level recorded for their category, independent of signal order. Permission declarations remain E0; an E2 capability indicates an API invocation reference, not execution or transmission.

All `privacy_capability_candidate` records provide `evidence_ids`. E0 declaration candidates also embed their permission evidence because it is not carried by a signal. E1/E2 signal candidates reference evidence held by `signals` and do not embed an `evidence` array. Query each ID through the `evidence` section, scoped to the same application when needed; consumers should not require every candidate to embed evidence.

```sh
python3 scripts/query_results.py TASK/analysis.sqlite3 --section findings
python3 scripts/query_results.py TASK/analysis.sqlite3 --section findings --id FINDING_ID
python3 scripts/query_results.py TASK/analysis.sqlite3 --section evidence --id EVIDENCE_ID
python3 scripts/query_results.py TASK/analysis.sqlite3 --section methods --package PACKAGE
python3 scripts/query_results.py TASK/analysis.sqlite3 --section fields --package PACKAGE
python3 scripts/query_results.py TASK/analysis.sqlite3 --section coverage --contains dataflow
```

Paths contain ordered `evidence`, `evidence_ids`, `data_category`, branch/callback `conditions`, and `sink.endpoint_status`. Recovered endpoints remain candidates and can be unresolved. Source evidence includes recoverable literal arguments, such as usage windows or virtual-display dimensions. An API configuration value is not an observed duration, frame rate or capture result. Constructed endpoint candidates in paths do not expand the literal extractor's `domains.txt` scope automatically.

`resolved_candidate` means that at least one retained destination passed the model's endpoint checks; it does not establish a complete destination set. When valid and rejected alternatives meet, a finding can retain the valid addresses with this status while rejected alternatives appear in the application's dataflow coverage gaps and make the stage `PARTIAL`. Findings have no separate destination-completeness flag. Inspect the same application's `method_dataflow_E3` / `interprocedural_dataflow_E4` coverage, including `metrics.gaps`, before treating the retained addresses as exhaustive.

Every indexed method definition is a candidate root. The analyzer does not prove that an Android lifecycle or UI entry invokes it. A disabled or unreachable method may still contain a possible path. Review conditions and app coverage before describing behavior; zero paths is not a safety conclusion.

## Supported Sources and Processing

Exact source and transform signatures, including modeled overloads, are maintained in `scripts/static_analysis/privacy_models.py`. Owner, method and descriptor matter; a custom method named `getImei` is not a platform identifier source.

Exact invocation gating applies to the categories covered by these privacy models. Existing SMS, location, contacts and clipboard invocation clues retain their E2 matching behavior; that does not add E3/E4 source models for them.

Ordinary boxing and String/byte conversion retain dataflow provenance without creating extra encoding signals. Explicit Base64, compression and cryptography signatures continue to produce their existing rule clues. Processing support and signal classification are separate decisions.

Bare `versionName` / `versionCode` names and ordinary application-owned version fields do not create sensitive fingerprint clues. Complete `android.content.pm.PackageInfo` version-field signatures and signing clues remain E1 candidates; modeled package-information and signing invocations retain their precise API matching and source semantics.

| Area | Current modeled behavior |
|---|---|
| App information | Installed packages/applications, selected PackageInfo/ApplicationInfo and signing APIs |
| Usage and traffic | Selected UsageStatsManager, NetworkStatsManager and TrafficStats calls; event/bucket output parameters |
| Identifiers | Selected TelephonyManager/SubscriptionInfo, Build serial and literal `android_id` access |
| Audio | AudioRecord output buffers; MediaRecorder audio output to an associated literal file |
| Screen | MediaProjection virtual-display Surface association with a MediaRecorder output file |
| Payloads | Object fields, arrays, JSON, maps/bundles, map-entry value iteration, and selected list/iterator operations |
| Transformations | Selected String/byte conversion, boxing, Base64, Cipher/MessageDigest and stream wrappers; transformations retain provenance |
| Network | Modeled URL/HTTP/Socket output streams and OkHttp request-body/build/newCall/execute or enqueue chains |
| Intermediate files | Known literal file association within the current analyzed path; unresolved contents or deletion outcomes remain gaps |
| Calls | Unique application method definitions, parameters/returns and object identity across supplied splits of the same app |
| Asynchronous handoff | Resolvable Runnable targets through Handler.post, Executor.execute or Thread.start |

Some library summaries use explicit owner/method/prototype-shape checks rather than parsing their implementations. These are model assumptions, not proof of the installed library or platform behavior. Application implementations available in the index take precedence over external summaries.

## Control Flow and Unknowns

Supported moves, constants, registers, field/array accesses and invoke instructions feed bounded path states. Known integer conditions prune branches; unknown conditions explore alternatives with recorded conditions. Selected integer operations recover constants. Try-handler edges are preserved. Loops stop when a path revisits an instruction and report a gap; recursion, switch/array payload semantics and unsupported instructions are not solved by a general symbolic engine.

The five long/float/double comparison instructions preserve operand provenance, overwrite their destination and continue with an unknown numeric result. They do not introduce exception-handler edges. Comparison constants are not folded, including floating-point bit patterns and NaN cases; later branches retain their uncertainty. Polymorphic/custom invokes and method-handle/type constants remain explicit unsupported boundaries.

Serialization/encoding results are snapshots of modeled content, not live aliases of later object mutations. Known object fields/JSON keys are distinguished. Unknown calls are recorded and mutable argument facts are invalidated rather than silently treated as pure functions. This can reduce recall, but it does not turn unresolved behavior into safety.

Known list indexes select their modeled elements. URLConnection output requires `setDoOutput`; known closed streams, including modeled wrapper/delegate closure, and zero-length slices do not create transmission paths. Reopening a known file in overwrite mode clears its modeled contents; append retains prior content. Unknown append modes and recorder overloads are gaps. Stream writes are modeled as possible sinks without simulating complete buffering, flush, recorder lifecycle or platform failure behavior. Exception edges carry explicit conditions without resolving exception type feasibility.

URL endpoint literals must be strings accepted by the model's absolute-URL checks. URL construction supports `http`, `https`, `ftp`, `ftps` and known non-network `file` URLs; OkHttp string URLs support only `http` / `https`. Network URLs require a host, and explicit ports must be in the range 1–65535. Invalid types, parsing failures and unsupported schemes produce located dataflow gaps instead of aborting the batch; non-string values are never coerced into addresses. Accepted endpoint candidates retain their original spelling, and flow emission rechecks propagated destinations before identity and ordering operations. Rejected destinations cannot become `resolved_candidate`; an OkHttp path may remain with an unresolved endpoint and partial coverage. These are bounded syntax and protocol-model checks, not complete Java/OkHttp URL validation, DNS resolution or proof that a connection can succeed.

Literal endpoint extraction uses a separate protocol set: `http`, `https`, `ws`, `wss`, `mqtt`, `mqtts`, `tcp`, `tls` and `udp`. Its `endpoints` records describe string candidates; E3/E4 paths depend on the modeled library calls above. A `wss://` literal can therefore be listed without a modeled sending path, while passing it to the modeled URL constructor produces a gap. Conversely, a modeled FTP destination need not have a protocol-URL record in `endpoints`. Neither collection is an exhaustive projection of the other.

Native/abstract implementations, reflection, dynamic loading, WebView/script, Binder/IPC and unknown callbacks remain located boundaries. No automatic native decompiler, cross-process propagation, complete class hierarchy, lifecycle solver or runtime evidence subsystem is included.

Map-entry iteration models `Map`/`HashMap`/`LinkedHashMap.entrySet`, the corresponding Set/Collection iterator, `Iterator.next` and `Map.Entry.getValue`. Values are read from the backing map when requested, including modeled prior value replacement; opaque map-source values retain provenance in a heap object. Entry values are aggregated, not selected by a precise key or iteration order. Entry keys, iterator removal and fail-fast concurrent-modification behavior remain unmodeled boundaries. This support preserves a local dataflow segment; it does not establish a full application upload path or actual execution.

## Resource Bounds and Persistence

| Bound | Default |
|---|---:|
| Retained method definitions per artifact | min(4,096, configured max results), shared across all DEX files |
| Definitions indexed for application interpretation | 8,192 |
| Retained fields per artifact | Configured max results; normally 50,000 across all DEX files |
| Indexed code units per artifact | min(131,072, configured max references); normally 100,000 |
| Code units per method / analyzed registers | 16,384 / 1,024 |
| Application interpretation steps | 100,000 |
| Steps per candidate root, shared by recursive calls | 2,048 |
| Candidate pool per artifact | min(4 × method cap, configured max results), bounded by 8 MiB estimated metadata |
| Application admission candidate pool | 4 × application index cap, bounded by 8 MiB estimated metadata |
| Retained call targets per method / neighborhood depth / edges | 64 / 4 / min(65,536, configured max references) |
| Distinct definition identities per artifact / application | min(100,000, configured max references) at each layer |
| Call depth / per-method path states | 4 / 128 |
| Heap objects / field or array slots per object | 256 / 128 |
| Sources or aliases per value | 8 |
| Path nodes | min(32, configured evidence cap); normally 20 |
| Propagated string constant length | 1,024 characters |
| Retained flow findings per application, including condition variants | min(1,000, configured result cap) |
| Condition variants per category, ordered evidence path and endpoint set | 4 |
| Displayed dataflow gaps | 256 plus an explicit truncation marker |
| SQLite method lookup cache per application analysis | 64 entries and 4 MiB estimated retained object size |

Application method/field facts merge the retained artifact facts without an additional application-wide retention cap. Their queryable totals can exceed the interpretation index limit. Exceeding that interpretation limit reports partial coverage without deleting the remaining facts. Prefer SQLite pagination for large results rather than loading the full JSON export.

Method retention is two-phase across an artifact's DEX files: discover bounded locators, invocation categories and call neighbors, then select and decode bodies. Sensitive sources, caller/callee neighborhoods and network operations receive rotating opportunities across category and DEX groups, with ordinary methods also considered. A full candidate pool can replace lower-priority entries for later candidates; discovery and metadata limits still leave unknown regions. Selection favors smaller bodies within a group and is not a guarantee of semantic recall. It never excludes code by vendor or library package prefix.

Reference scanning and definition enumeration have separate stopping boundaries. Exhausting the E2 reference-record cap stops further invocation/string reference scanning in that DEX, while bounded class-data enumeration continues to retain definition identities and available code headers. Later methods lack complete role/neighbor clues and remain part of the disclosed reference gap. A malformed method body records its own gap and does not skip later definitions in the same class. Cancellation, time, memory, class-data corruption and the identity cap still stop or invalidate definition coverage; this separation never raises or bypasses the reference budget.

Only needed DEX files are reread, hashed against discovery and decoded. `bytes_read` includes both passes and remains subject to the archive read limit; `unique_bytes_read` separates first-pass input coverage. `dex_body_selection` exposes considered/candidate/selected/retained methods, code units, omitted bodies and neighbors, and second-pass bytes. `candidate_metadata_bytes` is conservative estimated object accounting, not measured RSS or a hard memory bound. Old results without these metrics remain unknown; method-ID table length is not reconstructed as a definition denominator.

Application index admission uses the same bounded categories and neighborhoods across retained splits. Each artifact persists a bounded definition summary: sorted full SHA-256 identities packed as Base64, sorted positions of duplicate identities and a completeness flag. Singleton membership is required because another split can contain the same signature even when its body was omitted; duplicates alone cannot preserve this guarantee. No per-definition count table is persisted. Candidate multiplicities are checked against one artifact summary at a time without constructing a second application-wide identity table. Existing digest/count summaries remain readable without rewriting source data. The identity cap and cooperative resource checks remain in force.

Incomplete discovery or absent legacy identity summaries defer application interpretation rather than treating retained copies as unique. `definition_inventory` records completeness and reasons for the artifact summaries inspected before any global resource stop; `interpretation_deferred` makes identity-based deferral explicit, while considered/indexed method counts still describe the retained candidates. Excluding only the known signatures of an unreadable DEX would be unsound: its missing definitions could duplicate any other signature. Roots share the application step budget but have separate local quotas; exhausting a root records its stopping location and permits later roots. Global time/steps, memory and cancellation still stop analysis. Metrics distinguish definitions considered, index omissions, roots started/not started, local truncations, missing bodies and returned executions (`methods`); none proves Android runtime reachability or absence of unknown operations. `gap_occurrences` counts occurrences by reason beyond the gap display cap, with an explicit sample truncation flag.

Selection and scheduling semantics use engine 1.3.3, rule version 7 and privacy model 6. Model 6 adds map-entry value propagation; engine/rule updates distinguish component/vendor/address references, preserve instruction witnesses and narrow direct-call candidates. Incompatible caches/checkpoints are reparsed on a new-directory resume. New tasks use SQLite store version 4 and JSON schema 1; existing store versions 1/2/3 remain readable without rewriting them or inventing missing metrics.

Flow identity still includes the complete recorded conditions and endpoint set. Each evidence-path group retains up to four separate condition variants, preserving the conditions associated with each retained address. Exact retained identities are deduplicated before checking capacity. When the application result budget is full, a newly encountered group can replace the last retained variant of a donor group. Donors are selected in the order they acquired multiple retained variants; at least one variant of each donor remains. An existing group cannot displace another group to add a variant. Rejected and replaced variants produce located coverage gaps and partial status. This is bounded retention, not lossless condition aggregation; independent groups beyond the total result cap can still be omitted with a result-budget gap.

Review priority counts distinct category, ordered evidence-path and endpoint groups in both the flow and total-finding score contributions. `finding_count`, finding IDs and paginated queries still count the actual retained records, including condition variants.

The lookup cache holds only method definitions, never execution states or return summaries. Root reads reuse existing cache hits but do not admit misses; call-site lookups admit eligible definitions. A helper interpreted as a root before its first call may therefore require a second read. Entries too large for the byte budget bypass it; eviction respects both limits, and hits still check cancellation, time and memory. Object-size accounting is conservative and can count shared objects more than once; it is not a process RSS limit or an allocation bound for decoding one method.

The existing timeout and cooperative memory budget apply to each application analysis. Offline scheduling additionally defaults to `--analysis-timeout 1800`: dataflow uses the smaller of the remaining offline budget and the per-application timeout; after expiry, unstarted dataflow stays deferred with unknown metrics. Registration, merging and export still finish, so this is not a hard task wall-clock limit. Bounds, unknowns and source positions appear in `method_dataflow_E3` / `interprocedural_dataflow_E4` coverage metrics; budget exhaustion is partial, never a clean negative. Quick mode defers bodies and dataflow. OS-level memory isolation is not supplied by the analyzer.

Both dataflow stage records describe the same bounded interpretation run and share its metrics and gaps. They are not independent execution counts or separate budgets and must not be added together as such.

Artifact structure, app paths, coverage, evidence references and compact views use the existing SQLite transaction machinery. New tasks write store version 4, retaining JSON schema 1 and read-only support for existing store versions 1/2/3 without adding a migration framework. Rule, engine and privacy-model identities invalidate cache/resume results when semantics change. App dataflow is rebuilt from compatible artifact facts; source tasks are not rewritten.

Summary output lists important review totals and how many fall outside its 20-app display cap. Paginated queries remain the source for all targets and evidence; the display cap never limits detection.

`review_required_total` counts applications with review-priority reasons, including declared capabilities and sensitive static clues. It is neither a count of proven privacy issues nor a requirement for an E2 signal or E3/E4 path. Declaration-only candidates remain visible even when no transmission path is modeled.
