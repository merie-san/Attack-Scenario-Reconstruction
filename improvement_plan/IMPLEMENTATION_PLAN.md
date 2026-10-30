# Attack Scenario Reconstruction Implementation Plan

Prepared on 27 October 2026 for revision `cb12d9bef1be775540b12cac667bf4f439624933`.

## Recommended approach

<u>Establish trustworthy evaluation, repair time and state handling, make recovery deterministic and reversible, then rebuild the data and model baseline before adding bounded multi-hop search.</u>

The first release should retain the current modular architecture and the six known campaign attack types. Keep each major behavior change in a reviewable change set, with versioned experiment results. The supporting [feasibility review](FEASIBILITY_REVIEW.md) records the evidence and corrections to the original proposal.

## Delivery sequence and effort

Estimates assume one experienced Python and machine-learning developer working full time. They include focused regression checks and documentation, but exclude delays obtaining data and long training runs. They are planning estimates, not measured delivery times.

| Phase | Deliverable | Estimated developer days | Depends on |
| --- | --- | --- | --- |
| 0 | Reproducible baseline and data inventory | 1–2 | Available code and existing environment |
| 1 | Stable identities and corrected evaluation | 3–5 | Phase 0 |
| 2 | Correct timestamps, state snapshots, grouping, and runtime behavior | 5–8 | Phase 1 definitions |
| 3 | Transactional single-hop recovery with type alternatives | 3–5 | Phase 2 |
| 4 | Validated preparation and calibrated model baseline | 5–10 | Phases 0–2 and restored source data |
| 5 | Paired end-to-end evaluation and release decision | 2–4 | Phases 3–4 |

**Initial scope: approximately 19–34 developer days, or 4–7 working weeks**, provided the data is available. Phase 4 can begin while Phase 3 proceeds, but data access remains its prerequisite. Bounded multi-hop recovery is an optional additional 5–10 days after the initial baseline; broader probabilistic tracking needs a separate estimate.

## Phase 0 Establish reproducibility

Inventory the raw captures, extracted flows, annotation intervals, start-time metadata, train/test datasets, and scored event datasets. Record provenance, hashes, timestamp origin, units, and the notebook execution order. Identify which published results can actually be regenerated.

Record Python 3.14.6 as the currently tested interpreter and document the intended supported version. Separate runtime dependencies from optional preprocessing and notebook dependencies. Add a repeatable test command and a small self-contained campaign fixture that requires no private data.

Introduce a run configuration containing paths, thresholds, grouping gaps, seed, and output locations. Seed both Python and NumPy. Save generated scenario manifests and original flow IDs so each model and threshold configuration is evaluated on the same scenarios.

Acceptance criteria:

- The existing 66-test baseline and environment are recorded before changes.
- A small fixture runs from a clean checkout without external datasets.
- Repeating a seeded run reproduces the same scenario identities, inputs, and metrics.
- Missing data produces a clear inventory of required files and an actionable error.

## Phase 1 Correct identities and evaluation

Give each input flow a stable event ID and each actual or predicted step a distinct instance ID. Preserve source IP, source port, destination IP, destination port, protocol, and timestamps as evidence. Step grouping may deliberately span ports, but event identity must distinguish them.

Use exact identity for equality and hashing; keep time tolerances and unknown-type matching in explicit matching functions. Avoid approximate equality for dictionary keys and sets.

Use maximum-cardinality one-to-one matching for step precision and recall, with a documented temporal-distance cost and deterministic tie-break. Prevent duplicate predictions from receiving duplicate coverage credit. Define association correspondence separately so fragmented predictions can retain their provenance without being silently discarded. Handle unknown attack types consistently and report known-type and unknown-tolerant scores separately.

Implement the selected full-coverage association contract: form actual pairs from all eligible actual observations and predicted pairs from all eligible predictions. Count correct correspondences in the numerator. Missed actual pairs lower completeness, and spurious predicted pairs lower soundness. Define ties, overlap, empty and singleton cases, and fragmented correspondence explicitly. Version the new scores separately from the original conditional definitions.

Acceptance criteria:

- Two correctly associated detected steps out of ten yield step recall 0.2, soundness 1.0, and full pair completeness `1/45`.
- Two correctly grouped detected alerts out of a three-alert actual step yield soundness 1.0 and full aggregation completeness `1/3`.
- One prediction cannot cover two repeated actual step instances in precision/recall.
- An unmatched third prediction added to two correct steps yields full pair soundness `1/3`.
- Unknown predictions with compatible hosts and timing receive credit; wrong hosts/timing and incorrect known types do not.
- Splitting three matched alerts into a pair and singleton yields soundness 1.0 and completeness `1/3`.
- Merging two matched two-alert steps yields soundness `1/3` and completeness 1.0.
- Single-class confusion matrices return four counts using fixed labels `[0, 1]`.
- Every result states its metric version; old and new figures are never silently combined.

Primary files: `scenario_generator/compute_metrics.py`, identity classes in `scenario_reconstructor/scenario_reconstructor.py`, and `tests/test_compute_metrics.py`.

## Phase 2 Repair time state and runtime behavior

Normalize timestamps at ingestion to timezone-aware UTC and use milliseconds for stored durations and inter-flow statistics, matching the existing event input format. Determine each source's actual timezone before conversion; subtracting two hours is not a substitute for timezone localization and daylight-saving rules.

Set exploit intervals to minimum flow start and maximum flow end in both reconstruction and generator ground truth. Define inter-flow gaps as the next start minus the prior end; document that overlap can create a negative gap even when all individual durations are valid.

Replace timestamp standardization with one shared interval grouping function. Initially use sorted intervals and an explicit maximum gap in milliseconds. Add a maximum step span if long chains of small gaps would otherwise merge separate actions. Tune the gap using validation captures, not the final test set.

Copy host attribute sets into immutable historical snapshots. Include the relevant external-host state in the state representation used for explanations and recovery. Make host resolution consistent for checking and applying postconditions, while retaining an explicit policy for two external endpoints.

Preserve final results when periodic logging is enabled. Separate accepted evidence from the logging cursor and the active grouping buffer. Recompute or finalize step groups consistently across logging boundaries; a cursor alone does not solve groups whose membership changes later.

Repair empty host-attribute deserialization, runner invocation with `sys.executable`, checked subprocess failures, explicit log/data directories, and threshold validation. Use the same threshold boundary in detection metrics and manager acceptance. Give scenario generation feasible candidate selection, deduplicated host pools, positional subsampling, input checks, retry limits, and a maximum scenario length.

Acceptance criteria:

- A one-second flow yields a one-second exploit; generator and reconstructor use the same interval convention.
- Identical timestamps, distinct nearby flows, overlaps, and separated sessions have documented outcomes.
- A saved state never changes after later host updates.
- Logging on and off yields equivalent final alerts and steps without duplicate log entries.
- Supported external-destination traffic completes without a host lookup crash.
- An impossible generator configuration terminates with a clear error.
- Boundary-score events are classified consistently across the manager and metrics.

Primary files: `event_convertor/flow_event_generator.py`, `scenario_reconstructor/scenario_reconstructor.py`, `scenario_generator/scenario_generator.py`, `scenario_reconstructor/reconstruct_cAPTure.py`, and `run_scripts.py`.

## Phase 3 Repair single hop recovery

Preserve the full per-type score vector and original event ID when converting events to flow exploits. Store each suspect once and maintain secondary indexes for endpoint pairs and viable types. Use tuple keys rather than parsing hyphen-delimited group strings.

Search both primary and alternative types without altering the stored evidence. For each candidate, verify endpoint compatibility, its own preconditions, and temporal availability. Adopt `support.end_time <= trigger.start_time` as the conservative causal rule, with any alternative overlap or tolerance policy explicitly configured and tested.

Evaluate a recovery proposal in temporary state at the relevant event times. Replay affected accepted events when inserting older evidence; do not justify a past event using attributes learned later. Recheck the trigger after recovery. Commit host updates, accepted evidence, correlations, and consumed suspects together only when the entire proposal succeeds.

Remove only consumed event IDs from suspect storage. Keep unrelated clusters and maintain bounded retention. Record which event, candidate type, score, and rule supported each inferred step. Treat ranking scores as a documented heuristic until model scores have been calibrated; do not multiply scores and call the result a probability.

For unknown alerts, preserve unresolved evidence without immediately granting all compromise attributes. Keep the current wildcard policy as an explicit comparison configuration so its recall and false-positive tradeoff can be measured.

Acceptance criteria:

- A misclassified suspect with the correct alternative repairs a known single-missing-step scenario.
- Future or expired evidence is rejected, and an event ID cannot be recovered twice.
- Failed proposals leave state, histories, external-host registries, and suspect storage unchanged.
- Unused suspect clusters survive a successful recovery.
- Unknown evidence does not assert all five compromise attributes under the new policy.

Primary files: `scenario_reconstructor/attack_mapper.py`, `scenario_reconstructor/reconstruction_manager.py`, and the reconstruction data classes.

## Phase 4 Rebuild the data and model baseline

Extract notebook transformations into callable, versioned preparation functions while retaining the notebooks for inspection. Validate addresses using an IP parser and make MAC mapping capture-aware, with conflict reporting. Do not resolve the same MAC to one arbitrary address across unrelated captures.

Replace substring-based feature handling with an explicit schema. Preserve categorical tuples, reset indexes deliberately, sample complete rows, and enforce integer counts, physical bounds, directional totals, and timestamp/duration consistency. Consider resampling valid benign flows before adding perturbation. Split original captures or campaign/step groups before creating augmented copies.

Freeze training, calibration, validation, and final test partitions. Derive feature schemas and known class policy from training data only. Fit encoding, imputation, and scaling within the applicable training partition or cross-validation fold. Start with training-constant feature removal and compare rare-feature retention on validation data.

Compare weighted and unweighted logistic regression and XGBoost mappers. Keep the current one-vs-rest approach as a baseline before testing multiclass mapping. If a mapper is trained on malicious flows only, interpret its outputs as conditional on maliciousness and preserve the separate anomaly gate.

Calibrate using independent predictions and adequate positive examples per class. Start with sigmoid calibration and compare isotonic only when the calibration sample supports it. Track reliability, Brier score, log loss, per-class precision/recall, and precision-recall AUC. Select operating thresholds using validation costs or a declared false-positive budget. ECDF ranks may normalize anomaly scores but must not be presented as maliciousness probabilities. [Calibration reference](https://scikit-learn.org/stable/modules/calibration.html).

Acceptance criteria:

- Generated data passes the schema without new missing categories, invalid counts, or inconsistent timing.
- No original event group or augmented copy crosses the partition boundary.
- Final test labels do not influence preprocessing, threshold selection, or the known class list.
- Each model export includes preprocessing, class order, calibration, thresholds, seed, and data provenance.
- Improvements are measured on restored data rather than inferred from cleaner code.

Primary files: the preprocessing notebooks, `requirements.txt`, and new reusable preparation/training modules.

## Phase 5 Evaluate and decide on release

Evaluate all configurations against the same saved scenario manifests. Include a perfect-score oracle to isolate reconstruction errors, plus real model scores to measure the complete pipeline. Use all tested seeds for paired comparisons and report variability at scenario or capture level rather than treating correlated flows as independent samples.

Add changes in stages: evaluation and contracts, temporal grouping, alternative-type recovery, unknown handling, repaired data, class weighting, and calibration. Report recovery gains alongside false-positive additions, per-step misses, runtime, peak memory, and suspect retention. Set acceptable precision/recall and resource tradeoffs on validation data before the final test run.

Acceptance criteria:

- Correctness fixtures all pass, including the controlled failures documented in the review.
- Oracle-score scenarios reconstruct their expected steps and preserve all flow evidence under the declared grouping rule.
- Each claimed benefit is supported by a paired comparison with an unchanged scenario set.
- Release notes explain metric changes, configuration choices, remaining failure cases, and required datasets.
- Broader effectiveness claims include real replay or an independently specified campaign, since generator and reconstruction rules currently share assumptions.

## Optional next work after the baseline

**Bounded multi-hop recovery:** represent search nodes as relevant host-attribute state plus time and consumed evidence IDs. Preserve the existing semantics of alternatives within a precondition and conjunctions across preconditions. Current `compute_requirements` results describe alternative single-step explanations; do not reinterpret that set as a list of mandatory steps. Introduce an explicit recovery plan containing conjunctive requirements and alternative branches. Bound depth, visited states, candidate count, evidence age, and elapsed search time. Commit a complete valid branch transactionally. Proceed only if held-out examples show consecutive missing steps are a material residual error.

**Conformal prediction:** run as an uncertainty experiment after calibration. Evaluate empirical coverage and set size by attack class and capture, account for temporal dependence, and assess novel attacks separately. An empty prediction set is an abstention signal, not proof of a zero-day attack. [Conformal prediction reference](https://arxiv.org/html/2107.07511v6).

**Probabilistic tracking and learned transitions:** scope separately when deterministic recovery and repaired evaluation expose a specific remaining limitation. Define the probability model, branch limits, evidence provenance, and rollback behavior before selecting particle filtering, multiple hypotheses, or a learned sequence/graph model. Source-targeted postconditions can be introduced independently when a concrete new attack requires them.
