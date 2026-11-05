# Major changes since last version

This document describes **functional differences first**, followed by code organization.
The comparison baseline is the implementation in commit `071c453`, before the current
reconstruction corrections and refactoring series. That version already provided the
four evaluation categories, one-to-one matching, AND/OR clauses, and goal detection.
Those features are retained; the changes below explain how their inputs and behavior
have changed. The final section records the earlier evaluation redesign for context.

## Functional differences: metrics and causal graph

| Area | Previous implementation | Current implementation and observable effect |
|---|---|---|
| **Meaning of a causal edge** | Consecutive occurrences of the same attack context were linked automatically. Those links appeared in causal maps, reachability, and clause recovery. | Sharing a context creates no edge by itself. Causal edges require an earlier step's postconditions to support the later step's preconditions on the relevant tracked host. Temporal repetition alone no longer contributes causal credit or causal requirements. |
| **Repeated steps' prerequisites** | Only the first occurrence in a context received its actual precondition clauses. Later occurrences depended on the immediately preceding repetition. | Every distinct occurrence receives its own precondition clauses. It can use relevant evidence that became available after the first occurrence of its context. |
| **Alternative supporting occurrences** | A dependent step selected the latest earlier occurrence from each supporting group. | All valid earlier supporting occurrences enter the relevant OR clause. Recovering an earlier valid supporter can explain a dependency even if a later redundant repetition was missed. |
| **Repetition coverage** | Repetition order was embedded in the causal graph, so missing repetitions could affect both occurrence coverage and causal recovery. | `groups` retains occurrences and `get_repetition_pairs()` exposes consecutive repetitions separately. Step precision/recall still measure individual temporal executions; causal scores no longer require synthetic repetition chains. |
| **Goal-clause recovery** | Synthetic repetition clauses could increase the required-clause count on the explanation leading to a goal. | `get_goal_clause_recovery()` counts pure causal clauses. `is_scenario_detected()` still requires a matched goal and sufficient clause recovery, but redundant repetitions are not mandatory intermediate actions. |
| **External state dependencies** | DAG construction had no explicit internal-host tracking boundary and could infer support from postconditions on an external destination. | `tracked_host_ips` restricts state-enabling effects to internal destinations. Outbound steps remain in the graph and can depend on internal state, but cannot establish persistent external state for later steps. |
| **Actual/predicted policy consistency** | Actual and predicted inputs were converted to DAGs independently. | An explicit tracking policy is applied to both sides, including plain step-list inputs. Conflicting explicit policies raise `ValueError` instead of comparing different causal definitions. |
| **Alert identity used in matching** | Equality and the cached metric key omitted destination port, while hashing included it. Cached keys could become stale after edits. | Destination port participates in identity and matching. Equality and hashing use consistent fields; keys are computed from current fields, and timestamps use the common UTC comparison convention. Otherwise identical flows to different ports are distinct. |
| **Step and requirement identity** | Step equality used tolerant/asymmetric statistics rules that disagreed with hashing. Requirement equality ignored source ordering while hashing could depend on it. | Step value equality and hashing use the same exact fields; interval overlap remains the explicit approximate-matching rule. Requirement identity uses source membership consistently. Dictionary/set lookups no longer depend on those inconsistencies. |

### What the metric formulas still mean

The four evaluation responsibilities remain separate:

- **Flow filtering and alert correctness:** confusion matrices measure binary flow
  retention; alert precision/recall use one-to-one matching and classification checks.
  Duplicate alerts remain visible to alert precision even though confusion matrices
  measure dataset rows rather than duplicate emitted objects.
- **Aggregation quality:** soundness/completeness use correlation pairs, including
  singleton self-pairs, over one-to-one matched alerts. Missing alerts and extra alerts
  are measured by alert coverage/precision rather than counted again as clustering errors.
- **Occurrence coverage:** step precision/recall use one-to-one context and interval
  overlap matching. Missing repeated executions still lowers recall, even when the
  recovered occurrences provide a complete causal explanation.
- **Causal quality:** scenario soundness compares dependency reachability among matched
  steps. Completeness evaluates supported AND/OR clauses in the matched portion of the
  actual scenario; clauses without reachable matched supporters do not enter its
  denominator. It is not a replacement for whole-scenario occurrence recall.

Nearest-matched-ancestor stopping during missing-parent bypass is retained: traversal
only continues through missing steps. The goal recovery threshold remains **`0.8`**;
the functional change is which clauses are counted, not a changed default threshold.
Empty-case conventions and explicit unknown-classification matching are retained.

For example, let `Discovery1` and `Discovery2` establish the same attribute before
`Compromise`:

```text
Previous causal representation:
    Discovery1 -> Discovery2 -> Compromise

Current causal representation:
    Compromise has one OR clause: [Discovery1, Discovery2]

Separate repetition information:
    (Discovery1, Discovery2)
```

Recovering `Discovery1` and `Compromise` can now yield complete causal recovery while
occurrence recall remains `2/3`. A same-context pair can still be causal when its
postconditions genuinely support a later precondition; it is never causal solely
because it is a repetition. Strict start-time precedence prevents cycles. Initial
state is not represented explicitly, so a root is not proof that all its preconditions
were satisfied.

## Functional differences: reconstruction

| Area | Previous implementation | Current implementation and observable effect |
|---|---|---|
| **Temporal aggregation** | `StandardScaler` and DBSCAN grouped timestamp pairs relative to the available history. Changing distant history could change local clustering. Recovery could favor a DBSCAN cluster while excluding a newer singleton. | Alerts with the same attack type, source, and destination are sorted and merged by overlap or an inclusive physical idle gap. The default `max_idle_gap` is one second; singletons participate normally. No maximum step duration is imposed. |
| **Aggregation boundaries** | Logging aggregated and cleared a group's alerts and steps, so logging frequency could fragment results and alter final metrics. | Aggregation operates on the complete current-run alert history, including archived alerts. Logging and cleanup boundaries do not define attack-step boundaries. Step ends use the latest constituent end time; signed inter-flow statistics remain in milliseconds. |
| **Supporting alert classifications** | Recovery searched suspects by primary classification only. | Within each original suspect bucket, eligible flows are projected uniformly to each matching required type before clustering. Incompatible flows are excluded before clustering and remain available. Different original buckets are not merged. |
| **Primary versus alternative priority** | No supporting-alternative search existed. Candidate selection used the cluster score alone. | All primary-type candidates are validated before any alternative-type candidate. Within each tier, candidates retain the mean-anomaly-score times cluster-size ranking. Invalid primaries allow fallback to alternatives. |
| **Temporal evidence eligibility** | Recovery could select evidence starting after the trigger. | Supports must start strictly before the trigger. Equal-start and future supports are excluded before clustering; overlapping durations are allowed because effects are assumed available when the supporting flow starts. |
| **Validation of a recovered sequence** | Selected suspects were committed immediately, and the trigger could be added without confirming that recovery actually satisfied it. | A plan simulates every supporting alert in chronological order and then the trigger against isolated host state. Every alert must satisfy its own preconditions. An invalid plan changes no accepted evidence, suspects, recovered-FN records, or live host state. |
| **Partial acceptance and failures** | A failed attempt could leave supporting effects committed and affect later primary/alternative attempts. | Unexpected errors while applying the accepted batch restore host attributes, external registrations, accepted-alert buffers, and appended snapshots. Logging begins only after the complete batch is accepted. Archive errors propagate while retaining the accepted batch in memory; this is not a filesystem or process-crash transaction. |
| **Suspect consumption and FN records** | The entire winning suspect bucket was cleared, including unused clusters, and selected candidates were recorded as FNs before a coherent complete result was established. | Only selected original occurrences are consumed after successful acceptance. Original suspects are tracked separately from interpreted copies, so reclassification consumes the correct evidence without modifying the original objects. Only committed supporting alerts are recorded as recovered FNs. |
| **Alert logging** | `log_exploits()` wrote alerts and aggregate steps together and cleared both buffers. | `log_flow_exploits()` incrementally archives pending alerts as UTF-8 JSON lines. It neither aggregates nor clears. `clean_flow_exploits()` separately releases only successfully archived prefixes. Final results include archived alerts. Aggregate-step logging is removed. |
| **State logging and history** | State logging cleared the history. Historical snapshots also shared mutable sets with live hosts. | Every snapshot owns its attribute sets. `log_states()` appends only pending snapshots and preserves memory; `clean_states()` is explicit. `return_all_states()` restores the complete run, including cleaned snapshots, without duplicating logged states still in memory. Empty host attribute sets deserialize correctly. |
| **Logging triggers and archive lifecycle** | Thresholds counted active buffers, and the logging operation also performed destructive cleanup. | Thresholds count unlogged alerts or snapshots. Repeated logging without new evidence is a no-op. Batch offsets preserve access across log-path changes; reset starts a new run without deleting old records. Missing/truncated archives raise errors instead of silently returning partial history. |
| **External endpoints** | Preconditions registered external endpoints, but postcondition/state-change methods raised for external destinations. | External preconditions use the configured baseline only. Accepted outbound alerts cause no external state transition. Recovery cannot establish missing external attributes, while observed external addresses remain usable as candidate sources of internal effects. |
| **Threshold contract** | Inverted/equal suspect and anomaly thresholds were accepted. Direct alert conversion also accepted scores exactly at the suspect threshold. | The manager requires `suspect_threshold < anomaly_threshold`. Scores at or below the suspect threshold are ignored; scores above it and at or below the anomaly threshold become suspects; higher scores enter validation. Direct conversion requires strict `>` too. Detection metrics already used strict `>` and retain it. |
| **Returned scenario** | `get_results()` returned a flat list of steps and a list of currently retained alerts. A separate correlation sequence recorded selected transitions. | It returns `(AttackScenarioDAG, alerts)` with complete accepted alert history. Dependencies are built from aggregated occurrences, and synthetic correlation logging is removed. |

Recovery remains a **single-cluster, single-original-bucket** search. It does not combine
multiple missing steps or implement general multi-hop recovery. Within each required-type
projection it considers the latest eligible temporal cluster, rather than searching all
older clusters. External baseline assumptions are shared configuration, not learned
per-IP compromise state. Archives retain current-run metadata and are not restart
checkpoints.

For example, if a suspected scan has `SSHCompromise` as an alternative classification,
it can now be projected to that type and recovered as support for a later action.
Acceptance requires both the projected support and the later action to validate. If
either fails, the original suspect remains available and its speculative effects do
not reach the live network state.

## API migration and interpretation of results

- Obtain the old flat-step view with `scenario_dag.steps` after `get_results()`.
- Configure only alert and state log paths. The removed aggregate-step and correlation
  log paths, `log_exploits()`, `add_correlation()`, and `return_correlations()` are not
  restored by the compatibility modules.
- Replace `length_when_log_exploits` with `length_when_log_flow_exploits`; this now
  triggers alert archiving rather than aggregate-step logging/cleanup.
- Use `return_all_flow_exploits()` and `return_all_states()` for complete histories;
  the corresponding methods without `all` expose active buffers.
- Use `get_repetition_pairs()` for repetition order; causal maps and `get_chains()`
  now describe state-enabling dependencies only.

**Old and new causal scores are not directly equivalent:** synthetic repetition clauses
have disappeared, every occurrence has its own prerequisites, and external effects are
excluded when a tracking boundary is configured. Aggregation and recovery corrections
can also change the retained alerts and constructed steps before metrics run. Compare
the versions by rerunning the same scenarios under the same host policy and reporting
alert coverage, occurrence coverage, aggregation quality, and causal quality together.
The most recent file/name refactor preserves these corrected behaviors; it does not
itself introduce another metric definition.

## Reconstruction and metrics organization — 2026-11-05

The reconstruction monolith has been split into modules with distinct responsibilities.
Evaluation is an independent `metrics` package rather than part of scenario generation.
Production code and tests now import the canonical modules directly.

```text
scenario_reconstructor/
  models/
    attacks.py       AttackType, Precondition, RecoveryRequirement
    events.py        FlowAlert, AttackStep
    network.py       HostAttribute, Host, NetworkState
  dag.py             AttackGoal, AttackScenarioDAG
  engine.py          ScenarioReconstructor: network validation and aggregation
  manager.py         ReconstructionManager: stream routing and atomic recovery
  recovery.py        RecoveryPlan and ranked RecoveryCandidate records
  alerts.py          AlertFactory: scored event to classified alert
  aggregation.py     Context and idle-gap grouping, temporal step construction
  storage.py         EvidenceStore: buffers, incremental archives, explicit cleanup
  serialization.py   AlertStepParser and NetworkStateParser
  time_utils.py      Shared UTC comparison policy
  attack_mapper.py   Attack-type score interpretation
  reconstruct_cAPTure.py  Dataset configuration and evaluation runner

metrics/
  matching.py        One-to-one alert/occurrence matching and DAG policy alignment
  detection.py       Confusion matrices and alert precision/recall
  aggregation.py     Alert-to-step correlation quality
  occurrence.py      Temporal step precision/recall
  causal.py          Dependency soundness/completeness and goal detection
  calculator.py      Stable MetricsCalculator class facade

tests/
  support.py         Isolated test lifecycle and project fixture factories
  fixtures.py        Shared example host attributes
  models/           Model identity, serialization, and snapshots
  graph/            DAG construction
  reconstruction/   State validation, routing, recovery, aggregation, and archives
  metrics/          Detection, aggregation, occurrence, and causal evaluation
  integration/      cAPTure reconstruction, external policy, public compatibility
  events/           Flow-event conversion
  generation/       Scenario generation
  pipeline/         Deferred data preparation, training, and runner regressions
```

### Names and compatibility

| Previous name | Canonical name |
|---|---|
| `FlowExploit` | `FlowAlert` |
| `Exploit` | `AttackStep` |
| `Preconditions` | `Precondition` |
| `ExploitRequirement` | `RecoveryRequirement` |
| `StarNetworkAttackGraphBasedScenarioReconstructor` | `ScenarioReconstructor` |
| `ScenarioReconstructionManager` | `ReconstructionManager` |
| `ExploitGenerator` | `AlertFactory` |
| `StringToExploitConverter` | `AlertStepParser` |
| `StringToNetworkStateConvertor` | `NetworkStateParser` |

The original reconstruction module paths and `scenario_generator.compute_metrics`
remain small compatibility modules. Their exported classes are aliases of the canonical
classes, so object identity, equality, subclassing, and existing callers are preserved.
The `MetricsCalculator` static API delegates to the focused metric functions.
`FlowAlert.reclassify()`, `AlertFactory.from_event()`, and parser `parse_*()` methods
provide clearer entry points; their original method names remain aliases.

The file/name refactor preserves the current `FlowExploit(...)`, `Exploit(...)`, and
`NetworkState(...)` text formats and JSON-line alert archives. It requires no conversion
of those current archives. The earlier transition from destructive `log_exploits()`
text dumps to JSON-line alert archiving is a functional change described above; legacy
import aliases do not turn older dump files into current-run archives.

### Cleanup and preserved behavior

- Removed the old combined test modules after moving all their cases and shared setup
  into responsibility-based suites. Non-test enum fixtures no longer begin with `Test`,
  eliminating their collection warnings.
- Removed the unused DAG-conversion helper and unused imports. Parser attack lookups
  use a single identifier index instead of repeated scans and a redundant list.
- Centralized archive batch reads/writes and evidence reset bookkeeping. Logging,
  cleanup, and aggregation remain independent; cleanup releases archived prefixes only.
- Replaced positional recovery-candidate tuples with named, typed records. Original
  suspect references remain distinct from reclassified accepted alerts.
- Preserved strict threshold boundaries, primary-candidate priority, atomic validation
  and acceptance, the start-time causality rule, and the external-host baseline policy.
- Standalone aggregation assigns each output cluster its own attack type and host pair.
- Preserved independent occurrence coverage and causal quality metrics. Compatibility
  tests cover legacy imports, serialized records, and model imports without evaluation
  or training libraries.

### Current graph and metric semantics

Each temporal occurrence has its own AND/OR precondition clauses. Every strictly earlier
occurrence with matching postconditions on the relevant tracked host is an OR supporter.
Sharing a context does not create a causal edge. `get_repetition_pairs()` exposes
consecutive distinct occurrences per context separately from causal maps and reachability.
A repetition may still be a genuine supporter when its postconditions satisfy a later
precondition. Unobserved initial-state support remains outside the graph model.

Scenario completeness is conditional on matched occurrences and clauses with reachable
matched supporters; missing occurrences are measured by step recall. Missing redundant
repetitions do not create mandatory causal clauses. Ancestor bypass stops at matched
intermediates. Goal detection uses pure causal clause recovery with the current default
threshold of `0.8`.

The focused verification command is:

```powershell
.\.venv\Scripts\python.exe -m pytest tests --ignore=tests/pipeline -q
```

Deferred pipeline failures remain tracked in `tests/pipeline/test_regressions.py`;
this reorganization does not address their generation, preprocessing, or training issues.
The full-suite audit after extraction reported **218 passing tests and the same 18
deferred pipeline failures**, with **54 passing subtests** and no collection warnings.
All 211 pre-refactor tests outside the deferred pipeline were retained; five new
checks cover public compatibility and standalone aggregation across contexts.

## Background: earlier evaluation redesign

The following sections describe the evaluation redesign that preceded the functional
changes above. These are retained design explanations, not features newly introduced
by the latest refactor. The suite consists of four orthogonal groups of metrics, each
responsible for a distinct stage of the reconstruction pipeline:

- **Flow/Alert Detection**: Intrusion Detection & Reconstruction Confusion Matrices, Alert Precision and Recall.
- **Alert-to-Step Aggregation**: Step Soundness and Completeness on 1-to-1 matched alerts.
- **Attack Step Identification**: Step Precision and Recall with 1-to-1 interval overlap.
- **Scenario Causal Reconstruction**: Temporal AND/OR Graph Soundness, Completeness, and Goal Detection.

By establishing strict orthogonality, each stage is evaluated independently: errors at one level (e.g., duplicate or spurious alerts) are penalized at that level and do not artificially distort subsequent stages (e.g., alert aggregation or causal graph analysis).

---

### 1. Flow/Alert Detection

#### Motivation & Limitations of Previous Metrics
Previously, flow and alert detection relied solely on confusion matrices (`get_detection_confusion_matrix` and `get_reconstruction_confusion_matrix`). While useful for evaluating background traffic filtering, confusion matrices presented two critical shortcomings:
1. **Invisibility of Duplicate Alerts**: In `get_reconstruction_confusion_matrix`, predicted alerts are converted into a set of flow tuples `(src_ip, src_port, dst_ip, dst_port, protocol, start_time, end_time)` and compared against rows in the dataset `scenario_df`. Because sets automatically deduplicate elements, if the detector or reconstructor emits multiple duplicate alerts for the same underlying network flow, they collapse into a single entry. Consequently, duplicate predictions were completely invisible and never penalized as false positives.
2. **Absence of Semantic Attack Type Verification**: Confusion matrices only evaluate whether a network flow was flagged as anomalous versus normal (`label != "normal"`). They do not verify whether the alert was classified with the correct `attack_type`. A flow flagged with an entirely wrong attack semantic still counted as a True Positive.
3. **Confounded Pipeline Responsibilities**: Because there was no dedicated alert-level precision/recall metric, duplicate and false-alarm alerts were either unpenalized or leaked into subsequent step aggregation metrics, compromising metric orthogonality.

#### Reasoning behind the Changes
To resolve these issues, the evaluation separates raw traffic flow classification from alert object validation:
- Confusion matrices are retained specifically to evaluate dataset-level binary filtering against benign background traffic.
- Dedicated **Alert Precision** and **Alert Recall** metrics were introduced to evaluate alert objects (`FlowExploit`) directly, enforcing strict **1-to-1 matching** and semantic attack type validation.

#### Metric Definitions & Roles

1. **Intrusion Detection Confusion Matrix (`get_detection_confusion_matrix`)**
   - **Purpose**: Evaluates the baseline anomaly detector's capability to filter benign background flows prior to scenario reconstruction.
   - **How it works**: Computes True Negatives (TN), False Positives (FP), False Negatives (FN), and True Positives (TP) across `scenario_df` by thresholding `anomaly_score > alert_threshold` against binary labels (`label != "normal"`).

2. **Reconstruction Confusion Matrix (`get_reconstruction_confusion_matrix`)**
   - **Purpose**: Evaluates flow-level filtering after the reconstruction pipeline processes and filters detected flows into predicted alerts.
   - **How it works**: Checks whether each network flow in `scenario_df` is retained in the predicted flows set. Quantifies how effectively the reconstruction logic filters out false alarm flows while retaining true attack flows at the dataset level.

3. **Alert Precision (`get_alert_precision`)**
   - **Purpose**: Evaluates the purity and correctness of generated alert objects (`FlowExploit`).
   - **How it works**: Measures the proportion of predicted alerts that match ground-truth alerts using strict **1-to-1 matching**:
     $$\text{Alert Precision} = \frac{|\text{Matches}|}{|\text{Predicted Alerts}|}$$
   - **What it captures**: 
     - **Penalizes duplicates**: Since each actual alert can be matched at most once, redundant duplicate predictions remain unmatched, entering the denominator as false positives and lowering precision.
     - **Verifies attack types**: Reconstructed alerts must match the ground-truth `attack_type` (or satisfy undetermined/unknown rules). Misclassified alerts fail to match.

4. **Alert Recall (`get_alert_recall`)**
   - **Purpose**: Evaluates the coverage of actual attack flows by the alert generation pipeline.
   - **How it works**: Measures the proportion of actual ground-truth alerts successfully recovered through 1-to-1 matching:
     $$\text{Alert Recall} = \frac{|\text{Matches}|}{|\text{Actual Alerts}|}$$
   - **What it captures**: Penalizes missed attack flows (false negatives at the alert level), ensuring each ground-truth alert requires a distinct predicted counterpart.

---

### 2. Alert-to-Step Aggregation

#### Motivation & Limitations of Previous Metrics
Alert aggregation metrics evaluate the clustering of individual alerts (`FlowExploit`) into macro attack steps (`Exploit`). When alerts belong to the same step, they form correlation pairs $(a_i, a_j)$. The previous implementation suffered from several major flaws:
1. **Invisibility of Singleton Steps**: Alert pairs were generated using strict 2-combinations ($\binom{n}{2}$). Consequently, any attack step containing only a single alert generated zero pairs ($\binom{1}{2} = 0$). In scenarios with singleton steps, those steps were completely invisible to soundness and completeness. If all steps in a scenario were singletons, the total number of actual and predicted pairs was zero, causing division-by-zero crashes.
2. **Artificial Self-Pairs from Duplicate Matches**: Without 1-to-1 alert tracking, duplicate predicted alerts could map to the same actual alert, generating artificial self-pairs that skewed the correlation count.
3. **Lack of Isolation from Alert Detection Errors**: Previously, aggregation metrics attempted to penalize false-positive and missing alerts simultaneously with clustering errors. This confounded two different concerns: did the model fail because the detector produced spurious alerts, or because the clustering algorithm grouped alerts incorrectly?

#### Reasoning behind the Changes
1. **Self-Pairs for Every Alert**: By switching from $\binom{n}{2}$ to `combinations_with_replacement`, each alert $a_i$ within a step forms a self-pair $(a_i, a_i)$ in addition to cross-alert pairs $(a_i, a_j)$. This ensures that steps with only one alert are properly represented (the self-pair denotes the presence and membership of the alert within an attack step) and eliminates division-by-zero edge cases.
2. **Orthogonality via 1-to-1 Matched Alerts**: Correlation pairs are now constructed strictly from the subset of alerts that successfully matched 1-to-1 during alert detection. Because false positives, duplicates, and missed alerts are already penalized by Alert Precision and Recall, step aggregation metrics are strictly isolated to evaluate **pure clustering quality**: how well the detected alerts were grouped together.

#### Metric Definitions & Roles

1. **Step Soundness (`get_step_soundness_completeness` -> soundness)**
   - **Purpose**: Evaluates the purity/precision of alert clustering into attack steps.
   - **How it works**: Computes the proportion of predicted alert correlation pairs that correspond to actual correlation pairs:
     $$\text{Step Soundness} = \frac{|\text{Predicted Pairs} \cap \text{Actual Pairs}|}{|\text{Predicted Pairs}|}$$
   - **What it captures**: Penalizes **over-merging**. If the reconstructor mistakenly aggregates unrelated alerts from different attack steps into the same step, it generates invalid cross-alert pairs that dilute soundness.

2. **Step Completeness (`get_step_soundness_completeness` -> completeness)**
   - **Purpose**: Evaluates the recall/coverage of alert clustering into attack steps.
   - **How it works**: Computes the proportion of actual alert correlation pairs successfully recovered by the predicted steps:
     $$\text{Step Completeness} = \frac{|\text{Predicted Pairs} \cap \text{Actual Pairs}|}{|\text{Actual Pairs}|}$$
   - **What it captures**: Penalizes **fragmentation / over-splitting**. If the reconstructor splits alerts belonging to a single attack step across multiple smaller steps, the correlation pairs linking those alerts across splits are lost, lowering completeness.

---

### 3. Attack Step Identification

#### Motivation & Limitations of Previous Metrics
Attack step identification evaluates the reconstruction of macro attack steps (`Exploit`) along the attack timeline, regardless of how many individual alerts constitute each step. The previous design had significant weaknesses:
1. **Awkward "Timed" vs. "No-Timing" Dichotomy**:
   - The "no-timing" variant completely ignored timestamps, matching steps solely on host IPs and attack type. This was excessively lax and could not evaluate repeated attacks (a single predicted step could match multiple actual steps occurring at different times).
   - The "timed" variant required timestamps to fall within a fixed, hardcoded tolerance window (e.g., `TORELANCE = 2000 ms`). This was brittle: attack steps vary drastically in duration, and slight network delays caused legitimate step detections to fail matching.
2. **Unpenalized Fragmentation & Many-to-One Matches**: Many-to-one matching allowed multiple fragmented predicted steps to match a single ground-truth step without penalty, obscuring step fragmentation issues.

#### Reasoning behind the Changes
1. **Removal of Arbitrary Tolerances and Redundant Variants**: The artificial timed/no-timing split and hardcoded millisecond tolerance parameters were eliminated in favor of a single, physically grounded criterion: **temporal interval overlap**.
2. **Strict 1-to-1 Interval Overlap Matching**: Two steps match (`approx_match`) if they share the same context (source IP, destination IP, attack type) and their active execution intervals overlap:
   $$\max(\text{start}_1, \text{start}_2) \le \min(\text{end}_1, \text{end}_2)$$
   Enforcing strict 1-to-1 matching guarantees that each ground-truth step can only be claimed once, allowing repeated attack steps to be evaluated individually and penalizing fragmentation.

#### Metric Definitions & Roles

1. **Step Precision (`get_scenario_step_precision`)**
   - **Purpose**: Evaluates the validity and precision of identified attack steps.
   - **How it works**: Measures the proportion of predicted steps that match ground-truth steps 1-to-1:
     $$\text{Step Precision} = \frac{|\text{Matched Steps}|}{|\text{Predicted Steps}|}$$
   - **What it captures**: Penalizes false alarm steps and **step fragmentation**. If a single actual step is predicted as three separate overlapping fragments, only one can match 1-to-1; the remaining two fragments count as false positives in the denominator, directly lowering precision.

2. **Step Recall (`get_scenario_step_recall`)**
   - **Purpose**: Evaluates the coverage of actual attack steps.
   - **How it works**: Measures the proportion of actual ground-truth steps successfully recovered via 1-to-1 matching:
     $$\text{Step Recall} = \frac{|\text{Matched Steps}|}{|\text{Actual Steps}|}$$
   - **What it captures**: Penalizes missed attack steps (false negatives) and unrecovered repetitions of repeated attacks.

---

### 4. Scenario Causal Reconstruction

#### Motivation & Limitations of Previous Metrics
1. **Ordered Pairs Do Not Capture Causality**: The original metric generated causal pairs simply by taking all chronologically ordered step pairs $(S_i, S_j \text{ with } i < j)$. Temporal sequence does not capture causality: it cannot represent parallel or branching attack paths, nor does it verify whether an earlier step actually satisfies the preconditions of a later one.
2. **Confounded Coverage and Dependency Quality**: A causal score alone cannot express how many attack occurrences were recovered. Coverage is now measured separately by one-to-one step recall; structural completeness deliberately evaluates the matched portion of the scenario.
3. **No Campaign Goal Evaluation**: Pairwise ordering metrics could not assess whether the reconstructed attack campaign actually achieved its ultimate tactical objective.

#### Reasoning behind the Changes
1. **Temporal AND/OR Attack Graph (`AttackScenarioDAG`)**: Replaces simple ordered chains with a formal DAG where edges reflect verified precondition and postcondition relationships (`is_causally_correlated`):
   - Steps act as **AND-nodes** over their required precondition clauses.
   - Precondition clauses act as **OR-nodes** satisfied by any valid prior step providing the necessary compromise attributes.
   - Repetitions are stored separately through `groups` and `get_repetition_pairs()`; only actual precondition/postcondition support creates causal edges.
2. **Clause Completeness with Ancestor Bypass**: Evaluates satisfaction of required precondition clauses rather than raw pairs, searching ancestor paths in the DAG to avoid cascading penalties when intermediate steps are missed.
3. **Goal Detection (`is_scenario_detected`)**: Explicitly verifies whether the target goal was identified and its root-to-goal causal clauses recovered above the recovery threshold (default 80%).

#### Metric Definitions & Roles

1. **Scenario Soundness (`get_scenario_soundness_completeness` -> soundness)**
   - **Purpose**: Evaluates the precision of reconstructed causal dependencies between attack steps.
   - **How it works**: Measures the proportion of predicted causal edges between matched steps that represent legitimate causal relationships in the actual DAG:
     $$\text{Scenario Soundness} = \frac{|\text{Predicted Causal Pairs} \cap \text{Actual Causal Pairs}|}{|\text{Predicted Causal Pairs}|}$$
   - **What it captures**: Penalizes spurious, backward, or hallucinated causal dependencies that do not correspond to valid prerequisite-consequence relationships.

2. **Scenario Completeness (`get_scenario_soundness_completeness` -> completeness)**
   - **Purpose**: Evaluates how thoroughly the necessary causal prerequisites are satisfied across the reconstructed scenario under AND/OR logic.
   - **How it works**: For each matched step and each required precondition clause in the actual DAG, verifies whether a reconstructed edge links it to an eligible causal parent (or valid transitive ancestor if intermediate steps were missed):
     $$\text{Scenario Completeness} = \frac{\text{Satisfied Precondition Clauses}}{\text{Required Precondition Clauses}}$$
   - **What it captures**: Accurately reflects multi-stage attack progression under OR-semantics without penalizing valid alternative paths or cascading penalties when intermediate steps are bypassed.

3. **Scenario Goal Detection (`is_scenario_detected`)**
   - **Purpose**: Evaluates whether the overall attack campaign objective was recognized and causally traced from its origins.
   - **How it works**: Given an [`AttackGoal`](../scenario_reconstructor/dag.py) (target IP and final attack type):
     - Verifies that the goal step is present and matched in the reconstructed scenario.
     - Traces the root-to-goal causal clauses backwards (`get_goal_clause_recovery`) and checks whether the proportion recovered meets or exceeds the edge recovery threshold (default 80%).
   - **What it captures**: Distinguishes between scenarios where isolated attack steps were detected versus scenarios where the full multi-step attack campaign leading to the objective was successfully uncovered.
