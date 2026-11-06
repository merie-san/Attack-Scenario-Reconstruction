# Attack Scenario Reconstruction

This is a code repository for my master thesis on Attack Scenario Reconstruction. The repository contains four modules:

- The **Dataset Preprocessor**
- The **Scenario Reconstructor**
- The **Scenario Generator**
- The **Metrics collector**

The Dataset Preprocessor consists in a series of Jupyter notebooks which are responsible for transforming the initial intrusion detection dataset into a format suitable for scenario reconstruction. We started from the [cAPTure dataset](https://www.sciencedirect.com/science/article/pii/S1389128626005827) and extracted traffic data corresponding to the dollar_char campaign, which is then preprocessed to adapt it to our own reconstruction requirements. The results is a separated test and train set. The train set is used to build the necessary machine learners for reconstruction, while the test set is used as the basis for the reconstruction dataset through enrichment with anomaly and attack type score. 

The resulting dataset, which we call the event dataset, contain the network flows extracted from the corresponding campaign labeled with a corresponding anomaly and attack type score. This dataset can then be used by the Scenario Generator module to synthetically generate custom attack scenarios which can then be used for the purpose of metrics collection and reconstruction evaluation. To produce the target scenario through the Scenario Generator one must use its API and provide the requested parameters.  

From the results returned by the Scenario Generator module and the Scenario reconstructor module, the Metrics Collector is then able to compute and log performance and quality metrics of interest. Three types of metrics are provided: confusion matrix metrics which assess the influence that the reconstructor has on intrusion detection results, recall and precision metrics which assess the ability of the reconstructor in including individual anomalous events, and finally, soundness and completeness metrics which assess the reconstructor's ability in making correct associations between events.   

Lastly, the Scenario Reconstructor is the module responsible for transforming isolated alerts in explainable attack scenarios based on the current network state, the alert history and the attack's characteristics. The reconstructor models the system as a set of hosts, each with their compromise attributes describing attack relevant properties. When an alert is produced we assign an attack type to the alert based on its attack type scores and check the feasibility of the attack in the current network state: if the attack is feasible, the alert is added and the network state is modified accordingly, while if it is not we check the alert history and try to find false negative classifications.

At the end of the reconstruction procedure a sequence of attack steps is obtained from the reconstructor representing predicted attacker actions. The configuration of the Scenario Reconstructor happens through the definition of attack relevant host attributes based on the target network's properties and the types of attacks we are considering, and the pre- and post-conditions of the same attacks. These pre- and post-conditions are defined as assertions on the source or destination hosts of attacks regarding their compromise attributes.

For more detailed information on the structure and the configuration of the various modules see the thesis in question.  

### Scenario generation failures and bounded backtracking

Construction validates the core template fields (`timestamp`, `duration`, `label`,
and `step_number`) on a private dataframe copy. Timestamps must be valid and present,
durations must be finite nonnegative numbers in milliseconds, group identifiers must
be present, and column names must be unique. Empty or invalid templates raise
`ScenarioGenerationError`; include construction in the `try` block when handling
these failures. Timestamp conversion and numeric-duration normalization do not change
the caller's dataframe. Existing timezone interpretation is retained.

Inter-step delays use the absolute value of the normal draw before rounding to
seconds. Negative draws become positive delays; zero remains allowed. Steps are
still placed relative to the preceding step's last flow start and may overlap its
flow durations.

`generate_scenario()` filters infeasible transitions and host pairs before sampling
and backtracks when a valid local choice leads to a dead end. Candidate hosts and
enabled-host lists are restored for each alternative. Sampling follows attack,
then source, then destination among remaining feasible choices; completed scenarios
are not guaranteed to be uniformly distributed.

Keyword-only limits are `max_steps=100` and `max_search_attempts=10_000`. The step
limit counts attack executions; attempts count tested attack/source/destination
choices and `end` transitions, including choices rejected at the depth boundary.
Repetition is allowed within these bounds. Only a configured `end` transition
completes a scenario; reaching a limit never returns a truncated scenario.

Callers can distinguish exhausted choices from incomplete bounded search:

```python
from scenario_generator import (
    NoFeasibleScenarioError,
    ScenarioGenerationError,
    ScenarioSearchLimitError,
)

try:
    scenario_df = generator.generate_scenario(max_steps=100, max_search_attempts=10_000)
except NoFeasibleScenarioError as error:
    # Reject this request: the available alternatives were exhausted.
    print(error)
except ScenarioSearchLimitError as error:
    # Retry with different bounds/seed, skip, or stop according to caller policy.
    print(error.limit_name, error.limit, error.attempts)
except ScenarioGenerationError as error:
    # Other explicit generation failures, such as missing normal-flow templates.
    print(error)
else:
    steps, alerts = generator.export_results(attack_types)
```

All three failures inherit from `RuntimeError`. Invalid argument types or nonpositive
limits raise `TypeError`/`ValueError`. An exception preserves the last completed
`result` and exported metadata; callers should process a new result only on success.

### Flow-event timestamp conversion

`events.conversion.CaptureFlowEventConverter.convert()` produces UTC-aware start and end timestamps.
Naive input timestamps are interpreted as UTC; explicit timezone offsets are
converted while preserving the instant. Durations remain milliseconds. The
converter works on a private copy and leaves the input dataframe unchanged.

### Code organization

Reusable code is organized by responsibility:

| Package | Responsibility |
| --- | --- |
| `events` | Scored flow model and cAPTure dataframe conversion |
| `scenario_generator` | Template validation, bounded search, temporal rendering, and generation API |
| `scenario_configs` | Dataset-specific attack rules and fresh host initialization |
| `preprocessing` | Flow augmentation, endpoint filtering, timestamps, training schema/encoding, and calibration |
| `scenario_reconstructor` | State validation, recovery, aggregation, storage, and causal DAGs |
| `metrics` | Detection, alert/step matching, aggregation, and causal evaluation |
| `experiments` | Explicit single-run and batch evaluation entry points |

Reconstruction models live in `scenario_reconstructor/models`; causal graphs are
in `scenario_reconstructor/dag.py`. `engine.py` handles network-state validation,
`manager.py` handles stream routing and recovery, and `storage.py` handles accepted
evidence and archives. Aggregation and text parsing have dedicated modules.
Metrics live in the independent `metrics` package, split into detection,
aggregation, occurrence, and causal evaluation. `metrics.MetricsCalculator`
preserves the established class API.

New code should use `ScenarioGenerator` from `scenario_generator`,
`CaptureFlowEventConverter` from `events.conversion`, `FlowEvent` from `events`,
and `FlowAlert`, `AttackStep`, `Precondition`,
`RecoveryRequirement`, `ScenarioReconstructor`, and `ReconstructionManager` from
their canonical modules. The former names and module paths remain compatibility
aliases, and existing text log formats are unchanged. See
[`improvement_plan/CHANGES.md`](improvement_plan/CHANGES.md) for the layout and name mapping.

Tests mirror these responsibilities under `tests/models`, `tests/events`,
`tests/generation`, `tests/graph`, `tests/reconstruction`, `tests/metrics`,
`tests/preprocessing`, `tests/experiments`, and `tests/integration`, with shared
factories in `tests/support.py`. Run all checks with `python -m pytest tests -q`.
Preprocessing tests call reusable functions directly and exercise selected notebook
wrappers/setup cells on small fixtures. Batch subprocesses are mocked; tests do not
load real datasets or run model-training notebooks.

The notebooks stay under `jupyter notebook/` to preserve their relative data paths;
they import reusable preprocessing logic from the project root. The PCAP conversion
notebook retains its NFStream workflow. Plotting, model comparisons, and dataset
selection remain explicit notebook steps.

Canonical command entry points are `python -m experiments.capture` and
`python -m experiments.batch`. Existing `python -m scenario_reconstructor.reconstruct_cAPTure`
and `python run_scripts.py` commands still work. Importing a runner never starts
evaluations; its `main()` must be called explicitly. Real-dataset execution and
pipeline reintegration remain deferred.

### Notebook corrections and validation

Normal-flow augmentation keeps categorical tuples together, constrains nonnegative
counters, recomputes directional totals/durations, and transforms related timestamps
together. IPv4 filtering validates both endpoints. Capture-time shifts use date-safe
arithmetic.

The reconstruction-dataset notebook uses training-defined features/classes and holds
out 20% of its binary training data for threshold calibration (stratified, seed 42).
Encoding categories and the scaler are learned from the fit partition; final test
data is used for evaluation/export. Recall-based thresholds respect the strict `>`
comparison, including zero-recall and tied-score cases.

Notebook outputs were cleared after these changes. Regenerate data and learned results
before using them; real-dataset runs and pipeline reintegration are scheduled separately.

### Alert logging, cleanup, and aggregation

The reconstructor takes two log paths: `flow_exploit_log_path` and `state_log_path`.
Aggregated exploits are no longer logged. Accepted alerts are archived as UTF-8
JSON lines, including their attack type, alternatives, network fields, timestamps,
and anomaly score.

- `log_flow_exploits(reference_alert)` appends only new alerts from that group.
  It does not aggregate or remove them. Calling it again without new alerts is a no-op.
- `clean_flow_exploits(reference_alert)` releases only the successfully archived
  prefix of that group's in-memory alerts. Unlogged alerts and derived steps remain.
  Cleanup is explicit; periodic logging does not automatically invoke it.
- `update_exploits(reference_alert)` and `update_exploits_all()` aggregate the full
  accepted history, combining archived and active alerts. Logging/cleanup
  boundaries do not define aggregation boundaries.
- `return_flow_exploits()` exposes active alerts; `return_all_flow_exploits()` and
  the manager's `get_results()` include archived alerts as well.

The manager's `length_when_log_flow_exploits` threshold counts unlogged alerts per
group (`-1` disables automatic logging; logging occurs when the count exceeds the
threshold). Aggregation runs independently when results are requested.

Archive batch offsets and attack definitions are retained for the current run;
this archive is not a process-restart checkpoint. Keep archive files available
until final results are collected. Changing log paths preserves access to earlier
batches. `reset()` starts a fresh scenario without deleting old log records or
including them in the new scenario.

### State logging and cleanup

- `log_states()` appends only unlogged snapshots as UTF-8 `NetworkState(...)`
  lines and returns the number written. It neither clears snapshots nor changes
  live hosts. Repeating it without new states is a no-op.
- `clean_states()` explicitly releases only the successfully archived prefix and
  returns the number removed. Pending snapshots remain in memory.
- `return_states()` exposes active snapshots; `return_all_states()` restores the
  complete current-run sequence from archived batches and pending snapshots,
  preserving occurrence order without duplicating logged states still in memory.
- `length_when_log_states` counts unlogged snapshots, including the initial state.
  Logging occurs when the count exceeds the threshold; `-1` disables it. The
  manager does not automatically clean snapshots.

State snapshots own their attribute sets. Archive offsets and attribute definitions
are retained for this run, including across log-path changes. Reset starts a fresh
history without deleting old records. As with alert archives, files must remain
available until full history has been retrieved; this is not a restart checkpoint.

The reconstructor's keyword-only `max_idle_gap` parameter defaults to
`timedelta(seconds=1)`. Alerts with the same attack type, source IP, and destination
IP form a step when their intervals overlap or the next alert starts within this
gap of the step's latest end. The boundary is inclusive. A zero gap merges only
overlapping or touching intervals; negative gaps are rejected. There is no maximum
step duration. Suspect recovery uses the same grouping policy and selects the group
with the latest end, including single-alert groups. Timestamp comparisons use UTC,
with naive timestamps treated as UTC.

Alert, step, and requirement equality uses the same comparison keys as hashing.
Individual alert identity includes both ports, protocol, timestamps, hosts, and
attack type; anomaly scores and alternative classifications are annotations.
Step equality includes exact size and inter-flow statistics, with `-1` treated as
an ordinary unknown value. Approximate step matching and unknown predicted alert
types are handled by explicit matching methods rather than equality. Requirement
source IPs are compared as a set, independent of order and duplicates. Comparison
timestamps use the UTC convention above. Do not mutate identity fields, including
referenced attack definitions, while objects are stored in dictionaries or sets.

### External host policy

Only configured internal hosts accumulate compromise attributes. External IPs are
observed endpoint identifiers; their preconditions use `external_host_attributes`
as a shared baseline. Accepted outbound alerts remain evidence, but postconditions
on external destinations are ignored and do not produce network-state transitions.
Recovery cannot establish missing attributes on an external endpoint. Observed
external addresses remain available as possible sources of steps affecting internal
hosts, using only their baseline attributes.

`AttackScenarioDAG(steps, tracked_host_ips=...)` infers state dependencies only from
effects on tracked destinations. Repetition pairs and timestamp ordering remain.
The reconstructor supplies its internal host IPs, and the runner uses the same set
for the actual DAG. Metrics propagate an explicit policy to a step list or an
unrestricted DAG on the other side, and reject conflicting explicit policies.
Omitting `tracked_host_ips` preserves unrestricted standalone DAG behavior; an
empty set disables all state dependencies while preserving repetition pairs.

### Causal dependencies and repetitions

Every temporal step occurrence has its own AND/OR precondition clauses. A clause
contains all strictly earlier occurrences whose postconditions support it on the
relevant tracked host; repeated supporters are alternatives, not mandatory links.
The start-time policy permits overlapping flows and excludes equal-start or future
supporters. As before, preconditions without observed supporters do not add clauses;
roots therefore do not prove that initial preconditions were satisfied.

`clause_parents_map`, `parents_map`, `children_map`, `get_adjacent_pairs()`,
`get_causal_pairs()`, and `get_chains()` describe only state dependencies.
`groups` retains context-grouped occurrences, and `get_repetition_pairs()` returns
consecutive distinct occurrences within each group without adding causal edges.
Sharing a context does not itself imply causation; a repeated occurrence can still
be a causal supporter if its postconditions actually match a later precondition.

Scenario soundness/completeness and goal-clause recovery use pure causal clauses.
Missing a redundant supporting repetition does not increase the causal recovery
denominator. Step precision/recall continue to measure temporal occurrence coverage,
and alert and aggregation metrics retain their existing behavior. Public call
signatures are preserved, but causal paths and scores no longer include synthetic
repetition chains; callers needing repetition order should use the dedicated API.

### Validated recovery

The manager requires `suspect_threshold < anomaly_threshold`; equal or inverted
thresholds raise `ValueError`. Scores at or below the suspect threshold are ignored,
scores above it and at or below the anomaly threshold become suspects, and scores
strictly above the anomaly threshold are validated for acceptance. Detection metrics
use the same strict `>` anomaly boundary. Direct alert conversion also requires a
score strictly above the suspect threshold.

Recovery first creates a `RecoveryPlan` against isolated copies of the internal
and external host state. Every supporting alert must satisfy its own preconditions
in sequence, and the trigger must satisfy its preconditions after those effects.
Planning does not add accepted alerts, consume suspects, record FNs, or write logs.
Primary and alternative trigger classifications use the same validation path.
Supporting suspects may also use a matching alternative classification. Within
each original suspect bucket, flows matching a required type are interpreted
uniformly as that type before temporal clustering. Each projection contributes
its latest cluster; flows from different original buckets are evaluated separately.
All primary-type candidates are tried before any alternative-type candidate,
regardless of score. Within each tier, candidates are ranked by mean anomaly score
times cluster size. Invalid primary candidates allow fallback to alternatives.
Each proposal represents one type and host pair. Plans retain
the original suspect references separately from interpreted alerts: acceptance
consumes the originals and records the selected types as FNs without modifying
the original alert objects.
An invalid candidate does not prevent trying another candidate.

Supporting alerts must start strictly before the trigger, consistent with DAG
causality. Future alerts are excluded before temporal grouping. Supporting flows
may overlap the trigger; validation does not require them to finish first.
Subgoals are treated as achieved when the first supporting network flow starts.

Only a fully validated sequence is committed. Unexpected errors while applying
the sequence restore the prior host attributes, accepted-alert buffers, external
host registrations, and state-history length. After acceptance, only the consumed
suspect occurrences are removed and only committed supports are recorded as FNs.
Logging occurs after the complete batch is accepted. An archive error is reported
without discarding that accepted batch; this is not a filesystem transaction or a
process-crash recovery mechanism. Recovery still searches the existing one-group
proposals; this change does not introduce general multi-hop recovery.
