# Repository Guidelines for AI Coding Agents

## 1. Project Overview

**Attack Scenario Reconstruction** is a Python research codebase implementing an end-to-end pipeline for transforming isolated network-flow intrusion alerts into explainable multi-step attack scenarios and evaluating reconstruction quality across four orthogonal stages:

1. **Dataset Preprocessing & ML Scoring (`preprocessing/`, `jupyter notebook/`)**: Augments normal traffic, filters endpoints, aligns train/test schemas, trains binary anomaly detectors and per-attack classifiers, and calibrates detection thresholds on a stratified validation holdout.
2. **Synthetic Scenario Generation (`scenario_generator/`, `scenario_configs/`)**: Validates a scored/labeled flow dataset CSV used as flow templates and synthesizes attack scenarios with background traffic through bounded iterative backtracking or an explicit scenario path.
3. **State-Based Scenario Reconstruction (`scenario_reconstructor/`, `events/`)**: Converts scored flow events into alerts, validates preconditions against tracked host compromise attributes, atomically recovers false-negative alerts from a suspect buffer (including alternative classifications), aggregates alerts into temporal steps by physical idle gap, builds a Temporal AND/OR Causal Attack DAG, and incrementally archives evidence.
4. **Orthogonal Evaluation (`metrics/`)**: Independently evaluates flow/alert detection, alert-to-step aggregation, temporal step occurrence coverage, and causal AND/OR graph reconstruction & goal detection.

---

## 2. Canonical Package Layout vs. Compatibility Shims

New production code and tests **must import from the canonical modules**. Existing legacy compatibility modules and aliases **must be kept intact and identity-preserving (`is`)** for backward compatibility (enforced by `tests/integration/test_public_api.py` and `tests/experiments/test_entry_points.py`).

| Domain | Canonical Location / Names | Legacy Compatibility Module / Aliases |
| --- | --- | --- |
| Flow Events | `events.models.FlowEvent`<br>`events.conversion.CaptureFlowEventConverter` | `event_convertor.flow_event.FlowEvent`<br>`event_convertor.flow_event_generator.CAPTureFlowEventConvertor` |
| Scenario Generation | `scenario_generator.generator.ScenarioGenerator`<br>`scenario_generator.validation.validate_templates`<br>`scenario_generator.search.ScenarioSearch`<br>`scenario_generator.rendering.render_scenario`<br>`scenario_generator.exceptions.*` | `scenario_generator.scenario_generator.CAPTureScenarioGenerator`<br>`scenario_generator.CAPTureScenarioGenerator` |
| Reconstruction Models | `scenario_reconstructor.models` (`FlowAlert`, `AttackStep`, `AttackType`, `Precondition`, `RecoveryRequirement`, `Host`, `HostAttribute`, `NetworkState`) | `scenario_reconstructor.scenario_reconstructor` (`FlowExploit`, `Exploit`, `Preconditions`, `ExploitRequirement`) |
| Reconstruction Engine & Graph | `scenario_reconstructor.engine.ScenarioReconstructor`<br>`scenario_reconstructor.dag` (`AttackScenarioDAG`, `AttackGoal`)<br>`scenario_reconstructor.serialization` (`AlertStepParser`, `NetworkStateParser`) | `scenario_reconstructor.scenario_reconstructor` (`StarNetworkAttackGraphBasedScenarioReconstructor`, `StringToExploitConverter`, `StringToNetworkStateConvertor`) |
| Stream Management & Alerts | `scenario_reconstructor.manager.ReconstructionManager`<br>`scenario_reconstructor.alerts.AlertFactory`<br>`scenario_reconstructor.recovery` (`RecoveryPlan`, `RecoveryCandidate`) | `scenario_reconstructor.reconstruction_manager` (`ScenarioReconstructionManager`, `ExploitGenerator`) |
| Evaluation Metrics | `metrics.calculator.MetricsCalculator` (`metrics.detection`, `metrics.aggregation`, `metrics.occurrence`, `metrics.causal`, `metrics.matching`) | `scenario_generator.compute_metrics` (`MetricsCalculator`, `AttackGoal`, `AttackScenarioDAG`) |
| Campaign Config & Runners | `scenario_configs.loader` (`ScenarioConfig`, `load_scenario_config`)<br>`scenario_configs.capture`<br>`experiments.capture.main`<br>`experiments.batch` (`build_jobs`, `main`)<br>`experiments.reporting` (`IterationRecord`, `write_evaluation_outputs`, `aggregate_batch_results`, `main`) | `scenario_reconstructor.reconstruct_cAPTure`<br>`run_scripts.py` |

Do **not** change `FlowExploit(...)`, `Exploit(...)`, or `NetworkState(...)` text record formats without updating `AlertStepParser` and `NetworkStateParser` and preserving parser compatibility tests.

---

## 3. Architectural & Import Constraints

- **Domain Import Isolation (`scenario_reconstructor`)**:
  - `scenario_reconstructor/__init__.py` and core domain modules (`models/`, `dag.py`, `engine.py`, `manager.py`, `recovery.py`, `aggregation.py`, `storage.py`, `serialization.py`, `time_utils.py`, `attack_mapper.py`) **must not** import `metrics`, `pandas`, or `sklearn` at import time.
  - Keep CLI dependencies (`pandas`, `events.conversion`, `scenario_configs.capture`) isolated inside `scenario_reconstructor/cli.py` and `scenario_reconstructor/__main__.py`. Do not import `cli.py` from `scenario_reconstructor/__init__.py`.
  - Importing `scenario_configs` and loading the built-in campaign must also remain independent of `metrics`, `pandas`, and `sklearn`; keep `scenario_configs/loader.py` limited to standard-library and domain dependencies.
- **Import-Safe CLI Runners**:
  - Importing `experiments/capture.py`, `experiments/batch.py`, `experiments/reporting.py`, `scenario_generator/cli.py`, `scenario_reconstructor/cli.py`, `scenario_reconstructor/reconstruct_cAPTure.py`, or `run_scripts.py` must have **zero side effects** (no CSV reads, file writes, generation, reconstruction, or subprocess launches). All execution must live inside `main(argv=None)`.
- **Independent Experiment State**:
  - Use `config.create_hosts()` from `load_scenario_config()` per experiment run rather than mutating module-level globals (`HOSTS`, `BROKER`) across runs. Legacy `HOSTS`-only configurations must use deep copies.

---

## 4. Core Domain Invariants

Do not violate these contracts when modifying reconstruction, generation, or metric code:

1. **UTC Timestamp Normalization (`normalize_timestamp`)**:
   - Always normalize timestamps via `scenario_reconstructor.time_utils.normalize_timestamp` when comparing, sorting, checking intervals, or computing dictionary/hash keys across `FlowAlert`, `AttackStep`, `aggregation`, `manager`, `dag`, `metrics/detection.py`, and `metrics/aggregation.py`.
   - Convention: timezone-aware datetimes are converted to UTC and stripped of `tzinfo`; naive datetimes are treated as UTC and preserved as-is.
2. **Value Identity & Hash Consistency**:
   - `FlowAlert` identity (`_identity_key`) includes `(attack_type, source_ip, source_port, destination_ip, destination_port, protocol, normalize_timestamp(start_time), normalize_timestamp(end_time))`; `anomaly_score` and `attack_type_alternatives` are annotations, not identity fields.
   - `AttackStep` identity includes `(attack_type, source_ip, destination_ip, normalize_timestamp(start_time), normalize_timestamp(end_time), size, mean_interflow_time, std_interflow_time)`.
   - Never mutate identity fields of alerts, steps, `AttackType`, or `Precondition` in place while stored in sets or dicts. Use `FlowAlert.reclassify(attack_type)` to obtain an interpreted copy.
   - `NetworkState` must always own private copies of per-host attribute sets so subsequent mutations on live `Host` objects never alter historical snapshots.
3. **Strict Threshold Contract**:
   - `ReconstructionManager` requires `0 <= suspect_threshold < anomaly_threshold <= 1` (CLIs enforce `[0, 1]`; manager constructor enforces `suspect_threshold < anomaly_threshold`).
   - All score comparisons against `suspect_threshold`, `anomaly_threshold`, `type_threshold`, and `calibrate_threshold` use **strict `>`** (`score > threshold`).
4. **Internal vs. External Host Policy**:
   - Only internal hosts present in `reconstructor.host_dict` accumulate compromise state attributes (`set_postconditions`, `would_change_state`). External hosts use `external_host_attributes` purely as a read-only baseline and never acquire learned attributes.
   - Pass `tracked_host_ips=reconstructor.host_dict` when building `AttackScenarioDAG` for reconstructed or actual cAPTure scenarios. When `tracked_host_ips` is set, only effects on tracked destinations create causal dependencies.
   - In `metrics/matching.py`, `ensure_dag_pair` propagates an explicit `tracked_host_ips` policy across `(actual_scenario, predicted_scenario)` and raises `ValueError` if both sides specify conflicting explicit policies.
5. **Atomic False-Negative Recovery**:
   - Suspect evidence must start **strictly before** the trigger alert (`start_time < trigger.start_time`). Future and equal-start suspects are excluded before idle-gap clustering.
   - Each original suspect bucket is projected uniformly per matching `RecoveryRequirement` type via `FlowAlert.reclassify` before clustering; original buckets are never merged across different original classifications.
   - Candidate ranking sorts by `(candidate.is_primary, candidate.score)` descending (`score = mean_score * cluster_size`), so **all primary-type candidates are evaluated before any retyped alternative**.
   - `_validate_plan` simulates `(*ordered_supports, anomaly)` chronologically on isolated deep copies of internal and external hosts (`_validation_network()`). Every step in the plan must satisfy its preconditions; partial failures leave live state, buffers, logs, and suspects untouched.
   - `_commit_recovery` rolls back host attributes, external host registrations, `flow_exploits_dict`, and `state_sequence` if an unexpected error occurs during batch application, and removes consumed suspect occurrences by `id()` (not value equality) so unused clusters or duplicate instances remain intact.
6. **Temporal Aggregation & Incremental Archiving**:
   - `group_alerts` groups same-context alerts (`attack_type-destination_ip-source_ip`) by overlap or inclusive `max_idle_gap` (default `1s`).
   - `log_flow_exploits` and `log_states` append unlogged entries to archives without clearing buffers; `clean_flow_exploits` and `clean_states` release only already-archived prefixes.
   - `update_exploits_all` and `get_results()` aggregate over `return_all_flow_exploits()` (archived batches + unlogged buffer) so archiving/cleanup boundaries never fragment steps.
7. **AND/OR Attack DAG & Orthogonal Metrics**:
   - In `AttackScenarioDAG`, every distinct step occurrence receives its own AND/OR precondition clauses (`clause_parents_map`). Same-context repetitions do **not** create causal edges (`get_adjacent_pairs`, `get_causal_pairs`, `get_chains`); consecutive distinct repetitions are exposed separately via `get_repetition_pairs()`.
   - Duplicate step values in `steps` are retained for occurrence precision/recall, while DAG adjacency construction deduplicates identical step keys (`dict.fromkeys`) so self-loops cannot occur.
   - `AttackScenarioDAG.get_goal_clause_recovery` uses iterative traversal (safe for 1,000+ step chains) with consistent OR-branch selection (`(edge_ok, cand_ratio, -cand_req)`).
   - In `metrics/causal.py`, `causal_quality` completeness only bypasses missing steps and stops at the nearest matched ancestor so a shared ancestor cannot mask a missing matched AND parent.
8. **Scenario Generation Search & Templates**:
   - `validate_templates` validates and converts columns on a private deep copy without mutating caller DataFrames.
   - `ScenarioSearch.find_path` performs bounded iterative backtracking (`max_steps=100`, `max_search_attempts=10_000`) and raises typed `NoFeasibleScenarioError` or `ScenarioSearchLimitError`.
   - `ScenarioGenerator.generate_scenario(..., path=[(attack, src_ip, dst_ip), ...])` validates numeric limits, normal flows, and a non-empty sequence of available attack steps with distinct endpoints before rendering directly. Explicit paths bypass search rules and preserve the last result on validation failure.
   - CLI `-f` / `--file` inputs are scored/labeled flow dataset CSVs (scored flow dataset CSVs for reconstruction), used as flow templates during generation.
   - Generator, reconstruction, and evaluation CLIs accept `-c` / `--config` (`capture` by default), an importable `scenario_configs.<name>`, or a `.py` / `.json` config file through `scenario_configs/loader.py`. Validate configuration errors before reading CSV data and pass the selected score-column order to flow conversion.
   - Generator and evaluation CLIs expose mutually exclusive `--scenario-path` and repeatable `--step`. Paths accept JSON step arrays/objects, text lines, or inline `;` / `|` separated steps; individual steps use `attack:src->dst` or `attack,src,dst`. Validate syntax before reading CSV data. Only forward the `path` keyword to `generate_scenario` when an explicit path was supplied.

---

## 5. Testing & Verification Commands

Run the full test suite from the repository root using the project virtual environment:

```powershell
# Preferred: run all unit, regression, and integration tests via pytest
.\.venv\Scripts\python.exe -m pytest tests -q

# Alternative via unittest (NOTE: -t . is required so tests/metrics and tests/events
# do not shadow top-level metrics/ and events/ packages on sys.path)
.\.venv\Scripts\python.exe -m unittest discover -s tests -t . -q

# Check whitespace and patch hygiene
git diff --check
```

- Shared test base classes, lifecycle isolation helpers (`ProjectTestCase`), and fixture factories live in `tests/support.py`.
- Note on Windows sandboxing: If executing inside a restricted sandbox where `.venv\Scripts\python.exe` raises `Access is denied`, invoke Python directly from the host shell outside the sandbox to verify runtime tests.
