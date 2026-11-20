# Attack Scenario Reconstruction

A Python framework for turning isolated, noisy network intrusion alerts into explainable multi-stage attack scenarios. The project is demonstrated on the [`dollar_char` campaign](https://www.sciencedirect.com/science/article/pii/S1389128626005827) from the cAPTure IIoT/MQTT dataset. It provides an end-to-end workflow for preparing scored flow datasets, synthesizing multi-step attack scenarios, reconstructing attack timelines and causal graphs, and evaluating reconstruction quality.

---

## 1. Introduction & Project Structure

Traditional intrusion detection systems inspect network flows one by one. In practice, this leaves security analysts with fragmented alerts, false positives triggered by normal traffic, and missing steps caused by false negatives.

**Attack Scenario Reconstruction** addresses this by reasoning about **network state** across time. Each host in the monitored network is modeled with security-relevant attributes (for example, *SSH discovered* or *SSH compromised*), and each attack type specifies the preconditions it requires and the postconditions it produces. Using this model, the framework carries out four main functions:

1. **Dataset Preparation & ML Scoring**
   Converts packet captures into flow tables, augments benign background traffic, and scores each network flow with an overall anomaly score and per-attack-type probabilities.
2. **Synthetic Scenario Generation**
   Takes a labeled/scored flow dataset and synthesizes complete multi-step attack campaigns mixed with background traffic. Scenarios can either be sampled automatically under valid campaign progression rules or generated from an explicit step-by-step path.
3. **State-Based Scenario Reconstruction**
   Processes a stream of scored flows to build an attack timeline and causal graph:
   - **Noise filtering & false-positive rejection:** Flows below a suspicion cutoff are ignored, while high-confidence alerts are accepted only if their preconditions hold in the current network state.
   - **False-negative recovery:** When a high-confidence alert arrives with missing prerequisites, the reconstructor inspects lower-confidence *suspect* flows from earlier in the stream to recover the missed enabling step—only committing the recovery if the entire sequence validates cleanly.
   - **Step aggregation:** Related alerts sharing the same source, destination, and attack type within a configurable idle gap are grouped into discrete attack steps.
   - **Causal AND/OR Attack Graph:** Reconstructed steps are connected into a Temporal AND/OR Directed Acyclic Graph (DAG) showing which earlier steps enabled later ones.
4. **Four-Stage Evaluation**
   Evaluates every stage of the pipeline independently—alert detection, alert-to-step grouping, step occurrence coverage, and causal graph / goal recovery—so errors at one level do not distort metrics at another.

### Repository Layout

```text
Attack-Scenario-Reconstruction/
├── jupyter notebook/        # Notebooks for PCAP conversion, multi-campaign labeling, and ML scoring
├── preprocessing/           # Reusable datasets, evaluation/plotting, MAC/IPv4, UTC time, augmentation, and training helpers
├── scenario_configs/        # Built-in cAPTure campaign definition and .py/.json config loader
├── scenario_generator/      # Synthetic scenario synthesis and CLI (`python -m scenario_generator`)
├── events/                  # Conversion from scored flow CSVs into UTC FlowEvent streams
├── scenario_reconstructor/  # State engine, FN recovery, aggregation, DAG, and CLI (`python -m scenario_reconstructor`)
├── metrics/                 # Four-stage evaluation suite (`MetricsCalculator`)
├── experiments/             # Benchmark runners (`capture`, `batch`, `reporting`), policy loader (`policy`), and JSON configs (`configs/`)
└── tests/                   # Unit, regression, and integration tests
```

*(Note: `AGENTS.md` documents architectural invariants, package boundaries, and verification commands for developers and coding agents.)*

---

## 2. Usage Tutorial

### Step 1: Installation

Create and activate a Python virtual environment, then install the dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2: Prepare or Obtain a Scored Flow Dataset CSV

Both the generator and reconstructor read **labeled/scored flow dataset CSVs**. Each row represents a network flow with these columns:

- **Flow metadata & labels:** `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `timestamp`, `duration` (ms), `label` (`"normal"` for background traffic, or an attack name), `step_number` (`-1` for `"normal"`, or an integer ID grouping flows belonging to the same attack execution), and optional `campaign_id` (`-1` for `"normal"`, or `0..N-1` per attack campaign in multi-campaign exports).
- **Detector & classifier scores:** `anomaly_score` in `[0, 1]`, plus one score column per configured attack type (for the built-in `capture` campaign: `nmap_10_T5`, `nmap_mqtt`, `nmap_banner`, `brute_force_malformed`, `dollar_char`, `scp_inst`).

You can generate these scored CSVs from raw cAPTure traffic by running the notebooks in `jupyter notebook/` in order (`convert_to_csv.ipynb` → `process_attack_campaigns.ipynb` → `attack_normal_merging.ipynb` → `reconstruction_dataset_creation.ipynb`), which outputs under `data/cAPTure/`:
- `merged/` (`train.csv`, `test.csv`, and augmented normal sets)
- `ml/` (`ML_train.csv`, `ML_test.csv`, `calibrated_thresholds.json`, and `plots/`)
- `final_datasets/<campaign_name>/` (per-campaign `{anomaly}_{mapper}_rec_dataset.csv` template sets) and `final_datasets/all_campaigns/` (pooled multi-campaign copy).

---

### Step 3: Generate Synthetic Scenarios (`scenario_generator`)

Use `python -m scenario_generator` to turn a scored/labeled flow dataset CSV into a complete synthetic attack scenario (`.csv`) along with optional ground-truth steps and alerts.

#### Option A: Automatic Scenario Generation
Sample a valid multi-step scenario using a campaign configuration (`--config capture` is the default):

```powershell
python -m scenario_generator `
  -f data/final_dataset.csv `
  --config capture `
  -o output/scenario.csv `
  --steps-output output/actual_steps.txt `
  --alerts-output output/actual_alerts.txt `
  --normal-divisor 10 `
  --seed 42
```

- `--normal-divisor`: Keeps every Nth normal background flow (`1` keeps all normal flows; `10` keeps 10%).
- `--seed`: Fixes random sampling and inter-step timing for reproducible scenarios.
- `--max-steps`, `--max-search-attempts`, `--max-generation-retries`: Bound the scenario search depth and retries.

#### Option B: Explicit Step Sequence
If you want to synthesize a specific sequence of attack steps instead of sampling one randomly, pass repeatable `--step` arguments or a `--scenario-path` file:

```powershell
# Using repeatable --step arguments ('attack:src->dst' or 'attack,src,dst')
python -m scenario_generator `
  -f data/final_dataset.csv `
  -o output/scenario.csv `
  --step "nmap_10_T5:10.0.0.2->10.0.0.7" `
  --step "brute_force_malformed:10.0.0.2->10.0.0.7" `
  --seed 42

# Or using a JSON / text file of steps
python -m scenario_generator `
  -f data/final_dataset.csv `
  -o output/scenario.csv `
  --config campaign.json `
  --scenario-path steps.json
```

`--scenario-path` accepts a JSON list (such as `[["probe", "10.0.0.2", "10.0.0.9"]]`), a `{"steps": [...]}` object, a line-by-line text file, or an inline `;`/`|`-separated string.

#### Defining a Custom Campaign (`--config`)
Both `scenario_generator` and `scenario_reconstructor` accept `-c` / `--config` pointing to a named built-in config (`capture`), a `.py` config module, or a `.json` file:

```json
{
  "attack_types": [
    {
      "identifier": "probe",
      "preconditions": [{"attributes": ["start"], "targets_source": true}],
      "postconditions": ["discovered"],
      "description": "Scan target host"
    },
    {
      "identifier": "exploit",
      "preconditions": [{"attributes": ["discovered"], "targets_source": false}],
      "postconditions": ["compromised"]
    }
  ],
  "hosts": {"10.0.0.9": []},
  "external_host_attributes": ["start"],
  "next_attack_dict": {"start": ["probe"], "probe": ["exploit"], "exploit": ["end"]},
  "possible_srcs": {"probe": ["10.0.0.2"], "exploit": ["10.0.0.2"]},
  "possible_dsts": {"probe": ["10.0.0.9"], "exploit": ["10.0.0.9"]},
  "final_atk": "exploit"
}
```

*(Optional JSON fields include `"attributes"`, `"undetermined"`, `"attack_goal"`, `"score_columns"`, `"enable_src_for"`, `"enable_dst_for"`, `"dst_restricted_atks"`, and `"enable_atks"`.)*

---

### Step 4: Reconstruct a Scenario (`scenario_reconstructor`)

Run the reconstructor on any scored flow CSV (such as the `output/scenario.csv` produced in Step 3):

```powershell
python -m scenario_reconstructor `
  -f output/scenario.csv `
  --config capture `
  -o output/predicted_steps.txt `
  --alerts-output output/predicted_alerts.txt `
  --anomaly-threshold 0.8 `
  --suspect-threshold 0.4 `
  --type-threshold 0.2 `
  --max-idle-gap 1.0
```

Key reconstruction parameters:
- `--anomaly-threshold` (default `0.8`): Flows with `anomaly_score` strictly above this value enter validation as candidate attack alerts.
- `--suspect-threshold` (default `0.4`): Flows scoring in `(suspect_threshold, anomaly_threshold]` are buffered as suspects for potential false-negative recovery. Flows at or below `suspect_threshold` are ignored.
- `--type-threshold` (default `0.2`): Per-attack-type probability cutoff used to assign primary and alternative attack types.
- `--max-idle-gap` (default `1.0`, seconds): Maximum silence between consecutive alerts of the same context before splitting them into separate attack steps.
- Archive options (`--flow-log-path`, `--state-log-path`, `--log-flow-exploits-threshold`, `--log-states-threshold`, `--suspect-max-length`) and `--quiet` are also available (run with `--help` for all options).

---

### Step 5: Run the cAPTure Evaluation Experiments

To reproduce the multi-cycle cAPTure dataset benchmark (repeatedly generating scenarios from a cAPTure-structured dataset, reconstructing them, and averaging all evaluation metrics), pass reconstruction policy arguments directly or load them from a JSON file via `--policy-config` (explicit CLI flags override policy file values):

```bash
python -m experiments.capture \
  -f data/cAPTure/final_datasets/dollar_char/xgb_xgb_rec_dataset.csv \
  --policy-config experiments/configs/dollar_char_policy.json \
  -t 100 \
  -l output/capture_metrics.txt \
  --anomaly-threshold 0.8 \
  --suspect-threshold 0.4 \
  --type-threshold 0.2 \
  --edge-recovery-threshold 0.8 \
  --seed 42 \
  --quiet
```

This writes mean confusion matrices, alert precision/recall, step aggregation soundness/completeness, step occurrence precision/recall, causal graph soundness/completeness, and goal detection rate to `output/capture_metrics.txt`, along with a separate `*_fn_generating_scenarios.txt` log for any cycle where reconstruction introduced extra false negatives.

Each evaluation also writes `*_iterations.csv` (one row per cycle, numbered from zero) and `*_summary.csv` (one row per run). Iteration rows contain actual/predicted step and alert counts, recovered false negatives, rejected false positives, and all four metric layers. Summary rows contain the mean and population standard deviation (`ddof=0`) of each numeric metric and count. Both CSVs include dataset filename, detector/mapper names parsed from the filename, configuration, thresholds, idle gap, seed, and cycle count. Use `--iterations-csv <path>` and `--summary-csv <path>` to override the default paths beside the text log; parent directories are created automatically.

To run the benchmark grid across configured datasets and thresholds via `experiments.batch` (or the compatibility wrapper `run_scripts.py`), using default paths `./data/cAPTure/final_datasets/dollar_char/` and `./data/cAPTure/results/dollar_char/`:

```bash
# Run with default 48-job grid
python -m experiments.batch

# Or run a customized subset driven by a JSON policy config (CLI flags override file settings)
python run_scripts.py \
  --policy-config experiments/configs/dollar_char_policy.json \
  --datasets perfect_perfect \
  --times 10 \
  --workers 4
```

`experiments.batch` supports `--policy-config`, `--dataset-dir`, `--results-dir`, `-c`/`--config`, `-t`/`--times`, `--workers` (concurrent subprocesses with deterministic aggregation order), `--datasets`, `--detectors` (or `all`), `--mappers` (or `all`), `--resume` (skips jobs with non-empty `_summary.csv` and `_iterations.csv`), `--seed` / `--no-seed`, `--quiet`, and policy overrides (`--anomaly-thresholds`, `--suspect-thresholds`, `--type-threshold`, `--suspect-max-length`, `--log-flow-exploits-threshold`, `--log-states-threshold`, `--max-idle-gap`, `--edge-recovery-threshold`, `--normal-divisor`). Combined `batch_summary.csv` and `batch_iterations.csv` include only jobs that succeeded or resumed in the current run; failed-job files are preserved for diagnosis and excluded from automatic batch aggregation.

`experiments/reporting.py` provides the reusable CSV/text writers and batch aggregation API. Rebuild the aggregate CSVs from existing run CSVs without rerunning evaluations:

```bash
python -m experiments.reporting -d "data/cAPTure/results/dollar_char"
```

This standalone rebuild discovers available CSVs without knowing which jobs succeeded; use it on a curated set of run files. Aggregation skips missing files, excludes the master CSVs from discovery, and creates no directories or files when no run CSVs exist.

---

### Step 6: Python API Quickstart

You can also embed generation, reconstruction, DAG construction, and evaluation directly in Python:

```python
import pandas as pd
from events.conversion import CaptureFlowEventConverter
from metrics import MetricsCalculator
from scenario_configs import load_scenario_config
from scenario_generator import ScenarioGenerator
from scenario_reconstructor.attack_mapper import AttackMapper
from scenario_reconstructor.dag import AttackScenarioDAG
from scenario_reconstructor.engine import ScenarioReconstructor
from scenario_reconstructor.manager import ReconstructionManager

config = load_scenario_config("capture")  # Or pass a .py / .json config file path.
dataset_df = pd.read_csv("data/final_dataset.csv")

# 1. Generate a synthetic scenario
generator = ScenarioGenerator(
    dataset_df, config.next_attack_dict, config.enable_src_for, config.enable_dst_for,
    config.possible_srcs, config.possible_dsts, config.dst_restricted_atks,
    config.final_atk, config.enable_atks,
)
scenario_df = generator.generate_scenario(normal_flow_number_divisor=10)
actual_steps, actual_alerts = generator.export_results(config.atk_types)

# 2. Reconstruct the scenario from scored flows
flows = CaptureFlowEventConverter().convert(scenario_df, score_columns=config.score_columns)
reconstructor = ScenarioReconstructor(
    config.create_hosts(), config.external_host_attributes, config.atk_types,
    "./data/flow_exploits.log", "./data/states.log",
)
manager = ReconstructionManager(
    reconstructor, AttackMapper(config.atk_types, type_threshold=0.2),
    suspect_threshold=0.4, anomaly_threshold=0.8, unknown_attack=config.undetermined,
)
for flow in flows:
    manager.accept(flow)

predicted_dag, predicted_alerts = manager.get_results()
actual_dag = AttackScenarioDAG(actual_steps, tracked_host_ips=reconstructor.host_dict)

# 3. Evaluate across all four stages
calc = MetricsCalculator()
print("Alert P/R:", calc.get_alert_precision(predicted_alerts, actual_alerts, config.undetermined),
      calc.get_alert_recall(predicted_alerts, actual_alerts, config.undetermined))
print("Causal Soundness/Completeness:",
      calc.get_scenario_soundness_completeness(predicted_dag, actual_dag, config.undetermined))
print("Goal Detected:",
      calc.is_scenario_detected(predicted_dag, actual_dag, config.attack_goal, config.undetermined))
```

---

### Running the Test Suite

To verify the entire framework:

```bash
# Via unittest (works with standard library only; -t . keeps top-level packages on sys.path)
python -m unittest discover -s tests -t . -q

# Or via pytest (if installed in your environment)
python -m pytest tests -q
```
