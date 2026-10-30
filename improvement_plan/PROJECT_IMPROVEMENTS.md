# Attack Scenario Reconstruction: Project Analysis, Problems, and Solutions

This document provides an exhaustive technical and methodological review of the **Attack Scenario Reconstruction** project (`Attack-Scenario-Reconstruction`), synthesizing insights from both the accompanying Master Thesis (*"Attack Scenario Reconstruction for Multi-Step Attack Detection"*) and a deep inspection of the source code and Jupyter notebooks.

---

## Executive Summary & Main Directions for Improvement

The project proposes a unified, ML-driven NIDS alert generation and attack-graph scenario reconstruction pipeline with explicit False Negative (FN) recovery and False Positive (FP) pruning. Based on our analysis of the thesis and codebase, the main directions for improvement are grouped into five strategic pillars:

1. **Resolving the "Broken Attack Scenario" & Causal State-Tracking Limitations (Algorithmic Core)**
   - Allowing attack type revision (`_try_alternative_types`) for low-suspicion candidate alerts during FN recovery.
   - Extending single-hop missed exploit recovery (`compute_requirements`) to multi-hop path search (BFS/shortest-path over the attack graph).
   - Enforcing temporal causality (`happens-before` constraints) during FN recovery and replacing scale-invariant `StandardScaler + DBSCAN` clustering with physical time-window/1D-DBSCAN clustering.
   - Moving from greedy, irreversible state transitions to probabilistic or multi-hypothesis graph tracking (reducing dependence on rigid prior knowledge and preventing state pollution by `UNDETERMINED` wildcard postconditions).

2. **Uncertainty Quantification & Model Calibration (Machine Learning Pipeline)**
   - Replacing uncalibrated raw probability/score thresholds across heterogeneous models (`IsolationForest`, `GaussianNB`, `XGBoost`, `LogisticRegression`) with calibrated probabilities (`CalibratedClassifierCV`) and epistemic/aleatoric uncertainty estimation (e.g., Conformal Prediction or ensemble variance).
   - Eliminating test-set data leakage in threshold selection, addressing severe class imbalance in one-vs-rest attack mappers, and replacing arbitrary integer encoding of nominal features with one-hot/target encoding.

3. **Data Preprocessing & Semi-Synthetic Scenario Generation Fidelity**
   - Fixing critical timestamp distortion and negative feature values introduced during Gaussian noise perturbation of synthetic benign flows.
   - Resolving IPv6-to-IPv4 MAC-mapping collisions and regex filtering bugs that leak unresolved IPv6 addresses or drop valid flows.
   - Preventing runaway IP duplication and potential infinite loops in `CAPTureScenarioGenerator`.

4. **Evaluation Standardization & Metric Correctness**
   - Correcting the scenario completeness calculation in `MetricsCalculator`, which currently computes completeness only over *already matched* ground-truth steps rather than all ground-truth steps.
   - Enforcing 1-to-1 bipartite matching between predicted and actual steps/alerts, and fixing unit/timezone mismatches between `CAPTureScenarioGenerator` and `StarNetworkAttackGraphBasedScenarioReconstructor`.

5. **Software Engineering & Runtime Robustness**
   - Fixing Python data-model contract violations (`__eq__` vs. `__hash__` with floating-point tolerances), external destination host crashes, state-wiping bugs during intermediate logging, and OS-specific CLI runner issues.

---

## Part 1: Algorithmic & Architectural Problems and Solutions

### 1.1 The "Broken Attack Scenario" Problem (Unrevisable Low-Suspicion Alert Types)
* **Context & Location:** Thesis Chapter 6.2 & Chapter 7; [reconstruction_manager.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/reconstruction_manager.py#L86-L141) (`ScenarioReconstructionManager.accept` and `_recover_fns`).
* **Problem:** When an incoming event has `suspect_threshold < anomaly_score <= anomaly_threshold`, it is converted into a `FlowExploit` via `ExploitGenerator.to_flow_exploit` and stored in `self.suspect_dict` indexed only by its top predicted attack type (`main_type`). Unlike high-suspicion alerts (which invoke `_try_alternative_types` using `attack_type_alternatives` when preconditions fail), low-suspicion alerts in `suspect_dict` never have their alternative attack types evaluated. If the Attack Mapper misclassifies a critical intermediate step (e.g., `XGBoost` failing on `brute_force_malformed`), `_recover_fns` cannot find it under the required attack type. Consequently, the network state never advances, causing all subsequent legitimate attack steps (`nmap_mqtt`, `scp_inst`, `dollar_char`) to fail precondition checks and be discarded as False Positives—drastically increasing False Negatives.
* **Solution:**
  1. Index suspect alerts in `suspect_dict` by `(source_ip, destination_ip)` rather than locking them to a single `attack_type.identifier`, or index them under all viable types in `[anomaly.attack_type] + anomaly.attack_type_alternatives`.
  2. During `accept()` and `_try_alternative_types()`, allow the FN search to match suspect flows whose primary *or* alternative attack types (weighted by their type probability scores) satisfy `req.attack_type`.
  3. Mutate the recovered suspect's `attack_type` to `req.attack_type` upon recovery.

### 1.2 Scale-Invariant `StandardScaler` + `DBSCAN` Temporal Clustering Flaw
* **Context & Location:** [reconstruction_manager.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/reconstruction_manager.py#L32-L45) (`_find_most_recent_flow_cluster`) and [scenario_reconstructor.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/scenario_reconstructor.py#L583-L593) (`update_exploits`).
* **Problem:** Both FN recovery and step aggregation normalize `start_time` and `end_time` using `StandardScaler()` before running `DBSCAN(eps=0.5, min_samples=2)`:
  1. **Mathematical Failure for $N=2$ Flows:** For any two flows with distinct timestamps ($t_1 \neq t_2$), `StandardScaler` maps them to $(-1, -1)$ and $(+1, +1)$. The Euclidean distance is $\sqrt{(1 - (-1))^2 + (1 - (-1))^2} = \sqrt{8} \approx 2.828 > 0.5$ (or $2.0$ in 1D). Thus, **two flows can never form a cluster**, regardless of whether they occurred 1 millisecond apart.
  2. **Zero-Variance Crash:** If all flows in a group have identical timestamps, `StandardScaler` divides by zero standard deviation, producing `NaN` values and crashing `DBSCAN` with `ValueError: Input X contains NaN`.
  3. **Scale Invariance:** Standardizing timestamps makes clustering dependent on the global time span of the recorded history rather than physical inter-flow gaps. Two flows 10 minutes apart will cluster together if a third flow occurred 10 days later, whereas two flows 50ms apart will be split if total variance is small.
* **Solution:**
  - Remove `StandardScaler()` completely from timestamp clustering.
  - Perform DBSCAN directly on raw timestamps (in seconds or milliseconds) using a physically meaningful domain `eps` parameter (e.g., `eps=5.0` seconds) representing the maximum inter-flow gap within a single attack step:
    ```python
    X = np.array([[fe.start_time.timestamp(), fe.end_time.timestamp()] for fe in flow_exploit_list])
    clusterer = DBSCAN(eps=self.time_window_seconds, min_samples=1)
    labels = clusterer.fit_predict(X)
    ```
  - Setting `min_samples=1` also naturally handles singleton clusters without needing separate noise-handling branches.

### 1.3 Lack of Temporal Precedence ("Happens-Before") Constraint in FN Recovery
* **Context & Location:** Thesis Section 5.1.3 (p. 67); [reconstruction_manager.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/reconstruction_manager.py#L103-L122) and `#L172-L191`.
* **Problem:** When searching `self.suspect_dict` to satisfy missing preconditions for a current `anomaly`, the engine does not verify that candidate suspect flows occurred *before* `anomaly.start_time`. Furthermore, when a suspect group wins in `_recover_fns`, line 185 wipes the entire list (`self.suspect_dict[winning_group_id] = []`), deleting all other suspect clusters in that group that might be needed for subsequent steps.
* **Solution:**
  - Filter `suspect_list` by temporal causality before clustering:
    ```python
    valid_suspects = [s for s in suspect_list if s.start_time <= anomaly.start_time]
    ```
  - In `_recover_fns`, remove only the flows belonging to the recovered `flow_exploit_cluster` from `self.suspect_dict[winning_group_id]`, preserving remaining candidate flows.

### 1.4 Single-Hop Missed Exploit Assumption & Incomplete Multi-Precondition Recovery
* **Context & Location:** [scenario_reconstructor.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/scenario_reconstructor.py#L446-L503) (`compute_requirements`) and [reconstruction_manager.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/reconstruction_manager.py#L120-L122).
* **Problem:**
  1. `compute_requirements` assumes at most **one** missed exploit connects the current network state to the new alert. If both source and destination preconditions are unsatisfied (`len(red_src_preconditions) != 0 and len(red_dst_preconditions) != 0`), or if two consecutive steps were missed ($A \to B \to C$ where $A$ and $B$ are in `suspect_dict`), `compute_requirements` returns `None` and drops $C$ as an FP.
  2. In `_recover_fns` ([reconstruction_manager.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/reconstruction_manager.py#L172-L191)), only a single `winning_group_id` with the highest `mean_anomaly_score * len(cluster)` is recovered, and line 121 immediately calls `self._add_to_reconstructor(anomaly)` without re-checking `self.reconstructor.check_preconditions(anomaly)`.
* **Solution:**
  - Generalize `compute_requirements` into a bounded backward breadth-first search (BFS, e.g., depth $k \le 3$) over the attack graph to find minimal sequences of missing `ExploitRequirement` steps whose preconditions are satisfied by the current network state and whose candidate flows exist in `suspect_dict`.
  - If an exploit has unsatisfied preconditions on both source and destination hosts, allow `compute_requirements` to return a conjunction (list) of requirements—one for the source host and one for the destination host—and verify `self.reconstructor.check_preconditions(anomaly)` after recovery before adding `anomaly`.

### 1.5 Over-Permissive Wildcard (`UNDETERMINED`) Zero-Day Modeling & State Pollution
* **Context & Location:** Thesis Section 5.2.5 (p. 86); [reconstruct_cAPTure.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/reconstruct_cAPTure.py#L100-L104).
* **Problem:** The `UNDETERMINED` attack type is modeled as the union of all postconditions (`{SSH_DISCOVERED, MQTT_DISCOVERED, SSH_COMPROMISED, CRASHED, SCRIPTS_INSTALLED}`). Whenever a single high-anomaly flow fails to exceed `type_threshold` for any specific mapper, it is mapped to `UNDETERMINED`. Once accepted, it immediately grants **every compromise attribute** to the destination host. This destroys the selectivity of the attack graph: any future false positive targeting or originating from that host will automatically satisfy all preconditions, inflating FPs and corrupting the state history.
* **Solution:**
  - Instead of eagerly applying the union of all postconditions when an `UNDETERMINED` alert arrives, implement **lazy/deferred state resolution**: record the `UNDETERMINED` alert as a wildcard node on the target host and resolve its concrete type/postcondition retroactively when a subsequent known exploit requires a specific precondition on that host.
  - Alternatively, restrict `UNDETERMINED` postconditions to only those attack types whose preconditions were actually satisfied on the source and destination hosts at the time the `UNDETERMINED` alert was executed.

### 1.6 Irreversible State Transitions & Reliance on Static Prior Knowledge
* **Context & Location:** Thesis Chapter 7 (pp. 107–109); [scenario_reconstructor.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/scenario_reconstructor.py#L505-L529).
* **Problem:** Once an alert satisfies preconditions, `set_postconditions` permanently mutates `host.compromise_attributes`. A single early False Positive alert can permanently mark a host as compromised, enabling chains of subsequent FPs. Furthermore, constructing exact precondition/postcondition rules requires extensive manual domain engineering.
* **Solution:**
  - Introduce **probabilistic state tracking** or **multi-hypothesis scenario trees** (similar to Reid's MHT or particle filtering): maintain confidence weights on host compromise attributes based on the cumulative anomaly/type probabilities and cluster sizes of the supporting exploits, decaying attributes that are only supported by isolated singleton flows.
  - To reduce dependence on manual attack graphs, augment the reconstructor with a learned sequence/graph model (e.g., neural alert embeddings + sequential pattern mining / Markov transition matrix learned from historical flow sequences) as a fallback when explicit precondition rules are absent.

---

## Part 2: Machine Learning & Uncertainty Estimation Problems and Solutions

### 2.1 Uncalibrated Thresholds vs. Uncertainty Estimation
* **Context & Location:** Thesis Chapter 7 (p. 108); [run_scripts.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/run_scripts.py#L18-L20), [reconstruct_cAPTure.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/reconstruct_cAPTure.py#L124-L129), [reconstruction_dataset_creation.ipynb](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/jupyter%20notebook/reconstruction_dataset_creation.ipynb).
* **Problem:** Fixed numerical thresholds (`suspect_threshold in [0.2, 0.8]`, `anomaly_threshold in [0.3, 0.6, 0.9]`, `type_threshold = 0.1`) are applied uniformly across models with vastly different output distributions:
  - `IsolationForest` outputs min-max scaled anomaly scores skewed heavily toward a narrow band.
  - `GaussianNB` outputs extreme probabilities pushed to $0.0$ or $1.0$ due to conditional independence assumptions.
  - `XGBoost` and `LogisticRegression` have distinct calibration profiles.
  Moreover, raw point-estimate probabilities do not distinguish between **aleatoric uncertainty** (overlapping classes, e.g., `nmap_mqtt` vs `nmap_banner`) and **epistemic uncertainty** (unseen/zero-day attack patterns).
* **Solution:**
  1. **Probability Calibration:** Wrap supervised classifiers in `sklearn.calibration.CalibratedClassifierCV(method='isotonic' or 'sigmoid', cv=5)` on the training set so that scores represent true empirical probabilities. For unsupervised detectors (`IsolationForest`), use empirical Cumulative Distribution Function (ECDF / quantile) scoring (`scipy.stats.rankdata` or PyOD's `predict_confidence`).
  2. **Conformal Prediction / Uncertainty Quantification:** Implement Split Conformal Prediction for the Attack Mapper. Instead of picking all classes $> 0.1$, construct a conformal prediction set $C(x) \subseteq \mathcal{Y}$ guaranteed to contain the true attack type with probability $1 - \alpha$ (e.g., $95\%$).
     - If $|C(x)| == 0$ (high epistemic uncertainty / out-of-distribution), classify the anomalous flow as a **Zero-Day (`UNDETERMINED`)** attack.
     - If $|C(x)| == 1$, assign `main_type` with high confidence.
     - If $|C(x)| > 1$ (high aleatoric uncertainty), populate `attack_type_alternatives` with the conformal set.

### 2.2 Severe Class Imbalance & Missing Hyperparameter Weighting in Attack Mappers
* **Context & Location:** Thesis Table 10 (p. 92); [reconstruction_dataset_creation.ipynb](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/jupyter%20notebook/reconstruction_dataset_creation.ipynb) (Cells 102–112).
* **Problem:** Each attack type mapper is trained as a one-vs-rest binary classifier on the entire dataset where benign flows and other attacks outnumber specific steps (like `scp_inst`, `dollar_char`, or `brute_force_malformed`) by $100:1$ to $1000:1$. Because `XGBClassifier()` and `LogisticRegression()` are instantiated without class weighting, `LogisticRegression` achieves `0.000` recall/precision on `scp_inst` and `XGBoost` achieves `0.058` recall / `0.001` precision on `brute_force_malformed` (Thesis Table 10), directly triggering the broken scenario problem.
* **Solution:**
  - Set `scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()` in `XGBClassifier`.
  - Set `class_weight="balanced"` in `LogisticRegression`.
  - Alternatively, replace the 6 independent binary one-vs-rest models with a single **multiclass classifier** trained only on malicious flows (or with a dedicated benign class + balanced sample weights), which directly models inter-attack decision boundaries and ensures probabilities sum to $1.0$.

### 2.3 Test-Set Data Leakage & Feature Engineering Flaws
* **Context & Location:** [reconstruction_dataset_creation.ipynb](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/jupyter%20notebook/reconstruction_dataset_creation.ipynb) (Cells 17, 33–34, 64).
* **Problem:**
  1. **Data Leakage in `compute_thresh` (Cell 64):** Thresholds are computed by running `precision_recall_curve(y_test, y_prob)` directly on `X_test`/`y_test`. Additionally, `thresh[np.where(rec >= recall)[0][-1]]` can raise `IndexError` when the last element of `rec` is selected (since `len(thresh) == len(rec) - 1`).
  2. **Aggressive Low-Variance Filtering (Cell 17):** Dropping all columns where the mode frequency is $\ge 99\%$ (`value_counts(normalize=True).iloc[0] >= 0.99`) removes rare protocol/MQTT/SSH indicators that only activate during brief attack steps (which represent $< 1\%$ of total flows).
  3. **Arbitrary Integer Encoding of Nominal Features (Cells 33–34):** Categorical strings are mapped to arbitrary integers (`0, 1, 2, ...`) and passed to linear (`LogisticRegression`) and Gaussian (`GaussianNB`, `QDA`) models, imposing artificial ordinal relationships.
* **Solution:**
  - Carve out a dedicated validation split (`train_test_split(X_train, y_train, stratify=y_train)`) for threshold calibration and hyperparameter tuning.
  - Relax the low-variance filter to only drop 100% constant columns (`nunique(dropna=False) <= 1`), or check variance conditioned on the positive attack classes.
  - Use `OneHotEncoder(handle_unknown='ignore')` or `TargetEncoder` inside an `sklearn.compose.ColumnTransformer` pipeline.

---

## Part 3: Data Pipeline & Scenario Generation Problems and Solutions

### 3.1 Corrupt Timestamp Arithmetic & Negative Values in Synthetic Benign Traffic
* **Context & Location:** [attack_normal_merging.ipynb](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/jupyter%20notebook/attack_normal_merging.ipynb) (Cells 50–54, 58–59), [process_attack_train.ipynb](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/jupyter%20notebook/process_attack_train.ipynb) (Cells 23, 26), [process_attack_test.ipynb](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/jupyter%20notebook/process_attack_test.ipynb) (Cells 18, 21).
* **Problem:**
  1. **Epoch Division Bug (Cell 50):** In `generate_synthetic_data`, `n_df[cols] = df[cols].to_numpy() // repetitions + delta + start_time` divides Unix epoch timestamps (`~1.75e12` ms) by `repetitions = 500`. This shrinks all synthetic flow durations by a factor of 500 and adds `~3.5e9` ms (~40.5 days) on top of `start_time`.
  2. **Negative Physical Features (Cell 50):** Adding zero-mean Gaussian noise (`np.random.normal(0, 0.1 * std)`) to non-negative network counters (byte counts, packet counts, durations, inter-arrival times) produces negative packet/byte counts. This makes synthetic normal flows trivially distinguishable from real attack flows, explaining why supervised anomaly detectors (`XGBoost`, `LogisticRegression`) achieved an artificial `1.000` precision and `1.000` recall in Thesis Table 9!
  3. **Pandas Index Misalignment & Independent Column Shuffling (Cell 50):** `df` is sorted by timestamp without `.reset_index(drop=True)`, and then assigned a newly constructed `pd.DataFrame` for `cat_cols` (which has a default `0..N-1` index), misaligning rows and shuffling categorical columns independently of each other.
  4. **Unsafe Timezone Subtraction:** `start_time.item().replace(hour=start_time.item().hour - 2)` raises `ValueError: hour must be in 0..23` if the capture started between `00:00` and `01:59`.
* **Solution:**
  - Normalize timestamps relative to the minimum timestamp before scaling: `(df[cols] - df["bidirectional_first_seen_ms"].min()) // repetitions + delta + start_time`.
  - Clip perturbed numerical columns to valid physical bounds: `n_df[col] = np.clip(n_df[col] + noise, a_min=0, a_max=None)` and recompute derived totals (such as `bidirectional_bytes = src2dst_bytes + dst2src_bytes`).
  - Keep categorical tuples intact per flow (or sample whole rows with replacement) instead of shuffling categorical columns independently, and always call `df = df.sort_values(...).reset_index(drop=True)`.
  - Replace `.replace(hour=hour - 2)` with `start_time.item() - timedelta(hours=2)`.

### 3.2 Flawed IPv6-to-IPv4 Conversion & Regex Filtering Bug
* **Context & Location:** Thesis Chapter 5.2.2 (p. 76) & Chapter 7 (p. 108); [attack_normal_merging.ipynb](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/jupyter%20notebook/attack_normal_merging.ipynb) (Cells 11–33).
* **Problem:**
  1. **Regex Dot Bug (Cells 32–33):** Filtering IPv4 addresses uses:
     ```python
     attack_test = attack_test[attack_test["src_ip"].str.contains(".") & attack_test["dst_ip"].str.contains(".", regex=False)]
     ```
     Because `regex=False` was omitted on the first `.str.contains(".")`, `.` is interpreted as a regular expression wildcard matching **any character**, allowing unresolved IPv6 addresses in `src_ip` to pass through whenever `dst_ip` is IPv4.
  2. **Conversion Logic Flaw (Cells 22 & 27):** `elif src_mac not in mappings: mapping_not_found_train += 1` triggers even when `src_ip` is already a valid IPv4 address if its MAC wasn't previously recorded.
* **Solution:**
  - Explicitly pass `regex=False` on both `src_ip` and `dst_ip`:
    ```python
    mask = (~df["src_ip"].str.contains(":", regex=False)) & (~df["dst_ip"].str.contains(":", regex=False))
    ```
  - Only look up `mappings[mac]` when `":" in ip`.

### 3.3 `CAPTureScenarioGenerator` Biased IP Sampling & Infinite Loop Risks
* **Context & Location:** [scenario_generator.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_generator/scenario_generator.py#L58-L93) and `#L143`.
* **Problem:**
  1. **Duplicate IP Accumulation (Lines 86–92):** Every time an attack executes on `dst_ip`, `possible_srcs[atk].append(dst_ip)` and `possible_dsts[atk].append(dst_ip)` append `dst_ip` without checking if it is already in the list. Repeated scans on the same host exponentially increase its probability of being chosen in subsequent steps.
  2. **Unbounded `while True` Loops (Lines 59–81):** If no valid destination IP exists for the chosen attack (or if `enable_atks` cannot find an uncompromised target), the `while True` loops have no maximum retry counter and can hang indefinitely.
  3. **Fragile Index Modulo Sampling (Line 143):** `self.data_source["normal"][-1].index % normal_flow_number_divisor == 0` filters by the DataFrame's index label rather than positional row index, leading to uneven sampling if the index is not contiguous.
* **Solution:**
  - Deduplicate before appending: `if dst_ip not in possible_srcs[atk]: possible_srcs[atk].append(dst_ip)`.
  - Add a retry cap (`max_attempts = 100`) to `generate_scenario` loops and use positional slicing `.iloc[::normal_flow_number_divisor]` for normal traffic subsampling.

---

## Part 4: Evaluation Metrics & Software Engineering Bugs

### 4.1 Critical Bug: Scenario Completeness Artificially Inflated by Ignoring Missed Steps
* **Context & Location:** Thesis Equations (2) & (6), Tables 11–14; [compute_metrics.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_generator/compute_metrics.py#L208-L259) (`get_scenario_soundness_completeness` and `get_step_soundness_completeness`).
* **Problem:** In `get_scenario_soundness_completeness` (lines 220–228):
  ```python
  matched_actual_steps = []
  for step in actual_steps:
      if step in matches.values():
          matched_actual_steps.append(step)

  actual_pairs = {(matched_actual_steps[i], matched_actual_steps[j])
                  for i in range(len(matched_actual_steps))
                  for j in range(i + 1, len(matched_actual_steps))}
  ```
  `actual_pairs` is constructed **exclusively from `matched_actual_steps`** rather than all `actual_steps`! As a result, any ground-truth attack steps missed by the reconstructor are removed from the denominator of `completeness = len(correct_pairs) / len(actual_pairs)`. If a scenario has 10 steps and the reconstructor only detects 2 of them in the right order, `completeness` evaluates to `1 / 1 = 1.0000` (100%). This directly explains why `Scen. Compl` and `Step Compl.` in Thesis Tables 11–14 are almost always `0.99–1.0000` even when `Scen. Rec.` is low!
  Furthermore, if two predicted steps match the same actual step, `matched_predicted_steps` contains duplicate references `[a, a]`, generating reflexive pairs `(a, a)` in `predicted_pairs` that can never appear in `actual_pairs`.
* **Solution:**
  - Construct `actual_pairs` over the full ground-truth `actual_steps` (or provide two distinct metrics: `conditional_ordering_completeness` over matched steps and `overall_scenario_completeness` over all ground-truth steps):
    ```python
    actual_pairs = {(actual_steps[i], actual_steps[j])
                    for i in range(len(actual_steps))
                    for j in range(i + 1, len(actual_steps))}
    ```
  - Enforce 1-to-1 matching in `_get_step_matches` by tracking `matched_actual_indices = set()` so multiple predicted steps cannot collapse onto the same ground-truth step instance.

### 4.2 Exploit `end_time` Truncation & Interflow Time Unit/Timezone Mismatch
* **Context & Location:** [scenario_reconstructor.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/scenario_reconstructor.py#L168-L196), `#L599-L618`, and [scenario_generator.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_generator/scenario_generator.py#L126-L132), `#L169-L176`.
* **Problem:**
  1. **Truncated `end_time` (Lines 607 & 616 of `scenario_reconstructor.py`):** In `update_exploits`, both clustered exploits and noise exploits pass `start_time` instead of `end_time` for the `end_time` parameter:
     ```python
     # Line 607 (clustered):
     datetime.fromtimestamp(max(group["start_time"]), timezone.utc)
     # Line 616 (noise):
     datetime.fromtimestamp(flow_exploit["start_time"], timezone.utc)
     ```
     This sets the duration of all single-flow exploits to `0` and truncates the duration of the final flow in multi-flow exploits.
  2. **Unit Mismatch (Seconds vs. Milliseconds):** `CAPTureScenarioGenerator` computes `mean_interflow_time` and `std_interflow_time` in **milliseconds** (`np.diff(...) / np.timedelta64(1, 'ms')`), whereas `StarNetworkAttackGraphBasedScenarioReconstructor.update_exploits` computes them in **seconds** (via `.timestamp()`).
  3. **Python `__eq__` vs. `__hash__` Contract Violation (Lines 168–196):** `Exploit.__eq__` uses `abs(a - b) < 0.0001` for floating-point attributes, while `Exploit.__hash__` hashes the exact float values. Equal objects have different hashes, breaking `set` and `dict` operations.
* **Solution:**
  - Fix lines 607 and 616 in `scenario_reconstructor.py` to use `max(group["end_time"])` and `flow_exploit["end_time"]`.
  - Standardize `mean_interflow_time` and `std_interflow_time` to milliseconds (or seconds) in both `scenario_generator.py` and `scenario_reconstructor.py`.
  - Exclude floating-point tolerances from `__hash__` (e.g., hash only `(self.attack_type, self.source_ip, self.destination_ip, self.size)` or round floats before hashing and comparing).

### 4.3 Additional Runtime & Software Engineering Bugs
* **External Destination IP Crash:** In [scenario_reconstructor.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/scenario_reconstructor.py#L506-L517), `set_postconditions` and `would_change_state` only look up `self.host_dict.get(flow_exploit.destination_ip)` and raise `ValueError` if the target is an external IP (stored in `self.seen_external_hosts_dict`).
  - *Solution:* Use `self._obtain_hosts(flow_exploit)[1]` to retrieve the destination host consistently across internal and external hosts.
* **Source Host Postconditions:** `AttackType` postconditions can only modify the destination host (`set_postconditions`), preventing modeling of attacks that modify the source host state.
  - *Solution:* Mirror `Preconditions` by introducing a `Postconditions(compromise_attributes, targets_source: bool)` class.
* **State Loss on Periodic Logging:** In [scenario_reconstructor.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/scenario_reconstructor.py#L544-L554) and `#L630`, `log_exploits()` and `log_states()` clear `self.flow_exploits_dict[group_id] = []`, `self.exploits_dict[group_id] = []`, and `self.state_sequence = []`. If logging thresholds (`length_when_log_exploits != -1`) are enabled during a run, `get_results()` loses previously logged alerts and steps.
  - *Solution:* Track a `last_logged_index` cursor per group rather than wiping the in-memory lists.
* **Empty Host Attribute Deserialization Crash:** In [scenario_reconstructor.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_reconstructor/scenario_reconstructor.py#L325-L327), `StringToNetworkStateConvertor.from_str` splits an empty attribute string `""` into `[""]` and calls `self.att_type("")`, raising `ValueError`.
  - *Solution:* Guard with `if att_set_str.strip():` before splitting.
* **Single-Class Confusion Matrix Crash:** In [compute_metrics.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_generator/compute_metrics.py#L108) and `#L147`, `confusion_matrix(y_true, y_pred).ravel()` crashes with `ValueError: not enough values to unpack` if all predictions and labels are `0` or `1`.
  - *Solution:* Pass `labels=[0, 1]` to `confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()`.
* **Windows CLI Runner Incompatibility & Typo:** In [run_scripts.py](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/run_scripts.py#L21) and `#L38-L39`, `TORELANCE = 2000` is misspelled and `os.system("python3 -m ...")` fails on Windows where the executable is `python`.
  - *Solution:* Use `subprocess.run([sys.executable, "-m", "scenario_reconstructor.reconstruct_cAPTure", ...], check=True)`.

---

## Summary Priority Matrix

| Priority | Category | Component / File | Problem Summary | Recommended Solution |
| :--- | :--- | :--- | :--- | :--- |
| **P0 (Critical)** | Algorithmic Core | `reconstruction_manager.py` | Misclassified low-suspicion alerts cannot change attack type during FN recovery, breaking scenarios. | Allow `_try_alternative_types` on `suspect_dict` entries and index suspects by `(src_ip, dst_ip)`. |
| **P0 (Critical)** | Clustering | `reconstruction_manager.py`, `scenario_reconstructor.py` | `StandardScaler` + `DBSCAN(eps=0.5)` never clusters 2 flows, crashes on 0 variance, and is scale-invariant. | Remove `StandardScaler`; run DBSCAN on raw timestamps with a physical time window `eps` (in seconds). |
| **P0 (Critical)** | Metrics | `compute_metrics.py` | `actual_pairs` only includes *matched* actual steps, inflating completeness to ~100%. | Build `actual_pairs` from all ground-truth `actual_steps` and enforce 1-to-1 step matching. |
| **P0 (Critical)** | Data Pipeline | `attack_normal_merging.ipynb` | Epoch ms divided by 500 and unclipped Gaussian noise creates negative packet/byte counts & trivial ML separation. | Subtract min timestamp before scaling; clip noisy features to $\ge 0$; preserve joint categorical rows. |
| **P1 (High)** | Algorithmic Core | `reconstruction_manager.py`, `scenario_reconstructor.py` | FN recovery lacks `happens-before` check (`fn.start_time <= anomaly.start_time`) and only supports 1-hop recovery. | Filter suspects by timestamp precedence; extend `compute_requirements` to bounded multi-hop BFS. |
| **P1 (High)** | ML & Uncertainty | `reconstruction_dataset_creation.ipynb`, `attack_mapper.py` | Uncalibrated probabilities across models, severe class imbalance in mappers, and test-set threshold snooping. | Calibrate models (`CalibratedClassifierCV`), apply Conformal Prediction for uncertainty/zero-days, and use class weights. |
| **P1 (High)** | Data Integrity | `scenario_reconstructor.py`, `scenario_generator.py` | `end_time` set to `start_time` in `update_exploits`; ms vs. s unit mismatch; `__eq__`/`__hash__` violation. | Use `end_time` in `update_exploits`; standardize on ms; fix `Exploit.__hash__`. |
| **P2 (Medium)** | Data Pipeline | `attack_normal_merging.ipynb`, `scenario_generator.py` | Missing `regex=False` leaks IPv6 in `src_ip`; duplicate IPs appended in generator; unsafe `hour - 2` timezone math. | Pass `regex=False`; deduplicate `possible_srcs`/`possible_dsts`; use `timedelta(hours=2)`. |
| **P2 (Medium)** | Engineering | `scenario_reconstructor.py`, `compute_metrics.py`, `run_scripts.py` | Crash on external destination IP, monoclass `confusion_matrix`, empty host deserialization, and `python3` on Windows. | Lookup external hosts in `set_postconditions`; pass `labels=[0, 1]`; use `sys.executable`. |
