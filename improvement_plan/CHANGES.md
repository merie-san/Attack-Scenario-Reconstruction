# Major changes since last version

## New Evaluation Suite

The new evaluation suite consists of four orthogonal groups of metrics, each responsible for a distinct stage of the reconstruction pipeline:

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
Scenario causal reconstruction evaluates whether the causal dependencies between attack steps and the progression toward the attacker's ultimate goal were correctly recovered. Previous approaches had key limitations:
1. **Flawed Completeness Calculation**: Previous implementations computed causal completeness only over the subset of *already matched* steps rather than against all actual causal relationships, artificially inflating completeness scores (often reporting ~100% even when critical prerequisite steps were missing).
2. **Rigid Single-Hop Edge Requirements**: Requiring exact 1-hop causal edges between consecutive steps overly penalizes the scenario if a single intermediate step was missed. In multi-step attacks, if step $A$ enables step $B$, and $B$ enables step $C$, but step $B$ was not detected, a reconstructed causal link $A \to C$ preserves the true prerequisite chain. A realistic evaluator must support transitive prerequisite traversal under AND/OR logic.
3. **Lack of Campaign Goal Reachability Evaluation**: Prior metrics evaluated individual edges in isolation, failing to assess whether the complete attack campaign actually succeeded in reaching its high-level objective (e.g., exfiltrating database records or obtaining root privileges).

#### Reasoning behind the Changes
1. **Formal Temporal AND/OR Attack Graph (`AttackScenarioDAG`)**:
   - Each attack step acts as an **AND-node** requiring all of its precondition clauses (e.g., source host compromise, target vulnerability) to be satisfied.
   - Each precondition clause acts as an **OR-node** that can be satisfied by *any* valid prior attack step providing the necessary compromise attributes.
   - Repeated attacks within the same host/attack group are linked sequentially as chains ($S_i \to S_{i+1}$).
2. **Causal Completeness with Ancestor Bypass**: To avoid compounding penalties when intermediate steps are missed, clause completeness traverses causal ancestor paths in the ground truth to verify whether an earlier matched ancestor validly satisfies the prerequisite.
3. **Dedicated Goal Reachability Metric (`is_scenario_detected`)**: Introduces an explicit campaign-level milestone metric that evaluates both goal identification and the recovery of the root-to-goal causal path.

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
   - **How it works**: Given an [`AttackGoal`](file:///c:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/scenario_generator/compute_metrics.py#L14-L43) (target IP and final exploit type):
     - Verifies that the goal step is present and matched in the reconstructed scenario.
     - Traces the root-to-goal causal path backwards (`get_goal_clause_recovery`) and checks whether the proportion of recovered causal clauses meets or exceeds the edge recovery threshold (default 50%).
   - **What it captures**: Distinguishes between scenarios where isolated attack steps were detected versus scenarios where the full multi-step attack campaign leading to the objective was successfully uncovered.
