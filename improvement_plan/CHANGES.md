# Major changes since last version

## New Evaluation Suite

The new evaluation suite consists in four orthogonal groups of metrics, each responsible for different stages of the reconstruction pipeline: 

- **Flow/Alert Detection**: Confusion Matrices, Alert Precision and Recall.

- **Alert-to-Step Aggregation**: Step Soundness and Completeness on matched alerts.

- **Attack Step Identification**: Step Precision and Recall with one-to-one interval overlap.

- **Scenario Causal Reconstruction**: Temporal AND/OR Graph Soundness, Completeness and Goal Detection.

### Flow/Alert Detection

This group evaluates the initial stages of the pipeline: identifying malicious network flows from raw traffic and converting them into alert representations (`FlowExploit`) before any step aggregation occurs. It combines flow-level dataset metrics with object-level alert metrics:

1. **Intrusion Detection Confusion Matrix (`get_detection_confusion_matrix`)**
   - **Purpose**: Evaluates the baseline anomaly detector's ability to discriminate malicious traffic from benign background flows prior to scenario reconstruction.
   - **How it works**: Computes True Negatives (TN), False Positives (FP), False Negatives (FN), and True Positives (TP) across the entire traffic dataset (`scenario_df`) by applying a decision threshold (`anomaly_score > alert_threshold`) against binary ground-truth labels (`label != "normal"`).

2. **Reconstruction Confusion Matrix (`get_reconstruction_confusion_matrix`)**
   - **Purpose**: Evaluates flow-level filtering after the reconstruction pipeline processes and filters detected flows into predicted alerts.
   - **How it works**: Assesses whether each flow in the dataset (`scenario_df`) was retained within the set of predicted alert flows (matched by 5-tuple and temporal interval). This quantifies how effectively the reconstruction logic filters out false alarm flows while retaining true attack flows at the dataset level.

3. **Alert Precision (`get_alert_precision`)**
   - **Purpose**: Evaluates the purity and correctness of generated alert objects.
   - **How it works**: Measures the proportion of predicted alerts that correspond to actual ground-truth alerts via strict **1-to-1 matching**.
   $$\text{Alert Precision}=\frac{|\text{Matches}|}{|\text{Predicted Alerts}|}$$
   - **What it captures**: Unlike the reconstruction confusion matrix (which operates on sets of flow tuples), Alert Precision strictly penalizes:
     - **Duplicate predictions**: If multiple alerts are emitted for the same underlying network flow, only one matches; excess duplicates count as false positives in the denominator.
     - **Incorrect attack types**: Alerts must match the semantic `attack_type` of the ground truth (or conform to undetermined/unknown rules). Misclassified flows fail matching.

4. **Alert Recall (`get_alert_recall`)**
   - **Purpose**: Evaluates the coverage of actual attack alerts by the reconstruction system.
   - **How it works**: Measures the proportion of actual ground-truth alerts successfully recovered through 1-to-1 matching. 
   $$\text{Alert Recall}=\frac{|\text{Matches}|}{|\text{Actual Alerts}|}$$
   - **What it captures**: Measures false negatives at the alert level, ensuring each actual attack occurrence is accounted for without allowing a single predicted alert to satisfy multiple ground-truth events.

---

### Alert-to-Step Aggregation

This group evaluates how effectively individual alerts (`FlowExploit`) are clustered into macro attack steps (`Exploit`). When alerts belong to the same step, they form correlation pairs $(a_i, a_j)$.

- **Self-Pairs for Singleton Steps**: In earlier implementations, alert pairing used combinations of distinct alerts, which completely ignored attack steps containing only a single alert and led to division-by-zero errors when all steps were singletons. The new implementation generates pairs using `combinations_with_replacement`, producing a self-pair $(a_i, a_i)$ for every alert in a step. This guarantees that singleton steps are represented as the presence of an alert in a step.
- **Orthogonal Evaluation on Matched Alerts**: To decouple aggregation errors from alert detection errors (such as false alarms, duplicate predictions, or misclassifications), correlation pairs are built strictly from the subset of alerts that successfully matched 1-to-1 in the alert detection phase.

1. **Step Soundness (`get_step_soundness_completeness` -> soundness)**
   - **Purpose**: Evaluates the purity/precision of the alert clustering into steps.
   - **How it works**: Computes the proportion of predicted alert correlation pairs that are valid according to actual step groupings:
     $$\text{Step Soundness} = \frac{|\text{Predicted Pairs} \cap \text{Actual Pairs}|}{|\text{Predicted Pairs}|}$$
   - **What it captures**: Penalizes **over-merging** (grouping unrelated alerts from different actual steps into the same predicted step). Over-merging generates spurious cross-alert pairs that dilute soundness.

2. **Step Completeness (`get_step_soundness_completeness` -> completeness)**
   - **Purpose**: Evaluates the recall/coverage of alert clustering into steps.
   - **How it works**: Computes the proportion of actual alert correlation pairs successfully recovered by the predicted steps:
     $$\text{Step Completeness} = \frac{|\text{Predicted Pairs} \cap \text{Actual Pairs}|}{|\text{Actual Pairs}|}$$
   - **What it captures**: Penalizes **fragmentation / over-splitting** (dividing alerts that belong to a single attack step into multiple disjoint steps). Splitting a step destroys the correlation pairs connecting those alerts, lowering completeness.

---

### Attack Step Identification

This group evaluates the identification of attack steps (`Exploit`) as discrete macro-events along the attack timeline, independently of their internal alert counts or causal relationships.

- **1-to-1 Interval Overlap Matching**: Previously, step evaluation relied on an awkward distinction between "timed" (requiring start/end times within a rigid millisecond tolerance window) and "no-timing" (ignoring timestamps entirely) metrics. The "no-timing" metric was too lax and could not handle repeated steps, while the fixed tolerance window was too brittle for long or delayed steps. The new evaluation uses strict **1-to-1 matching based on temporal interval overlap** (`approx_match`): two steps match if they share the same context (source IP, destination IP, attack type) and their active time intervals overlap ($\max(s_1, s_2) \le \min(e_1, e_2)$).

1. **Step Precision (`get_scenario_step_precision`)**
   - **Purpose**: Evaluates the accuracy and validity of the reconstructed attack steps.
   - **How it works**: Measures the proportion of predicted attack steps that successfully match actual attack steps 1-to-1:
     $$\text{Step Precision} = \frac{|\text{Matched Steps}|}{|\text{Predicted Steps}|}$$
   - **What it captures**: Penalizes hallucinated steps (false positives) and **step fragmentation**. If an actual attack step is predicted as multiple fragmented steps, only one can match 1-to-1; the remaining fragments become unmatched predictions that increase the denominator and lower precision.

2. **Step Recall (`get_scenario_step_recall`)**
   - **Purpose**: Evaluates the coverage of actual attack steps.
   - **How it works**: Measures the proportion of actual attack steps successfully recovered via 1-to-1 matching:
     $$\text{Step Recall} = \frac{|\text{Matched Steps}|}{|\text{Actual Steps}|}$$
   - **What it captures**: Penalizes missed attack steps (false negatives) and unrecovered repetitions of repeated attacks.

---

### Scenario Causal Reconstruction

This group evaluates the highest level of reconstruction: causal dependencies between attack steps and the progression toward attack goals, represented as a Temporal AND/OR Directed Acyclic Graph (`AttackScenarioDAG`).

- **Temporal AND/OR Graph Semantics**:
  - Each attack step acts as an **AND-node** that requires all of its precondition clauses (e.g., source host compromise, target vulnerability) to be satisfied.
  - Each precondition clause acts as an **OR-node** that can be satisfied by *any* valid prior attack step providing the necessary compromise attributes.
  - Repeated steps within the same host/attack group are linked sequentially as chains ($S_i \to S_{i+1}$).

1. **Scenario Soundness (`get_scenario_soundness_completeness` -> soundness)**
   - **Purpose**: Evaluates the precision of reconstructed causal dependencies between attack steps.
   - **How it works**: Measures the proportion of predicted causal edges that represent legitimate causal relationships between matched steps in the ground-truth DAG:
     $$\text{Scenario Soundness} = \frac{|\text{Predicted Causal Pairs} \cap \text{Actual Causal Pairs}|}{|\text{Predicted Causal Pairs}|}$$
   - **What it captures**: Penalizes spurious, backwards, or hallucinated causal edges that do not reflect genuine prerequisite-consequence relationships.

2. **Scenario Completeness (`get_scenario_soundness_completeness` -> completeness)**
   - **Purpose**: Evaluates how thoroughly the necessary causal prerequisites are satisfied in the reconstructed scenario under AND/OR logic.
   - **How it works**: For each matched step and each required precondition clause in the actual scenario, it verifies whether the reconstructed graph provides a valid causal parent link. If intermediate steps were missed, the evaluator traverses ancestor paths to allow valid transitive dependencies:
     $$\text{Scenario Completeness} = \frac{\text{Satisfied Precondition Clauses}}{\text{Required Precondition Clauses}}$$
   - **What it captures**: Accurately reflects multi-stage attack progression under OR-semantics without penalizing valid alternative paths or cascading penalties when intermediate steps are bypassed.

3. **Scenario Goal Detection (`is_scenario_detected`)**
   - **Purpose**: Provides a macro campaign-level assessment of whether the attacker's ultimate objective was identified and causally reconstructed.
   - **How it works**: Given an `AttackGoal` (e.g., target IP and final exploit type):
     - Confirms that the target goal step is present and matched in the reconstructed scenario.
     - Traces the root-to-goal causal path backwards (`get_goal_clause_recovery`) and checks whether the proportion of recovered causal clauses meets or exceeds the edge recovery threshold (default 50%).
   - **What it captures**: Distinguishes between scenarios where the attack campaign objective was completely uncovered versus scenarios where isolated steps were detected without identifying the full attack progression.
