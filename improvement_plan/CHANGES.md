# Major changes since last version

## Metrics calculation

The original metrics present several logical inconsistencies, bugs, and problems. Here we list each problem and how are they resolved.

### Important problems for alert aggregation metrics

Alert aggregation metrics are developed for the purpose of evaluating the correctness of step creation: when two alerts are inserted in the same attack step, we recover a correlation as an alert pair. Alert Correlation quality is then evaluated with the proportion of correctly recovered alert pairs in all actual alert pairs (completeness) or in all predicted alert pairs (soundness). The previous implementation presented two major problems:
- Attack steps containing a single alert are invisible to completeness and soundness metrics.
- When matching predicted alerts with actual alerts, duplicate predictions are matched to the same actual alert. Duplicates generate artificial self-pairs.
- No metric measures how well alerts are recovered for each attack step, so duplicates are not penalized.

The fixes are:

- We add for each alert included in a step a self-pair, so even when we find attack steps with only one alert, soundness and completeness metrics would still be able to be computed. The self-pairs would represent the presence of an alert in an attack step.
- We modify the matching procedure so we have a list of already seen alerts, that could be used to avoid many-to-one matching. 
- To penalize the presence of duplicated alerts, we define the alert precision and recall metrics. Differently from the confusion matrix functions, the alert precision and recall metrics takes into account alert duplication. 

Step recall and precision metrics were designed to allow many-to-one matches of predicted steps to actual steps to limit penalization from fragmentation. The artificial distinction between the timing and no-timing variant compensates for the difficulty of an exact match, but is awkward: the no-timing variant is too lax while the timing one is too strict. Overall, the two metrics fail to correctly evaluate repeated attack steps since only the first of the bunch will be considered.

The fixes are:

- Implement matching through overlap: find the first actual step from the predicted step that overlaps. In this way fragmentation is penalized in precision, and repeated steps in the actual step influence the final results obtained.

