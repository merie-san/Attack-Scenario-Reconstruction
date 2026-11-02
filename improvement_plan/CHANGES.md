# Major changes since last version

## Metrics calculation

The original metrics present several logical inconsistencies, bugs, and problems. Here we list each problem and how are they resolved.

### Important problems for alert aggregation metrics

Alert aggregation metrics are developed for the purpose of evaluating the correctness of step creation: when two alerts are inserted in the same attack step, we recover a correlation as an alert pair. Alert Correlation quality is then evaluated with the proportion of correctly recovered alert pairs in all actual alert pairs (completeness) or in all predicted alert pairs (soundness). The previous implementation presented two major problems:
- Attack steps containing a single alert are invisible to completeness and soundness metrics.
- When matching predicted alerts with actual alerts, duplicate predictions are matched to the same actual alert. Duplicates generate artificial self-pairs.