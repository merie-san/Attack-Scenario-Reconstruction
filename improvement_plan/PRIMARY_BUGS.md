# Primary Bugs and Regression Coverage

27 October 2026. Base production revision `cb12d9bef1be775540b12cac667bf4f439624933`.

## Scope and current status

This inventory contains **29 bug and requirement groups**. Every group has an active failing regression. The three regression modules contain 62 tests, including eight passing controls. All 25 test classes across the whole suite now use `RegressionCase`. The full run reports **131 tests, 73 passes, 52 assertion failures, six runtime errors, and zero skips**.

BUG-01 through BUG-03 are active again because the selected evaluation requirement now includes full actual and predicted pair support. Their previous withdrawal applied to the alternative conditional definition. No production metric formula has been changed.

P0 means a defect undermines the validity of evaluation or training data. P1 means it materially corrupts reconstruction, evidence, or a supported execution path. P2 means it affects narrower input or execution cases. Fixes are required work; no production fixes are included in this change.

The tests require full actual/predicted pair denominators, one-to-one occurrence matching for precision/recall, common duration units, timezone-aware ingestion, and completion-before-trigger recovery under the conservative causal policy. Association provenance must still represent fragmentation rather than silently discarding unmatched predictions.

## Selected metric contract

All eligible actual pairs contribute to completeness, including pairs involving missed steps or alerts. All eligible predicted pairs contribute to soundness, including pairs involving unmatched predictions. Only correctly corresponding pairs receive numerator credit. Missing actual pairs therefore reduce completeness; spurious predicted pairs reduce soundness. Matched-only association scores would need a separate conditional metric name.

## Evaluation and identity

| ID | Priority | Bug and why it must be fixed | Required correction |
| --- | --- | --- | --- |
| BUG-01 | P0 | Scenario completeness currently excludes unmatched actual steps, contrary to the selected full-coverage contract. | Count every eligible actual step pair, including pairs involving missed steps. |
| BUG-02 | P0 | Aggregation completeness excludes pairs involving missed actual alerts. | Form the full actual alert-pair denominator before matching. |
| BUG-03 | P0 | Soundness excludes pairs involving unmatched predicted steps or alerts. | Form the full predicted pair denominator and credit only correctly corresponding pairs. |
| BUG-04 | P0 | Precision and recall reuse matched instances, with or without timing. One prediction can cover two repeated actual steps, or duplicate predictions can both earn credit. | Use shared one-to-one matching with maximum cardinality and deterministic temporal tie-breaking. |
| BUG-05 | P1 | Flow equality and metric keys omit destination port, although hashing includes it. Distinct flows can collapse or behave inconsistently in dictionaries and evaluation. | Include the complete flow identity or a stable event ID consistently in equality, keys, and hashing. |
| BUG-06 | P1 | Exploit equality uses non-transitive tolerances, can be asymmetric with sentinel statistics, and disagrees with hashing. Requirement equality deduplicates source IPs while hashing counts duplicates. Sets and dictionaries can lose equivalent objects. | Separate exact identity from approximate matching; use consistent immutable values and set semantics for requirement sources. |

Production locations: `scenario_generator/compute_metrics.py`; identity classes in `scenario_reconstructor/scenario_reconstructor.py`.

## State time and grouping

| ID | Priority | Bug and why it must be fixed | Required correction |
| --- | --- | --- | --- |
| BUG-07 | P0 | Historical network states retain references to live attribute sets. Later compromise updates rewrite the apparent past, invalidating explanations and replay. | Copy or freeze attributes when taking snapshots. |
| BUG-08 | P1 | Reconstruction uses flow start times for exploit end times in both clusters and singletons. Durations are truncated or become zero, corrupting timing comparisons. | Aggregate minimum start and maximum actual end. |
| BUG-09 | P1 | The generator's actual step ends at the final flow's start. Its exported ground truth omits the last flow's duration. | Derive actual step boundaries from all member flow intervals. |
| BUG-10 | P1 | Generated inter-flow means and standard deviations use milliseconds; reconstruction uses seconds. Identical evidence produces values differing by 1,000. | Use one documented duration unit in both paths and serialization. |
| BUG-11 | P1 | Event conversion leaves naive timestamps unchanged while reconstructed exploits use UTC-aware timestamps. Comparisons can raise errors or interpret local time inconsistently. | Define source timezone at ingestion and normalize to aware UTC before reconstruction. The regression fixture represents naive UTC input. |
| BUG-12 | P1 | Temporal grouping standardizes each batch independently. Two distinct flows one millisecond apart become noise/singletons, so grouping depends on the history's scale. | Share a physical-time interval grouping rule with explicit gap and maximum-span parameters. |

Production locations: `NetworkState.from_dict_of_host` and `update_exploits` in `scenario_reconstructor/scenario_reconstructor.py`; `scenario_generator/scenario_generator.py`; `event_convertor/flow_event_generator.py`; `_find_most_recent_flow_cluster` in `scenario_reconstructor/reconstruction_manager.py`.

## Recovery

| ID | Priority | Bug and why it must be fixed | Required correction |
| --- | --- | --- | --- |
| BUG-13 | P1 | Recovery only finds suspects under their primary attack type. A correct alternative type cannot supply a missing prerequisite, breaking the remainder of a scenario. | Preserve scores and original evidence; search viable suspect types and commit the selected interpretation only after validation. |
| BUG-14 | P1 | Recovery does not enforce temporal availability. A future event, or a flow that has not finished, can enable an earlier action. | Reject or explicitly handle out-of-order events; require supporting evidence to be effective at the dependent event's time. The overlap test uses completion-before-start semantics. |
| BUG-15 | P1 | Recovering one cluster empties its entire suspect group. Unrelated evidence needed later is silently discarded. | Remove only consumed evidence IDs, preserving other clusters. |
| BUG-16 | P1 | Both primary and alternative trigger paths assume recovery succeeded and commit without rechecking prerequisites. An unsuccessful recovery can still mark the target compromised. | Recheck all requirements and the trigger before committing; make the complete proposal transactional. Tests inject a recovery no-op to exercise this failure path. |

Production location: `scenario_reconstructor/reconstruction_manager.py`, especially `accept`, `_try_alternative_types`, and `_recover_fns`.

## Persistence and runtime

| ID | Priority | Bug and why it must be fixed | Required correction |
| --- | --- | --- | --- |
| BUG-17 | P1 | Postcondition methods only look in the internal host dictionary, although precondition checks register external destinations elsewhere. A supported flow then crashes. | Resolve internal and registered external hosts consistently. |
| BUG-18 | P1 | Logging removes accepted alerts, steps, and state history from returned results. Repeated state logging also appends the same correlations again. Logging configuration changes the evaluated outcome. | Separate persistent results from log cursors and active buffers; log each record once and preserve retrieval across flushes. |
| BUG-19 | P2 | Deserializing a host with an empty attribute set converts the empty string to an enum, raising ValueError. Valid state snapshots cannot round-trip. | Treat an empty attribute field as an empty set. |
| BUG-20 | P1 | Confusion matrices without fixed labels collapse to one cell for homogeneous labels and predictions. Unpacking then crashes. | Request fixed labels `[0, 1]` in both detection and reconstruction metrics. |
| BUG-21 | P1 | Manager acceptance uses strict `>` while detection metrics use `>=`, and inverted suspicion/anomaly thresholds are accepted. Boundary scores and invalid configurations produce inconsistent behavior. | Use one boundary convention and reject invalid threshold ordering. |

Production locations: `scenario_reconstructor/scenario_reconstructor.py`, `scenario_reconstructor/reconstruction_manager.py`, and `scenario_generator/compute_metrics.py`.

## Preparation generation and execution

| ID | Priority | Bug and why it must be fixed | Required correction |
| --- | --- | --- | --- |
| BUG-22 | P0 | Independent Gaussian perturbation creates negative counters and breaks directional byte totals. A model can learn impossible synthetic artifacts. | Validate bounds, integer counts, and dependent totals using an explicit physical feature schema; regenerate dependent values together. |
| BUG-23 | P0 | Assigning a new categorical DataFrame to filtered indexes creates missing values. Independently resampling categorical columns also invents incompatible tuples. | Preserve row alignment and sample related categorical fields together. |
| BUG-24 | P1 | The source IPv4 filter uses a regex dot, which matches any character. Unresolved IPv6 sources leak into the intended IPv4 dataset. | Parse addresses or apply an explicit literal/IPv4 predicate to both endpoints, with a declared unresolved-address policy. |
| BUG-25 | P1 | Compression retains the original timestamp origin, changes bidirectional timestamps without updating directional times, and manually subtracts two from an hour field. Output depends on arbitrary origin, contradicts its own intervals, and crashes near midnight. | Normalize relative offsets consistently across time fields; recompute durations; use real timezone conversion or valid timedelta arithmetic as appropriate. |
| BUG-26 | P0 | Threshold tuning reads final-test features and labels. Training feature and class selection also depend on test columns and label membership. The threshold helper separately crashes at a recall target of zero. Evaluation independence and edge-case execution are compromised. | Freeze a training-derived schema/class policy; use validation/calibration data for tuning; handle precision-recall terminal entries and invalid targets explicitly. |
| BUG-27 | P1 | Impossible generator choices can retry forever. Repeated enablement duplicates host entries, changing sampling probabilities. Evaluation can hang or become unintentionally biased. | Select feasible choices, deduplicate pools, and bound retries and overall scenario length. |
| BUG-28 | P2 | Normal-flow subsampling uses index-label modulo rather than positions. Gapped indexes can retain all rows when half were requested. | Use positional sampling with a validated positive divisor. |
| BUG-29 | P2 | The evaluation runner dispatches a shell string using hardcoded `python3`. Windows or a different environment can fail or run the wrong interpreter. | Use a checked subprocess argument list beginning with `sys.executable`; make data/log paths explicit. |

Notebook locations: `attack_normal_merging.ipynb`, particularly `generate_dataframe`, IPv4 filtering, and capture time conversion; `process_attack_train.ipynb` and its corresponding test preprocessing; `reconstruction_dataset_creation.ipynb`, particularly `compute_thresh` and train/test intersections. Runtime locations: `scenario_generator/scenario_generator.py` and `run_scripts.py`.

## Test files and execution

Tests were added to the actual project at `C:\Users\DavideZhiAngZhang\PycharmProjects\Attack-Scenario-Reconstruction`:

- `tests/test_regression_metrics.py` covers full pair denominators, occurrence reuse, unknown-step timing/host compatibility, splitting/merging, and single-class confusion matrices.
- `tests/test_regression_reconstruction.py` covers identity, snapshots, end times, grouping, recovery, logging, host resolution, and thresholds.
- `tests/test_regression_data_pipeline.py` covers ground truth, time units, ingestion, augmentation, address filtering, test-set isolation, generator termination/sampling, and interpreter selection.
- `tests/regression_support.py` supplies the shared base lifecycle, `make_` factories, temporary log paths, seeded/restored randomness, and selective notebook loaders.
- `tests/__init__.py` makes imports and module-based unittest execution consistent.

All seven legacy test modules now use the shared base and call it from their setup methods. `TestCalculator` now expects full denominators for scenario and aggregation scores, and its combined precision/recall test has four independent methods. `TestStarNetworkAttackGraphBasedScenarioReconstructor.test_update_exploits` retains corrected end-time and duration-unit expectations. Requirement hashing is checked by the equality/dictionary contract rather than by reproducing its implementation.

Subclasses with custom setup must initialize the base. Use `self.log_path(name)` for any test-created log and the `make_reconstructor`, `make_manager`, `make_flow`, `make_event`, `make_step`, `make_scenario_frame`, and `make_generator` factories for reusable fixtures. Factory names are distinct from subject attributes.

From the project root, run the complete suite:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Run only the new modules:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_regression_*.py' -v
```

These commands currently exit unsuccessfully because the production defects remain. They do not suppress failures using `expectedFailure` or skips. The generator hang reproduction runs in a child process with a ten-second timeout; its runner test launches no real evaluation commands. Random state is seeded and restored, and all logging tests use temporary paths. Normal and reverse execution order have identical failure/error identities; campaign hosts and production-file hashes remain unchanged.

Notebook tests compile only selected real functions or assignments, with small controlled inputs. When preparation moves into importable modules, move these checks to those public helpers rather than retaining notebook-structure assertions. Test-set schema policy can instead reject an incompatible test input, but must not silently redefine the training features or classes.

## Remaining design work and validation limits

Multi-hop recovery, conjunctive requirements across two hosts, probabilistic tracking, source-targeted postconditions, and a learned sequence/graph fallback are extensions rather than newly discovered runtime defects. Unknown attacks currently grant broad postconditions by explicit configuration; replacing that policy requires a separate recall/false-positive comparison.

Calibration quality, class-weighting benefits, feature-filter effects, MAC-mapping collision policy, and real campaign generalization still require restored datasets and experimental validation. The tests do not claim statistical performance or validate thesis tables. The constant-timestamp control passes, so the original proposal's StandardScaler zero-variance crash claim is excluded from this bug inventory.

The appendix below maps every bug group to the exact regression methods observed in the saved test run.

## Regression method mapping

| Bug | Regression method | Current result |
| --- | --- | --- |
| BUG-01 | [test_B01_scenario_completeness_counts_all_actual_pairs](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_metrics.py:11) | failed |
| BUG-02 | [test_B02_aggregation_completeness_counts_missing_alerts](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_metrics.py:19) | failed |
| BUG-03 | [test_B03_aggregation_soundness_counts_unmatched_predictions](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_metrics.py:37) | failed |
| BUG-03 | [test_B03_scenario_soundness_counts_unmatched_predictions](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_metrics.py:29) | failed |
| BUG-04 | [test_B04_precision_without_timing_matches_each_actual_step_once](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_metrics.py:74) | failed |
| BUG-04 | [test_B04_recall_without_timing_matches_each_prediction_once](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_metrics.py:67) | failed |
| BUG-04 | [test_B04_timed_precision_does_not_reuse_actual_step](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_metrics.py:88) | failed |
| BUG-04 | [test_B04_timed_recall_does_not_reuse_prediction](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_metrics.py:81) | failed |
| BUG-05 | [test_B05_destination_port_distinguishes_flow_identity](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:14) | failed |
| BUG-05 | [test_B05_destination_port_distinguishes_metric_identity](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:18) | failed |
| BUG-06 | [test_B06_equal_exploits_are_interchangeable_dictionary_keys](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:23) | failed |
| BUG-06 | [test_B06_exploit_equality_is_symmetric_with_unknown_statistics](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:32) | failed |
| BUG-06 | [test_B06_exploit_equality_is_transitive](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:38) | failed |
| BUG-06 | [test_B06_requirement_source_order_and_duplicates_have_consistent_identity](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:43) | failed |
| BUG-07 | [test_B07_later_host_changes_do_not_rewrite_historical_state](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:49) | failed |
| BUG-08 | [test_B08_cluster_end_is_maximum_flow_end](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:70) | failed |
| BUG-08 | [test_B08_single_flow_exploit_preserves_actual_end](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:63) | failed |
| BUG-09 | [test_B09_generated_step_ends_at_last_flow_end](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:25) | failed |
| BUG-10 | [test_B10_generator_and_reconstructor_interflow_units_agree](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:32) | failed |
| BUG-10 | [test_B10_interflow_standard_deviation_uses_the_same_units](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:45) | failed |
| BUG-11 | [test_B11_naive_input_is_normalized_before_utc_comparison](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:63) | failed |
| BUG-12 | [test_B12_nearby_flows_form_one_step_without_outlier_history](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:81) | failed |
| BUG-12 | [test_B12_recovery_groups_nearby_flows_together](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:90) | failed |
| BUG-13 | [test_B13_recover_suspect_using_its_alternative_attack_type](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:105) | failed |
| BUG-14 | [test_B14_future_evidence_is_not_recovered_for_a_past_trigger](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:113) | failed |
| BUG-14 | [test_B14_unfinished_support_cannot_enable_an_earlier_action](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:120) | failed |
| BUG-15 | [test_B15_successful_recovery_retains_unused_suspect_clusters](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:127) | failed |
| BUG-16 | [test_B16_failed_recovery_cannot_commit_trigger](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:137) | failed |
| BUG-16 | [test_B16_failed_recovery_for_alternative_trigger_cannot_commit](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:146) | failed |
| BUG-17 | [test_B17_registered_external_destination_can_receive_postconditions](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:171) | error |
| BUG-18 | [test_B18_logging_preserves_state_history](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:186) | failed |
| BUG-18 | [test_B18_periodic_logging_preserves_final_results](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:179) | failed |
| BUG-18 | [test_B18_repeated_state_logging_does_not_duplicate_correlations](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:192) | failed |
| BUG-19 | [test_B19_empty_host_attributes_round_trip](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:56) | error |
| BUG-20 | [test_B20_detection_confusion_matrix_accepts_single_class](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_metrics.py:94) | error |
| BUG-20 | [test_B20_reconstruction_confusion_matrix_accepts_single_class](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_metrics.py:101) | error |
| BUG-21 | [test_B21_anomaly_threshold_boundary_matches_detection_metrics](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:158) | failed |
| BUG-21 | [test_B21_suspect_threshold_must_be_below_anomaly_threshold](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_reconstruction.py:165) | failed |
| BUG-22 | [test_B22_directional_byte_totals_stay_consistent](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:167) | failed |
| BUG-22 | [test_B22_gaussian_augmentation_preserves_nonnegative_counters](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:162) | failed |
| BUG-23 | [test_B23_augmentation_preserves_joint_categorical_relationships](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:183) | failed |
| BUG-23 | [test_B23_filtered_indexes_do_not_create_missing_categories](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:176) | failed |
| BUG-24 | [test_B24_ipv4_filter_rejects_ipv6_source](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:189) | failed |
| BUG-25 | [test_B25_capture_time_conversion_handles_midnight_rollover](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:229) | error |
| BUG-25 | [test_B25_compression_is_invariant_to_timestamp_origin](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:204) | failed |
| BUG-25 | [test_B25_directional_times_remain_inside_shifted_flow_interval](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:218) | failed |
| BUG-26 | [test_B26_test_label_absence_does_not_remove_training_classes](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:255) | failed |
| BUG-26 | [test_B26_test_schema_does_not_select_training_features](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:262) | failed |
| BUG-26 | [test_B26_threshold_selection_does_not_inspect_final_test_features](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:269) | failed |
| BUG-26 | [test_B26_zero_recall_target_does_not_index_past_thresholds](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:284) | error |
| BUG-27 | [test_B27_impossible_destination_terminates_instead_of_looping](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:73) | failed |
| BUG-27 | [test_B27_repeated_enabling_does_not_duplicate_sampling_weight](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:103) | failed |
| BUG-28 | [test_B28_normal_subsampling_uses_positions_not_index_labels](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:129) | failed |
| BUG-29 | [test_B29_runner_uses_current_python_interpreter](C:/Users/DavideZhiAngZhang/PycharmProjects/Attack-Scenario-Reconstruction/tests/test_regression_data_pipeline.py:296) | failed |

All eight controls pass: unknown-step compatibility, split/merge associations, perfect occurrence scores, and identical-timestamp clustering.
