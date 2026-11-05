"""Value identity, hash lookup, and explicit evaluation matching contracts."""

from datetime import timedelta, timezone

from metrics import MetricsCalculator
from scenario_reconstructor.dag import AttackScenarioDAG
from scenario_reconstructor.models import RecoveryRequirement
from tests.support import EPOCH, ProjectTestCase, SOURCE, TARGET


class TestAlertIdentity(ProjectTestCase):
    def test_equal_alerts_are_interchangeable_keys_despite_annotation_changes(self):
        first = self.make_flow()
        annotated = self.make_flow(anomaly_score=0.9, attack_types_alternatives=[self.wrong])
        self.assertEqual(first, annotated)
        self.assertEqual(hash(first), hash(annotated))
        self.assertEqual({first: 'alert'}[annotated], 'alert')
        self.assertEqual(len({first, annotated}), 1)
        first.anomaly_score = 0.8
        first.attack_type_alternatives.append(self.finish)
        self.assertIn(first, {annotated})

    def test_different_flow_fields_or_classifications_remain_distinct(self):
        first = self.make_flow()
        differences = [
            {'attack': self.wrong}, {'source_ip': 'other-source'}, {'source_port': '1001'},
            {'destination_ip': 'other-destination'}, {'destination_port': '443'}, {'protocol': '17'},
            {'start_time': EPOCH + timedelta(microseconds=1)},
            {'end_time': EPOCH + timedelta(seconds=2)},
        ]
        for fields in differences:
            with self.subTest(fields=fields):
                other = self.make_flow(**fields)
                self.assertNotEqual(first, other)
                self.assertNotEqual(other, first)
                self.assertEqual(len({first, other}), 2)

    def test_metrics_reject_wrong_destination_port_even_for_unknown_predictions(self):
        actual = [self.make_flow()]
        for attack in (self.discover, self.unknown):
            with self.subTest(attack=attack.identifier):
                predicted = [self.make_flow(attack=attack, destination_port='443')]
                self.assertEqual(MetricsCalculator.get_alert_precision(predicted, actual, self.unknown), 0)
                self.assertEqual(MetricsCalculator.get_alert_recall(predicted, actual, self.unknown), 0)

    def test_unknown_type_matching_is_explicit_and_directional(self):
        actual, unknown = self.make_flow(), self.make_flow(attack=self.unknown)
        self.assertNotEqual(actual, unknown)
        self.assertEqual(actual.metric_key, unknown.metric_key)
        self.assertTrue(actual.unk_eq(unknown, self.unknown))
        self.assertFalse(unknown.unk_eq(actual, self.unknown))
        self.assertEqual(MetricsCalculator.get_alert_recall([unknown], [actual], self.unknown), 1)
        self.assertEqual(MetricsCalculator.get_alert_recall([unknown], [actual]), 0)

    def test_metric_key_reflects_edits_before_use_as_a_dictionary_key(self):
        flow = self.make_flow()
        previous = flow.metric_key
        flow.destination_port = '443'
        self.assertNotEqual(flow.metric_key, previous)
        same = self.make_flow(destination_port='443')
        self.assertEqual(flow, same)
        self.assertEqual({flow: 'edited alert'}[same], 'edited alert')

    def test_equal_instants_have_equal_identity_and_match_across_timezones(self):
        actual = self.make_flow()
        offset = timezone(timedelta(hours=2))
        variants = [
            self.make_flow(start_time=actual.start_time.astimezone(offset),
                           end_time=actual.end_time.astimezone(offset)),
            self.make_flow(start_time=actual.start_time.replace(tzinfo=None),
                           end_time=actual.end_time.replace(tzinfo=None)),
        ]
        for predicted in variants:
            with self.subTest(timestamp=predicted.start_time):
                self.assertEqual(predicted, actual)
                self.assertEqual(predicted.metric_key, actual.metric_key)
                self.assertEqual({actual: 'same instant'}[predicted], 'same instant')
                self.assertEqual(MetricsCalculator.get_alert_recall([predicted], [actual]), 1)


class TestStepIdentity(ProjectTestCase):
    def test_equal_steps_and_unknown_statistics_are_interchangeable_keys(self):
        for mean, std in [(-1, -1), (1.0, 2.0), (-1, 2.0), (1.0, -1)]:
            with self.subTest(mean=mean, std=std):
                first = self.make_step(mean=mean, std=std)
                other = self.make_step(mean=mean, std=std)
                self.assertEqual(first, other)
                self.assertEqual(hash(first), hash(other))
                self.assertEqual({first: 'step'}[other], 'step')
                self.assertEqual(len({first, other}), 1)

    def test_statistics_are_exact_and_unknown_values_are_not_wildcards(self):
        measured = self.make_step(mean=1.0, std=2.0)
        variants = [self.make_step(mean=1.00005, std=2.0),
                    self.make_step(mean=1.0, std=2.00005), self.make_step()]
        for other in variants:
            with self.subTest(mean=other.mean_interflow_time, std=other.std_interflow_time):
                self.assertNotEqual(measured, other)
                self.assertNotEqual(other, measured)
                self.assertEqual(len({measured, other}), 2)
                self.assertTrue(measured.approx_match(other))

    def test_close_statistics_do_not_form_nontransitive_equality_chains(self):
        steps = [self.make_step(mean=value, std=2) for value in (1.0, 1.000075, 1.00015)]
        self.assertEqual(len(set(steps)), 3)
        for first, other in zip(steps, steps[1:]):
            self.assertNotEqual(first, other)
            self.assertTrue(first.approx_match(other))

    def test_size_and_context_and_interval_remain_part_of_identity(self):
        first = self.make_step()
        for fields in [{'size': 2}, {'attack': self.wrong}, {'source_ip': 'other-source'},
                       {'destination_ip': 'other-destination'},
                       {'start_time': EPOCH + timedelta(microseconds=1)},
                       {'end_time': EPOCH + timedelta(seconds=2)}]:
            with self.subTest(fields=fields):
                self.assertNotEqual(first, self.make_step(**fields))

    def test_dag_lookup_and_deduplication_accept_equivalent_timestamp_representations(self):
        root, child = self.make_step(0, mean=1, std=2), self.make_step(3, mean=1, std=2)
        offset = timezone(timedelta(hours=-3))
        same_root = self.make_step(0, mean=1, std=2,
                                   start_time=root.start_time.astimezone(offset),
                                   end_time=root.end_time.astimezone(offset))
        same_child = self.make_step(3, mean=1, std=2,
                                    start_time=child.start_time.replace(tzinfo=None),
                                    end_time=child.end_time.replace(tzinfo=None))
        dag = AttackScenarioDAG([root, child, same_root])
        self.assertEqual(len(dag.groups[root.get_exploit_group_id()]), 2)
        self.assertEqual(dag.parents_map[same_child], [])
        self.assertEqual(dag.get_adjacent_pairs(), set())
        self.assertEqual(dag.get_repetition_pairs(), {(same_root, same_child)})
        self.assertEqual(dag.get_chains(), [[same_root], [same_child]])

    def test_step_context_key_reflects_edits_before_hashing(self):
        step = self.make_step()
        previous = step.metric_key
        step.source_ip = 'other-source'
        self.assertNotEqual(step.metric_key, previous)
        self.assertEqual({step: 'edited step'}[self.make_step(source_ip='other-source')], 'edited step')


class TestRequirementIdentity(ProjectTestCase):
    def test_source_order_and_duplicates_do_not_change_lookup_or_deduplication(self):
        first = RecoveryRequirement(self.discover, [SOURCE, 'other-source'], TARGET)
        other = RecoveryRequirement(self.discover, ['other-source', SOURCE, SOURCE], TARGET)
        self.assertEqual(first, other)
        self.assertEqual(hash(first), hash(other))
        self.assertEqual({first: 'requirement'}[other], 'requirement')
        self.assertEqual(len({first, other}), 1)

    def test_attack_destination_and_source_membership_remain_distinct(self):
        first = RecoveryRequirement(self.discover, [SOURCE], TARGET)
        variants = [RecoveryRequirement(self.wrong, [SOURCE], TARGET),
                    RecoveryRequirement(self.discover, [SOURCE], 'other-destination'),
                    RecoveryRequirement(self.discover, [], TARGET),
                    RecoveryRequirement(self.discover, [SOURCE, 'other-source'], TARGET)]
        self.assertEqual(len({first, *variants}), 5)
        for other in variants:
            self.assertNotEqual(first, other)
