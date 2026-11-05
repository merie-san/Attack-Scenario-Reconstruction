"""External endpoints provide flow context and baseline attributes, not learned state."""

from metrics import MetricsCalculator
from scenario_reconstructor.dag import AttackScenarioDAG
from scenario_reconstructor.models import AttackType, Precondition
from tests.support import Attribute, ProjectTestCase, SOURCE, TARGET


EXTERNAL = '203.0.113.8'


class TestExternalHostPolicy(ProjectTestCase):
    def test_outbound_alert_is_accepted_without_state_transition_or_external_effect(self):
        manager = self.make_manager()
        manager.accept(self.make_event(score=0.95, destination_ip=EXTERNAL))
        rec = manager.reconstructor
        dag, alerts = manager.get_results()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(dag.steps), 1)
        self.assertEqual(manager.get_fps(), [])
        self.assertEqual(rec.seen_external_hosts_dict[EXTERNAL].compromise_attributes, set())
        self.assertEqual(rec.get_state_sequence_length(), 1)
        self.assertNotIn(EXTERNAL, rec.return_states()[0].state)

    def test_external_preconditions_use_baseline_not_cached_host_attributes(self):
        rec = self.make_reconstructor(external_host_attributes={Attribute.DISCOVERED})
        needs_source = AttackType('needs_source', {Precondition({Attribute.DISCOVERED}, True)}, set())
        flow = self.make_flow(attack=needs_source, source_ip=EXTERNAL)
        self.assertTrue(rec.check_preconditions(flow))
        rec.seen_external_hosts_dict[EXTERNAL].compromise_attributes.clear()
        rec.seen_external_hosts_dict[EXTERNAL].compromise_attributes.add(Attribute.COMPROMISED)
        self.assertTrue(rec.check_preconditions(flow))
        needs_compromise = AttackType('needs_compromise', {Precondition({Attribute.COMPROMISED}, True)}, set())
        blocked = flow.mutate(needs_compromise)
        self.assertFalse(rec.check_preconditions(blocked))
        self.assertIsNone(rec.compute_requirements(blocked))

    def test_recovery_cannot_establish_external_destination_state(self):
        manager = self.make_manager()
        manager.accept(self.make_event(score=0.5, destination_ip=EXTERNAL))
        manager.accept(self.make_event(10, score=0.95, destination_ip=EXTERNAL,
                       scores={'discover': 0.0, 'wrong': 0.0, 'finish': 1.0}))
        self.assertEqual(manager.get_fns(), [])
        self.assertEqual(len(manager.get_fps()), 1)
        self.assertEqual(sum(len(group) for group in manager.suspect_dict.values()), 1)
        self.assertEqual(manager.get_results()[1], [])

    def test_outbound_effect_cannot_enable_later_external_source(self):
        manager = self.make_manager()
        self.finish.preconditions = {Precondition({Attribute.DISCOVERED}, True)}
        manager.accept(self.make_event(score=0.95, destination_ip=EXTERNAL))
        manager.accept(self.make_event(10, score=0.95, source_ip=EXTERNAL,
                       scores={'discover': 0.0, 'wrong': 0.0, 'finish': 1.0}))
        self.assertEqual(len(manager.get_results()[1]), 1)
        self.assertEqual(len(manager.get_fps()), 1)
        self.assertEqual(manager.get_fns(), [])
        self.assertEqual(manager.reconstructor.seen_external_hosts_dict[EXTERNAL].compromise_attributes, set())

    def test_external_source_can_supply_internal_recovery_using_baseline(self):
        rec = self.make_reconstructor(external_host_attributes={Attribute.OTHER})
        manager = self.make_manager(reconstructor=rec)
        # Observe the endpoint; this does not establish its state.
        manager.accept(self.make_event(-10, score=0.95, destination_ip=EXTERNAL))
        manager.accept(self.make_event(0, score=0.5, source_ip=EXTERNAL))
        manager.accept(self.make_event(10, score=0.95,
                       scores={'discover': 0.0, 'wrong': 0.0, 'finish': 1.0}))
        self.assertEqual([alert.source_ip for alert in manager.get_fns()], [EXTERNAL])
        self.assertIn(Attribute.COMPROMISED, rec.host_dict[TARGET].compromise_attributes)
        self.assertEqual(rec.seen_external_hosts_dict[EXTERNAL].compromise_attributes, {Attribute.OTHER})

    def test_dag_excludes_both_external_dependency_directions_but_keeps_repetitions(self):
        outgoing = self.make_step(0, destination_ip=EXTERNAL)
        source_condition = AttackType('source_condition', {Precondition({Attribute.DISCOVERED}, True)}, set())
        incoming = self.make_step(1, attack=source_condition, source_ip=EXTERNAL)
        external_condition = self.make_step(2, attack=self.finish, destination_ip=EXTERNAL)
        repeat = self.make_step(3, destination_ip=EXTERNAL)
        steps = [repeat, external_condition, incoming, outgoing]
        dag = AttackScenarioDAG(steps, tracked_host_ips={SOURCE, TARGET})
        self.assertEqual(dag.get_adjacent_pairs(), set())
        self.assertEqual(dag.get_repetition_pairs(), {(outgoing, repeat)})
        self.assertEqual(dag.parents_map[incoming], [])
        self.assertEqual(dag.parents_map[external_condition], [])
        self.assertFalse(dag.is_causally_correlated(outgoing, incoming))
        self.assertFalse(dag.is_causally_correlated(outgoing, external_condition))
        self.assertEqual(dag.steps, [outgoing, incoming, external_condition, repeat])
        unrestricted = AttackScenarioDAG(steps)
        self.assertTrue(unrestricted.is_causally_correlated(outgoing, incoming))
        self.assertTrue(unrestricted.is_causally_correlated(outgoing, external_condition))

    def test_internal_effect_can_enable_outbound_step(self):
        root = self.make_step(0)
        outbound_type = AttackType('outbound', {Precondition({Attribute.DISCOVERED}, True)}, set())
        outbound = self.make_step(1, attack=outbound_type, source_ip=TARGET, destination_ip=EXTERNAL)
        dag = AttackScenarioDAG([outbound, root], tracked_host_ips={SOURCE, TARGET})
        self.assertEqual(dag.get_adjacent_pairs(), {(root, outbound)})
        self.assertTrue(dag.is_causally_correlated(root, outbound))

    def test_empty_tracking_set_disables_state_dependencies(self):
        root = self.make_step(0)
        child = self.make_step(1, attack=self.finish)
        self.assertEqual(AttackScenarioDAG([root, child], tracked_host_ips=set()).get_adjacent_pairs(), set())
        self.assertEqual(AttackScenarioDAG([root, child]).get_adjacent_pairs(), {(root, child)})

    def test_reconstructed_and_actual_dags_share_policy_with_external_baseline(self):
        rec = self.make_reconstructor(external_host_attributes={Attribute.DISCOVERED})
        manager = self.make_manager(reconstructor=rec)
        self.finish.preconditions = {Precondition({Attribute.DISCOVERED}, True)}
        manager.accept(self.make_event(0, score=0.95, destination_ip=EXTERNAL))
        manager.accept(self.make_event(10, score=0.95, source_ip=EXTERNAL,
                       scores={'discover': 0.0, 'wrong': 0.0, 'finish': 1.0}))
        predicted, alerts = manager.get_results()
        self.assertEqual(len(alerts), 2)
        self.assertEqual(predicted.tracked_host_ips, frozenset(rec.host_dict))
        actual_steps = [self.make_step(0, destination_ip=EXTERNAL),
                        self.make_step(10, attack=self.finish, source_ip=EXTERNAL)]
        for actual_input in (actual_steps, AttackScenarioDAG(actual_steps)):
            actual, normalized_predicted = MetricsCalculator._ensure_dag_pair(actual_input, predicted)
            self.assertEqual(actual.tracked_host_ips, predicted.tracked_host_ips)
            self.assertEqual(actual.get_adjacent_pairs(), set())
            self.assertEqual(normalized_predicted.get_adjacent_pairs(), set())
        with self.assertRaises(ValueError):
            MetricsCalculator.get_scenario_soundness_completeness(
                predicted, AttackScenarioDAG(actual_steps, tracked_host_ips=set()))
