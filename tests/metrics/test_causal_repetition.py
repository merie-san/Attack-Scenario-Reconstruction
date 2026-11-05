"""Repeated observations affect occurrence coverage, not synthetic causal clauses."""

from metrics import MetricsCalculator
from scenario_reconstructor.dag import AttackGoal, AttackScenarioDAG
from scenario_reconstructor.models import AttackType, Precondition
from tests.support import Attribute, ProjectTestCase


class TestCausalRepetitionSeparation(ProjectTestCase):
    def test_every_occurrence_gets_its_own_preconditions_and_all_prior_supporters(self):
        root = self.make_step(0)
        first = self.make_step(2, attack=self.finish)
        later_root = self.make_step(4)
        second = self.make_step(6, attack=self.finish)
        simultaneous_root = self.make_step(6)
        dag = AttackScenarioDAG([second, simultaneous_root, first, later_root, root])
        self.assertEqual(dag.clause_parents_map[first], [[root]])
        self.assertEqual(dag.clause_parents_map[second], [[root, later_root]])
        self.assertEqual(dag.get_repetition_pairs(), {
            (root, later_root), (later_root, simultaneous_root), (first, second),
        })
        self.assertEqual(dag.get_causal_pairs(), {(root, first), (root, second), (later_root, second)})
        for parent, child in dag.get_adjacent_pairs():
            self.assertTrue(dag.is_causally_correlated(parent, child))

    def test_later_occurrence_can_depend_on_a_group_that_started_after_its_group(self):
        first = self.make_step(0, attack=self.finish)
        support = self.make_step(2)
        second = self.make_step(4, attack=self.finish)
        dag = AttackScenarioDAG([first, support, second])
        self.assertEqual(dag.roots, [first, support])
        self.assertEqual(dag.clause_parents_map[second], [[support]])
        self.assertEqual(dag.get_repetition_pairs(), {(first, second)})
        self.assertNotIn((first, second), dag.get_causal_pairs())

    def test_missing_repetition_preserves_causal_recovery_but_reduces_occurrence_and_alert_recall(self):
        roots = [self.make_step(0), self.make_step(4)]
        target = self.make_step(8, attack=self.finish)
        actual = AttackScenarioDAG([*roots, target])
        for recovered_root in roots:
            with self.subTest(root=recovered_root.start_time):
                predicted = AttackScenarioDAG([recovered_root, target])
                self.assertEqual(MetricsCalculator.get_scenario_soundness_completeness(predicted, actual), (1.0, 1.0))
                self.assertEqual(MetricsCalculator.get_scenario_step_recall(predicted, actual), 2 / 3)
                self.assertEqual(MetricsCalculator.get_scenario_step_precision(predicted, actual), 1.0)
                goal = AttackGoal(attack_type=self.finish)
                self.assertTrue(MetricsCalculator.is_scenario_detected(
                    predicted, actual, goal, edge_recovery_threshold=1.0))
                self.assertEqual(actual.get_goal_clause_recovery(target, predicted.get_causal_pairs()), (1, 1))
                actual_flows = [self.make_flow(0), self.make_flow(4), self.make_flow(8, attack=self.finish)]
                predicted_flows = [flow for flow in actual_flows
                                   if flow.start_time in (recovered_root.start_time, target.start_time)]
                self.assertEqual(MetricsCalculator.get_alert_recall(predicted_flows, actual_flows), 2 / 3)
                self.assertEqual(MetricsCalculator.get_alert_precision(predicted_flows, actual_flows), 1.0)

    def test_repetition_pairs_cannot_recover_a_missing_causal_clause(self):
        root = self.make_step(0, duration=10)
        first = self.make_step(2, attack=self.finish)
        second = self.make_step(4, attack=self.finish)
        actual = AttackScenarioDAG([root, first, second])
        # Root still matches by interval but starts after both dependent occurrences.
        shifted_root = self.make_step(6)
        predicted = AttackScenarioDAG([first, second, shifted_root])
        self.assertEqual(predicted.get_repetition_pairs(), {(first, second)})
        self.assertEqual(predicted.get_causal_pairs(), set())
        self.assertEqual(MetricsCalculator._get_causal_correlation_pairs(actual, predicted)[1], set())
        self.assertEqual(MetricsCalculator.get_scenario_soundness_completeness(predicted, actual), (0.0, 0.0))
        self.assertEqual(actual.get_goal_clause_recovery(second, predicted.get_repetition_pairs()), (0, 1))
        self.assertFalse(MetricsCalculator.is_scenario_detected(
            predicted, actual, AttackGoal(attack_type=self.finish), edge_recovery_threshold=1.0))

    def test_repeated_and_goal_keeps_independent_clauses(self):
        first_root, second_root = self.make_step(0), self.make_step(1)
        other = self.make_step(2, attack=self.wrong)
        goal_type = AttackType('and_goal', {
            Precondition({Attribute.DISCOVERED}, False), Precondition({Attribute.OTHER}, False),
        }, set())
        first_goal, second_goal = self.make_step(3, attack=goal_type), self.make_step(5, attack=goal_type)
        dag = AttackScenarioDAG([first_root, second_root, other, first_goal, second_goal])
        for goal in (first_goal, second_goal):
            self.assertCountEqual(dag.clause_parents_map[goal], [[first_root, second_root], [other]])
            self.assertEqual(dag.get_goal_clause_recovery(goal, dag.get_causal_pairs()), (2, 2))
        self.assertNotIn((first_goal, second_goal), dag.get_causal_pairs())
        predicted = AttackScenarioDAG([first_root, other, second_goal])
        self.assertEqual(MetricsCalculator.get_scenario_soundness_completeness(predicted, dag), (1.0, 1.0))
        self.assertEqual(MetricsCalculator.get_scenario_step_recall(predicted, dag), 3 / 5)
        self.assertTrue(MetricsCalculator.is_scenario_detected(
            predicted, dag, AttackGoal(attack_type=goal_type), edge_recovery_threshold=1.0))

    def test_shared_context_only_creates_causal_edges_if_postconditions_support_preconditions(self):
        self_enabling = AttackType('self_enabling', {Precondition({Attribute.DISCOVERED}, False)},
                                   {Attribute.DISCOVERED})
        first, second = self.make_step(0, attack=self_enabling), self.make_step(2, attack=self_enabling)
        dag = AttackScenarioDAG([first, second])
        self.assertEqual(dag.get_repetition_pairs(), {(first, second)})
        self.assertEqual(dag.clause_parents_map[second], [[first]])
        self.assertTrue(dag.is_causally_correlated(first, second))

    def test_deep_true_causal_chain_remains_iterative(self):
        steps = []
        for i in range(1050):
            # Different contexts form a genuine host-to-host dependency chain.
            attack = AttackType('chain', {Precondition({Attribute.DISCOVERED}, True)}, {Attribute.DISCOVERED})
            steps.append(self.make_step(i * 2, attack=attack, source_ip=f'host-{i}', destination_ip=f'host-{i + 1}'))
        dag = AttackScenarioDAG(steps)
        self.assertEqual(dag.get_repetition_pairs(), set())
        self.assertEqual(dag.get_chains(), [steps])
        self.assertEqual(dag.get_goal_clause_recovery(steps[-1], dag.get_adjacent_pairs()), (1049, 1049))
