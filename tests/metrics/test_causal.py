from datetime import datetime, timedelta, timezone

from metrics import MetricsCalculator
from scenario_reconstructor.dag import AttackGoal, AttackScenarioDAG
from scenario_reconstructor.models import AttackStep, AttackType, Precondition
from tests.metrics.fixtures import (
    ATTACK_1,
    ATTACK_2,
    ATTACK_3,
    ExampleHostAttribute,
    MetricsFixture,
    UNDETERMINED,
)
from tests.support import ProjectTestCase


class TestCausalMetrics(MetricsFixture):
    def test_attack_scenario_dag_construction(self):
        dag = self.actual_dag
        # 3 distinct groups form a chain: step 0 (10.0.0.2 -> 10.0.0.5) -> step 1 (10.0.0.2 -> 10.0.0.5) -> step 2 (10.0.0.5 -> 10.0.0.10)
        self.assertEqual(dag.roots, [self.actual_steps[0]])
        self.assertEqual(dag.parents_map[self.actual_steps[0]], [])
        self.assertEqual(dag.parents_map[self.actual_steps[1]], [self.actual_steps[0]])
        self.assertEqual(dag.parents_map[self.actual_steps[2]], [self.actual_steps[1]])
        chains = dag.get_chains()
        self.assertEqual(chains, [[self.actual_steps[0], self.actual_steps[1], self.actual_steps[2]]])
        # Transitive causal pairs include both direct edges (s0->s1, s1->s2) and transitive ancestor edge (s0->s2)
        self.assertEqual(
            dag.get_causal_pairs(),
            {
                (self.actual_steps[0], self.actual_steps[1]),
                (self.actual_steps[1], self.actual_steps[2]),
                (self.actual_steps[0], self.actual_steps[2]),
            },
        )

    def test_get_scenario_soundness_completeness(self):
        actual_with_extra = AttackScenarioDAG(
            list(self.actual_steps)
            + [
                AttackStep(
                    ATTACK_3, 2, "10.0.0.6", "10.0.0.10",
                    datetime(2001, 10, 10, 0, 1, 3),
                    datetime(2001, 10, 10, 0, 1, 38),
                    (datetime(2001, 10, 10, 0, 1, 38) - datetime(2001, 10, 10, 0, 1, 2)).total_seconds(),
                    0,
                )
            ]
        )
        sound, compl = self.calculator.get_scenario_soundness_completeness(self.predicted_dag, actual_with_extra, UNDETERMINED)
        # Matched steps (0, 1, 2) preserve all causal DAG clauses
        self.assertEqual(sound, 1.0)
        self.assertEqual(compl, 1.0)

        # If a matched step's timestamp is inverted relative to its causal parent, DAG edges change and soundness/completeness drop
        inverted_predicted_dag = AttackScenarioDAG([
            AttackStep(ATTACK_1, 2, "10.0.0.2", "10.0.0.5", datetime(2001, 10, 10, 0, 0, 5), datetime(2001, 10, 10, 0, 0, 8), 0, 0),
            AttackStep(ATTACK_2, 1, "10.0.0.2", "10.0.0.5", datetime(2001, 10, 10, 0, 0, 1), datetime(2001, 10, 10, 0, 0, 40), -1, -1),
        ])
        actual_two_dag = AttackScenarioDAG(self.actual_steps[:2])
        sound_inv, compl_inv = self.calculator.get_scenario_soundness_completeness(inverted_predicted_dag, actual_two_dag, UNDETERMINED)
        # No causal edges are predicted when s1 precedes s0, while actual_two_dag has edge (s0 -> s1) -> sound = 0.0, compl = 0.0
        self.assertEqual(sound_inv, 0.0)
        self.assertEqual(compl_inv, 0.0)

    def test_is_scenario_detected_with_attack_goal(self):
        # Goal is ATTACK_3 targeting 10.0.0.10 from 10.0.0.5 (actual_steps[2], whose path from root is s0 -> s1 -> s2)
        goal = AttackGoal(attack_type=ATTACK_3, source_ip="10.0.0.5", destination_ip="10.0.0.10")
        self.assertTrue(
            self.calculator.is_scenario_detected(
                self.predicted_dag, self.actual_dag, goal, UNDETERMINED, edge_recovery_threshold=0.5
            )
        )
        # If the goal requires a destination IP not present in the scenario, detection is False
        unreachable_goal = AttackGoal(attack_type=ATTACK_3, destination_ip="10.0.0.99")
        self.assertFalse(
            self.calculator.is_scenario_detected(
                self.predicted_dag, self.actual_dag, unreachable_goal, UNDETERMINED
            )
        )
        # If only the final step s2 is predicted (both s0 and s1 missed), 0 of 2 path clauses are recovered (0/2 < 0.5)
        predicted_only_goal_dag = AttackScenarioDAG([self.predicted_steps[-1]])
        self.assertFalse(
            self.calculator.is_scenario_detected(
                predicted_only_goal_dag, self.actual_dag, goal, UNDETERMINED, edge_recovery_threshold=0.5
            )
        )

    def test_dag_and_or_clause_semantics(self):
        # Two distinct attack types (ATTACK_1 and ATTACK_1_ALT) satisfy the SAME precondition ATT_1 (OR-clause)
        attack_1_alt = AttackType("att_1_alt", set(), {ExampleHostAttribute.ATT_1})
        # Another root attack grants ATT_2 directly on 10.0.0.5
        attack_2_root = AttackType("att_2_root", set(), {ExampleHostAttribute.ATT_2})
        # Goal attack requires BOTH ATT_1 and ATT_2 on source 10.0.0.5 (two distinct AND-clauses)
        attack_and_goal = AttackType(
            "att_and_goal",
            {
                Precondition({ExampleHostAttribute.ATT_1}, True),
                Precondition({ExampleHostAttribute.ATT_2}, True),
            },
            {ExampleHostAttribute.ATT_3},
        )

        s1_a = AttackStep(ATTACK_1, 1, "10.0.0.2", "10.0.0.5", datetime(2001, 10, 10, 0, 0, 0), datetime(2001, 10, 10, 0, 0, 2), -1, -1)
        s1_b = AttackStep(attack_1_alt, 1, "10.0.0.2", "10.0.0.5", datetime(2001, 10, 10, 0, 0, 10), datetime(2001, 10, 10, 0, 0, 12), -1, -1)
        s2_root = AttackStep(attack_2_root, 1, "10.0.0.2", "10.0.0.5", datetime(2001, 10, 10, 0, 0, 15), datetime(2001, 10, 10, 0, 0, 32), -1, -1)
        s_goal = AttackStep(attack_and_goal, 1, "10.0.0.5", "10.0.0.10", datetime(2001, 10, 10, 0, 0, 30), datetime(2001, 10, 10, 0, 0, 35), -1, -1)

        actual_dag = AttackScenarioDAG([s1_a, s1_b, s2_root, s_goal])

        # s_goal has 2 AND-clauses: one OR-clause [s1_a, s1_b] (for ATT_1) and one clause [s2_root] (for ATT_2)
        clauses_as_sets = [set(or_clause) for or_clause in actual_dag.clause_parents_map[s_goal]]
        self.assertEqual(len(clauses_as_sets), 2)
        self.assertIn({s1_a, s1_b}, clauses_as_sets)
        self.assertIn({s2_root}, clauses_as_sets)

        goal = AttackGoal(attack_type=attack_and_goal, source_ip="10.0.0.5", destination_ip="10.0.0.10")

        # Case 1: Predictor recovers ONLY s1_a (ignoring redundant OR-sibling s1_b) plus s2_root and s_goal
        # Both AND-clauses of s_goal are satisfied -> completeness = 1.0 and goal is detected at threshold=1.0
        pred_or_branch = AttackScenarioDAG([s1_a, s2_root, s_goal])
        sound_or, compl_or = self.calculator.get_scenario_soundness_completeness(pred_or_branch, actual_dag)
        self.assertEqual(sound_or, 1.0)
        self.assertEqual(compl_or, 1.0)
        self.assertTrue(
            self.calculator.is_scenario_detected(pred_or_branch, actual_dag, goal, edge_recovery_threshold=1.0)
        )

        # Case 2: Predictor matches s1_a, s2_root (overlapping [15, 32] at [31, 35]), and s_goal,
        # but s2_root_inverted starts at 0:00:31 (after s_goal at 0:00:30), breaking the second AND-clause
        s2_root_inverted = AttackStep(attack_2_root, 1, "10.0.0.2", "10.0.0.5", datetime(2001, 10, 10, 0, 0, 31), datetime(2001, 10, 10, 0, 0, 35), -1, -1)
        pred_missing_and = AttackScenarioDAG([s1_a, s2_root_inverted, s_goal])
        sound_and, compl_and = self.calculator.get_scenario_soundness_completeness(pred_missing_and, actual_dag)
        # Only 1 of the 2 required AND-clauses is satisfied -> completeness = 0.5, and goal fails detection at threshold=1.0
        self.assertEqual(sound_and, 1.0)
        self.assertEqual(compl_and, 0.5)
        self.assertFalse(
            self.calculator.is_scenario_detected(pred_missing_and, actual_dag, goal, edge_recovery_threshold=1.0)
        )


class TestCausalRegressions(ProjectTestCase):
    def test_shared_ancestor_cannot_satisfy_a_matched_and_parent(self):
        branch_a = AttackType(
            'branch_a', {Precondition({ExampleHostAttribute.ATT_1}, False)},
            {ExampleHostAttribute.ATT_2},
        )
        branch_b = AttackType(
            'branch_b', {Precondition({ExampleHostAttribute.ATT_1}, False)},
            {ExampleHostAttribute.ATT_3},
        )
        goal_type = AttackType('and_goal', {
            Precondition({ExampleHostAttribute.ATT_2}, False),
            Precondition({ExampleHostAttribute.ATT_3}, False),
        }, set())
        root = self.make_step(0, ATTACK_1)
        a = self.make_step(10, branch_a)
        b = self.make_step(20, branch_b, duration=30)
        goal = self.make_step(30, goal_type)
        shifted_b = self.make_step(40, branch_b)
        actual = AttackScenarioDAG([root, a, b, goal])
        predicted = AttackScenarioDAG([root, a, shifted_b, goal])

        self.assertEqual(MetricsCalculator.get_scenario_step_recall(predicted, actual), 1.0)
        self.assertIn((root, goal), predicted.get_causal_pairs())
        self.assertNotIn((shifted_b, goal), predicted.get_causal_pairs())
        self.assertEqual(
            MetricsCalculator.get_scenario_soundness_completeness(predicted, actual),
            (1.0, 0.75),
        )

    def test_goal_recovery_reuses_scoring_choice_for_or_branch(self):
        a = self.make_step(0, ATTACK_2)
        root = self.make_step(5, ATTACK_1)
        b_type = AttackType(
            'branch_b', {Precondition({ExampleHostAttribute.ATT_1}, False)},
            {ExampleHostAttribute.ATT_2},
        )
        goal_type = AttackType(
            'or_goal', {Precondition({ExampleHostAttribute.ATT_2}, False)}, set(),
        )
        b = self.make_step(10, b_type, duration=30)
        goal = self.make_step(20, goal_type)
        actual = AttackScenarioDAG([a, root, b, goal])
        shifted_b = self.make_step(30, b_type)
        predicted = AttackScenarioDAG([root, shifted_b, goal])
        self.assertEqual(actual.clause_parents_map[goal], [[a, b]])
        self.assertEqual(predicted.get_causal_pairs(), {(root, shifted_b)})
        self.assertEqual(actual.get_goal_clause_recovery(goal, {(root, b)}), (1, 2))
        self.assertTrue(MetricsCalculator.is_scenario_detected(
            predicted, actual, AttackGoal(attack_type=goal_type), edge_recovery_threshold=0.5,
        ))

    def test_missing_parent_search_stops_at_nearest_matched_intermediate(self):
        missing_type = AttackType(
            'missing', {Precondition({ExampleHostAttribute.ATT_2}, False)},
            {ExampleHostAttribute.ATT_3},
        )
        bypass_type = AttackType(
            'bypass', {Precondition({ExampleHostAttribute.ATT_1}, False)},
            {ExampleHostAttribute.ATT_3},
        )
        goal_type = AttackType(
            'goal', {Precondition({ExampleHostAttribute.ATT_3}, False)}, set(),
        )
        root = self.make_step(0, ATTACK_1)
        intermediate = self.make_step(10, ATTACK_2, duration=40)
        missing = self.make_step(20, missing_type)
        goal = self.make_step(30, goal_type)
        actual = AttackScenarioDAG([root, intermediate, missing, goal])
        bypass = self.make_step(5, bypass_type)
        shifted_intermediate = self.make_step(40, ATTACK_2)
        predicted = AttackScenarioDAG([root, bypass, goal, shifted_intermediate])
        self.assertIn((root, goal), predicted.get_causal_pairs())
        self.assertEqual(
            MetricsCalculator.get_scenario_soundness_completeness(predicted, actual),
            (1.0, 0.5),
        )
        # With both intermediates missing, the root is the nearest matched ancestor.
        self.assertEqual(
            MetricsCalculator.get_scenario_soundness_completeness([root, bypass, goal], actual),
            (1.0, 1.0),
        )

    def test_duplicate_repetitions_do_not_create_self_loops(self):
        a0 = self.make_step(0)
        a1 = self.make_step(10)
        duplicate_a1 = self.make_step(10)
        self.assertIsNot(a1, duplicate_a1)
        dag = AttackScenarioDAG([a0, a1, duplicate_a1])
        self.assertEqual(len(dag.steps), 3)
        self.assertEqual(dag.groups[a0.get_exploit_group_id()], [a0, a1])
        for step in dag.steps:
            self.assertNotIn(step, dag.parents_map[step])
            self.assertNotIn(step, dag.children_map[step])
            for clause in dag.clause_parents_map[step]:
                self.assertNotIn(step, clause)
        self.assertEqual(dag.get_chains(), [[a0], [a1]])
        self.assertEqual(dag.get_repetition_pairs(), {(a0, a1)})
        self.assertEqual(dag.get_goal_clause_recovery(a1, {(a0, a1)}), (0, 0))
        self.assertAlmostEqual(
            MetricsCalculator.get_scenario_step_precision(dag, [a0, a1]), 2 / 3,
        )
        self.assertAlmostEqual(
            MetricsCalculator.get_scenario_step_recall([a0, a1], dag), 2 / 3,
        )

    def test_timezone_offsets_preserve_edges_and_metric_scores(self):
        utc_start = datetime(2026, 1, 1, 9, tzinfo=timezone.utc)
        utc_goal = datetime(2026, 1, 1, 10, tzinfo=timezone.utc)
        actual_root = self.make_step(start_time=utc_start, end_time=utc_start)
        actual_goal = self.make_step(attack=self.finish, start_time=utc_goal, end_time=utc_goal)
        actual = AttackScenarioDAG([actual_goal, actual_root])
        goal = AttackGoal(attack_type=self.finish)
        for root_time, goal_time in (
            (utc_start.astimezone(timezone(timedelta(hours=2))), utc_goal),
            (utc_start.astimezone(timezone(timedelta(hours=2))), utc_goal.replace(tzinfo=None)),
            (utc_start.replace(tzinfo=None), utc_goal),
        ):
            with self.subTest(root_time=root_time, goal_time=goal_time):
                root = self.make_step(start_time=root_time, end_time=root_time)
                target = self.make_step(attack=self.finish, start_time=goal_time, end_time=goal_time)
                predicted = AttackScenarioDAG([target, root])
                self.assertEqual(predicted.steps, [root, target])
                self.assertEqual(predicted.get_adjacent_pairs(), {(root, target)})
                self.assertTrue(predicted.is_causally_correlated(root, target))
                self.assertEqual(predicted.get_goal_clause_recovery(target, {(root, target)}), (1, 1))
                self.assertEqual(MetricsCalculator.get_scenario_step_precision(predicted, actual), 1.0)
                self.assertEqual(MetricsCalculator.get_scenario_step_recall(predicted, actual), 1.0)
                self.assertEqual(
                    MetricsCalculator.get_scenario_soundness_completeness(predicted, actual),
                    MetricsCalculator.get_scenario_soundness_completeness(actual, actual),
                )
                self.assertTrue(MetricsCalculator.is_scenario_detected(
                    predicted, actual, goal, edge_recovery_threshold=1.0,
                ))

    def test_many_repetitions_are_or_supporters_not_mandatory_goal_clauses(self):
        repetitions = [self.make_step(i * 2, duration=0) for i in range(1100)]
        goal_step = self.make_step(2200, self.finish, duration=0)
        dag = AttackScenarioDAG(repetitions + [goal_step])
        self.assertEqual(dag.get_chains(), [[step, goal_step] for step in repetitions])
        self.assertEqual(len(dag.get_repetition_pairs()), 1099)
        self.assertEqual(
            dag.get_goal_clause_recovery(goal_step, dag.get_adjacent_pairs()), (1, 1),
        )
        # Any one earlier occurrence can support the goal without recovering repeats.
        predicted = AttackScenarioDAG([repetitions[-1], goal_step])
        self.assertTrue(MetricsCalculator.is_scenario_detected(
            predicted, dag, AttackGoal(attack_type=self.finish), edge_recovery_threshold=1.0,
        ))

    def test_all_prior_repetitions_before_goal_use_utc_instants(self):
        offset = timezone(timedelta(hours=2))
        first_time = datetime(2026, 1, 1, 11, tzinfo=offset)
        latest_time = datetime(2026, 1, 1, 11, 30, tzinfo=offset)
        future_time = datetime(2026, 1, 1, 11, tzinfo=timezone.utc)
        goal_time = datetime(2026, 1, 1, 10, tzinfo=timezone.utc)
        first = self.make_step(start_time=first_time, end_time=first_time)
        latest = self.make_step(start_time=latest_time, end_time=latest_time)
        future = self.make_step(start_time=future_time, end_time=future_time)
        goal = self.make_step(attack=self.finish, start_time=goal_time, end_time=goal_time)
        dag = AttackScenarioDAG([future, goal, latest, first])
        self.assertEqual(dag.steps, [first, latest, goal, future])
        self.assertEqual(dag.parents_map[goal], [first, latest])
        self.assertEqual(dag.get_goal_clause_recovery(goal, dag.get_adjacent_pairs()), (1, 1))

    def test_B01_scenario_completeness_is_orthogonal_to_missing_steps(self):
        actual = [self.make_step(i) for i in range(10)]
        soundness, completeness = MetricsCalculator.get_scenario_soundness_completeness(actual[:2], actual)
        self.assertEqual(soundness, 1.0)
        self.assertEqual(completeness, 1.0)
        self.assertAlmostEqual(MetricsCalculator.get_scenario_step_recall(actual[:2], actual), 2 / 10)

    def test_B03_scenario_soundness_is_orthogonal_to_unmatched_predictions(self):
        actual = [self.make_step(0), self.make_step(1)]
        extra = self.make_step(2, AttackType('false_positive', set(), set()))
        soundness, completeness = MetricsCalculator.get_scenario_soundness_completeness(actual + [extra], actual)
        self.assertEqual(soundness, 1.0)
        self.assertEqual(completeness, 1.0)
        self.assertAlmostEqual(MetricsCalculator.get_scenario_step_precision(actual + [extra], actual), 2 / 3)
