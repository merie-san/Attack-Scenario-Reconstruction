from scenario_reconstructor.dag import AttackGoal, AttackScenarioDAG
from scenario_reconstructor.models import AttackType, NetworkState, Precondition
from tests.support import Attribute, ProjectTestCase, SOURCE, TARGET


class TestBatchScenarioDAG(ProjectTestCase):

    def test_metrics_reexports_reconstructor_types(self):
        from scenario_generator.compute_metrics import AttackGoal as MetricsAttackGoal
        from scenario_generator.compute_metrics import AttackScenarioDAG as MetricsAttackScenarioDAG

        self.assertIs(MetricsAttackGoal, AttackGoal)
        self.assertIs(MetricsAttackScenarioDAG, AttackScenarioDAG)

    def test_empty_scenario_dag(self):
        dag = self.make_reconstructor().return_scenario_dag()
        self.assertIsInstance(dag, AttackScenarioDAG)
        self.assertEqual(dag.steps, [])
        self.assertEqual(dag.roots, [])
        self.assertEqual(dag.parents_map, {})
        self.assertEqual(dag.clause_parents_map, {})

    def test_clustered_steps_build_and_or_dag_with_repetitions(self):
        alternative = AttackType('alternative', set(), {Attribute.DISCOVERED})
        goal_type = AttackType('goal', {
            Precondition({Attribute.DISCOVERED}, True),
            Precondition({Attribute.OTHER}, False),
        }, {Attribute.COMPROMISED})
        rec = self.make_reconstructor(attacks=self.types + [alternative, goal_type])
        # Insert the goal first and repetitions out of order: DAG order comes from time.
        batches = [
            (goal_type, 3, SOURCE, TARGET),
            (self.discover, 4, TARGET, SOURCE),
            (self.discover, 0, TARGET, SOURCE),
            (self.discover, 2, TARGET, SOURCE),
            (alternative, 1, TARGET, SOURCE),
            (self.wrong, 1, SOURCE, TARGET),
        ]
        for attack, second, source, destination in batches:
            for port in ('2000', '2001'):
                rec.add_flow_exploit(self.make_flow(
                    second, attack=attack, duration=0.1, source_ip=source,
                    destination_ip=destination, source_port=port,
                ))
        rec.update_exploits_all()
        dag = rec.return_scenario_dag()

        self.assertIsInstance(dag, AttackScenarioDAG)
        self.assertEqual(len(dag.steps), 6)
        self.assertEqual([step.size for step in dag.steps], [2] * 6)
        self.assertEqual(dag.steps, sorted(dag.steps, key=lambda step: step.start_time))
        discovery = [step for step in dag.steps if step.attack_type == self.discover]
        alt = next(step for step in dag.steps if step.attack_type == alternative)
        other = next(step for step in dag.steps if step.attack_type == self.wrong)
        goal = next(step for step in dag.steps if step.attack_type == goal_type)

        self.assertCountEqual(dag.roots, [*discovery, alt, other])
        for root in dag.roots:
            self.assertEqual(dag.parents_map[root], [])
            self.assertEqual(dag.clause_parents_map[root], [])
        self.assertEqual(dag.get_repetition_pairs(), {
            (discovery[0], discovery[1]), (discovery[1], discovery[2]),
        })
        self.assertEqual(
            {frozenset(clause) for clause in dag.clause_parents_map[goal]},
            {frozenset([discovery[0], discovery[1], alt]), frozenset([other])},
        )
        self.assertCountEqual(dag.parents_map[goal], [discovery[0], discovery[1], alt, other])
        self.assertIn(goal, dag.children_map[discovery[1]])
        self.assertIn(goal, dag.children_map[alt])
        self.assertIn(goal, dag.children_map[other])
        self.assertEqual(dag.get_adjacent_pairs(), {
            (discovery[0], goal), (discovery[1], goal), (alt, goal), (other, goal),
        })

    def test_change_log_paths_uses_only_alert_and_state_logs(self):
        rec = self.make_reconstructor()
        paths = [self.log_path(name) for name in ('new_flows.log', 'new_states.log')]
        rec.change_log_paths(*paths)
        self.assertEqual([rec.flow_exploit_log_path, rec.state_log_path], paths)
        rec.log_states()
        with open(paths[1]) as state_log:
            self.assertIn('NetworkState(', state_log.read())
