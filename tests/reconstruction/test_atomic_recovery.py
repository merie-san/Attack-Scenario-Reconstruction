"""A recovery hypothesis may affect real state only after the complete sequence validates."""

from pathlib import Path
from unittest.mock import patch

from scenario_reconstructor.models import AttackType, Precondition, RecoveryRequirement
from tests.support import Attribute, ProjectTestCase, SOURCE, TARGET


class TestAtomicRecovery(ProjectTestCase):
    def trigger(self, second=10, **options):
        return self.make_event(second, score=0.95,
                               scores={'discover': 0.0, 'wrong': 0.0, 'finish': 1.0}, **options)

    def snapshot(self, manager):
        rec = manager.reconstructor
        return {
            'hosts': {ip: set(host.compromise_attributes) for ip, host in rec.host_dict.items()},
            'external': {ip: set(host.compromise_attributes) for ip, host in rec.seen_external_hosts_dict.items()},
            'alerts': {key: list(flows) for key, flows in rec.return_flow_exploits().items()},
            'steps': {key: list(steps) for key, steps in rec.return_exploits().items()},
            'states': [({ip: set(values) for ip, values in state.state.items()}, state.transition_time)
                       for state in rec.return_states()],
            'fns': list(manager.get_fns()),
            'suspects': {key: list(flows) for key, flows in manager.suspect_dict.items()},
            'logs': [Path(path).read_bytes() if Path(path).exists() else None
                     for path in (rec.flow_exploit_log_path, rec.state_log_path)],
        }

    def test_retyped_support_preserves_original_until_commit_and_consumes_only_selected_cluster(self):
        manager = self.make_manager(length_when_log_flow_exploits=0)
        support = self.make_flow(attack=self.wrong, attack_types_alternatives=[self.discover])
        future = self.make_flow(100, attack=self.wrong, attack_types_alternatives=[self.discover])
        group_id = support.get_flow_exploit_group_id()
        manager.suspect_dict[group_id] = [support, future]
        before = self.snapshot(manager)
        trigger = manager.generator.to_flow_exploit(self.trigger())
        plan = manager._plan_alert(trigger)
        self.assertIsNotNone(plan)
        self.assertEqual(self.snapshot(manager), before)
        self.assertIs(plan.source_suspects[0], support)
        self.assertIsNot(plan.recovered_alerts[0], support)
        self.assertEqual(plan.recovered_alerts[0].metric_key, support.metric_key)
        self.assertEqual(plan.recovered_alerts[0].anomaly_score, support.anomaly_score)
        self.assertEqual(plan.recovered_alerts[0].attack_type, self.discover)
        manager._commit_recovery(plan)
        self.assertEqual(support.attack_type, self.wrong)
        self.assertEqual(support.attack_type_alternatives, [self.discover])
        self.assertEqual(manager.suspect_dict[group_id], [future])
        self.assertIs(manager.suspect_dict[group_id][0], future)
        self.assertEqual(manager.get_fns(), list(plan.recovered_alerts))
        _, alerts = manager.get_results()
        self.assertEqual([alert.attack_type for alert in alerts], [self.discover, self.finish])
        self.assertNotIn(Attribute.OTHER, manager.reconstructor.host_dict[TARGET].compromise_attributes)

    def test_invalid_support_alternative_leaves_original_and_state_untouched(self):
        manager = self.make_manager(length_when_log_flow_exploits=0)
        blocked = AttackType('blocked', {Precondition({Attribute.OTHER}, False)}, {Attribute.DISCOVERED})
        support = self.make_flow(attack=self.wrong, attack_types_alternatives=[blocked])
        manager.suspect_dict[support.get_flow_exploit_group_id()] = [support]
        before = self.snapshot(manager)
        requirements = {RecoveryRequirement(blocked, [SOURCE], TARGET)}
        with patch.object(manager.reconstructor, 'compute_requirements', return_value=requirements):
            manager.accept(self.trigger())
        self.assertEqual(self.snapshot(manager), before)
        self.assertEqual(len(manager.get_fps()), 1)

    def test_primary_support_is_preferred_when_both_interpretations_validate(self):
        manager = self.make_manager()
        alternative = AttackType('alternative', set(), {Attribute.DISCOVERED, Attribute.OTHER})
        manager.reconstructor.attack_types.append(alternative)
        support = self.make_flow(attack_types_alternatives=[alternative])
        manager.suspect_dict[support.get_flow_exploit_group_id()] = [support]
        manager.accept(self.trigger())
        self.assertIs(manager.get_fns()[0], support)
        self.assertNotIn(Attribute.OTHER, manager.reconstructor.host_dict[TARGET].compromise_attributes)

    def test_recovery_uses_one_uniform_type_and_leaves_incompatible_flows(self):
        manager = self.make_manager()
        blocked = AttackType('blocked', {Precondition({Attribute.OTHER}, False)}, {Attribute.DISCOVERED})
        bootstrap = AttackType('bootstrap', set(), {Attribute.DISCOVERED, Attribute.OTHER})
        first = self.make_flow(0, attack=self.wrong, attack_types_alternatives=[blocked, bootstrap])
        second = self.make_flow(1, attack=self.wrong, attack_types_alternatives=[blocked])
        group_id = first.get_flow_exploit_group_id()
        manager.suspect_dict[group_id] = [second, first]
        requirements = {RecoveryRequirement(attack, [SOURCE], TARGET) for attack in (blocked, bootstrap)}
        with patch.object(manager.reconstructor, 'compute_requirements', return_value=requirements):
            manager.accept(self.trigger())
        self.assertEqual([flow.attack_type for flow in manager.get_fns()], [bootstrap])
        self.assertEqual(manager.suspect_dict[group_id], [second])
        self.assertEqual(first.attack_type, self.wrong)
        self.assertEqual(second.attack_type, self.wrong)

    def test_retyped_duplicate_occurrences_are_each_consumed_once(self):
        manager = self.make_manager()
        support = self.make_flow(attack=self.wrong, attack_types_alternatives=[self.discover, self.discover])
        group_id = support.get_flow_exploit_group_id()
        manager.suspect_dict[group_id] = [support, support]
        manager.accept(self.trigger())
        self.assertEqual([alert.attack_type for alert in manager.get_fns()], [self.discover, self.discover])
        self.assertEqual(manager.suspect_dict[group_id], [])

    def test_primary_cluster_beats_higher_scoring_alternative_in_another_bucket(self):
        manager = self.make_manager()
        alternative = self.make_flow(0, attack=self.wrong, anomaly_score=0.7,
                                     attack_types_alternatives=[self.discover])
        primary = self.make_flow(1, anomaly_score=0.3)
        # Insert the stronger alternative first to rule out incidental iteration priority.
        manager.suspect_dict = {alternative.get_flow_exploit_group_id(): [alternative, alternative],
                                primary.get_flow_exploit_group_id(): [primary]}
        manager.accept(self.trigger())
        self.assertEqual(manager.get_fns(), [primary])
        self.assertIs(manager.get_fns()[0], primary)
        self.assertEqual(manager.suspect_dict[alternative.get_flow_exploit_group_id()],
                         [alternative, alternative])

    def test_invalid_primary_cluster_allows_valid_alternative_cluster(self):
        manager = self.make_manager()
        blocked = AttackType('blocked', {Precondition({Attribute.OTHER}, False)}, {Attribute.DISCOVERED})
        primary = self.make_flow(0, attack=blocked)
        alternative = self.make_flow(1, attack=self.wrong, attack_types_alternatives=[self.discover])
        manager.suspect_dict = {primary.get_flow_exploit_group_id(): [primary],
                                alternative.get_flow_exploit_group_id(): [alternative]}
        requirements = {RecoveryRequirement(attack, [SOURCE], TARGET) for attack in (blocked, self.discover)}
        with patch.object(manager.reconstructor, 'compute_requirements', return_value=requirements):
            manager.accept(self.trigger())
        self.assertEqual([alert.attack_type for alert in manager.get_fns()], [self.discover])
        self.assertEqual(manager.suspect_dict[primary.get_flow_exploit_group_id()], [primary])
        self.assertEqual(manager.suspect_dict[alternative.get_flow_exploit_group_id()], [])

    def test_projection_filters_before_clustering_so_other_types_cannot_bridge_gap(self):
        manager = self.make_manager()
        other = AttackType('other', set(), {Attribute.DISCOVERED, Attribute.OTHER})
        first = self.make_flow(0, attack=self.wrong, attack_types_alternatives=[self.discover])
        bridge = self.make_flow(2, attack=self.wrong, anomaly_score=0.3,
                                attack_types_alternatives=[other])
        last = self.make_flow(4, attack=self.wrong, attack_types_alternatives=[self.discover])
        group_id = first.get_flow_exploit_group_id()
        manager.suspect_dict[group_id] = [first, bridge, last]
        requirements = {RecoveryRequirement(attack, [SOURCE], TARGET) for attack in (other, self.discover)}
        with patch.object(manager.reconstructor, 'compute_requirements', return_value=requirements):
            manager.accept(self.trigger())
        self.assertEqual([alert.start_time for alert in manager.get_fns()], [last.start_time])
        self.assertEqual(manager.get_fns()[0].attack_type, self.discover)
        self.assertEqual(manager.suspect_dict[group_id], [first, bridge])

    def test_projections_do_not_merge_original_buckets(self):
        manager = self.make_manager()
        weaker = self.make_flow(0, attack=self.wrong, anomaly_score=0.3,
                                attack_types_alternatives=[self.discover])
        stronger = self.make_flow(1, attack=self.unknown, anomaly_score=0.7,
                                  attack_types_alternatives=[self.discover])
        manager.suspect_dict = {weaker.get_flow_exploit_group_id(): [weaker],
                                stronger.get_flow_exploit_group_id(): [stronger]}
        manager.accept(self.trigger())
        self.assertEqual([alert.start_time for alert in manager.get_fns()], [stronger.start_time])
        self.assertEqual(manager.suspect_dict[weaker.get_flow_exploit_group_id()], [weaker])
        self.assertEqual(manager.suspect_dict[stronger.get_flow_exploit_group_id()], [])

    def test_mixed_types_cannot_jointly_satisfy_a_single_step_proposal(self):
        manager = self.make_manager()
        other = AttackType('other', set(), {Attribute.OTHER})
        self.finish.preconditions.add(Precondition({Attribute.OTHER}, False))
        first = self.make_flow(0, attack=self.wrong, attack_types_alternatives=[self.discover, other])
        second = self.make_flow(1, attack=self.wrong, attack_types_alternatives=[self.discover, other])
        manager.suspect_dict[first.get_flow_exploit_group_id()] = [first, second]
        before = self.snapshot(manager)
        # Neither uniform type is sufficient; independently assigning types would succeed.
        requirements = {RecoveryRequirement(attack, [SOURCE], TARGET) for attack in (self.discover, other)}
        with patch.object(manager.reconstructor, 'compute_requirements', return_value=requirements):
            manager.accept(self.trigger())
        self.assertEqual(self.snapshot(manager), before)
        self.assertEqual(len(manager.get_fps()), 1)

    def test_equal_start_support_alternative_cannot_enable_trigger(self):
        manager = self.make_manager()
        support = self.make_flow(10, attack=self.wrong, attack_types_alternatives=[self.discover])
        manager.suspect_dict[support.get_flow_exploit_group_id()] = [support]
        before = self.snapshot(manager)
        manager.accept(self.trigger())
        self.assertEqual(self.snapshot(manager), before)
        self.assertEqual(len(manager.get_fps()), 1)

    def test_retyped_support_is_rejected_when_trigger_remains_unsatisfied(self):
        manager = self.make_manager(length_when_log_flow_exploits=0)
        support = self.make_flow(attack=self.wrong, attack_types_alternatives=[self.discover])
        manager.suspect_dict[support.get_flow_exploit_group_id()] = [support]
        self.finish.preconditions.add(Precondition({Attribute.OTHER}, False))
        before = self.snapshot(manager)
        requirements = {RecoveryRequirement(self.discover, [SOURCE], TARGET)}
        with patch.object(manager.reconstructor, 'compute_requirements', return_value=requirements):
            manager.accept(self.trigger())
        self.assertEqual(self.snapshot(manager), before)
        self.assertEqual(len(manager.get_fps()), 1)

    def test_retyped_support_commit_failure_restores_original_suspect_and_state(self):
        manager = self.make_manager(length_when_log_flow_exploits=0)
        support = self.make_flow(attack=self.wrong, attack_types_alternatives=[self.discover])
        manager.suspect_dict[support.get_flow_exploit_group_id()] = [support]
        before = self.snapshot(manager)
        original_add = manager._add_to_reconstructor

        def failing_add(alert):
            original_add(alert)
            if alert.attack_type == self.finish:
                raise RuntimeError('simulated failure')

        with patch.object(manager, '_add_to_reconstructor', side_effect=failing_add):
            with self.assertRaisesRegex(RuntimeError, 'simulated failure'):
                manager.accept(self.trigger())
        self.assertEqual(self.snapshot(manager), before)
        self.assertIs(manager.suspect_dict[support.get_flow_exploit_group_id()][0], support)

    def test_successful_plan_is_read_only_until_the_whole_batch_is_committed(self):
        manager = self.make_manager(length_when_log_flow_exploits=0)
        manager.accept(self.make_event(score=0.5))
        before = self.snapshot(manager)
        trigger = manager.generator.to_flow_exploit(self.trigger())
        plan = manager._plan_alert(trigger)
        self.assertIsNotNone(plan)
        self.assertEqual(len(plan.recovered_alerts), 1)
        self.assertEqual(self.snapshot(manager), before)
        recovered = manager._commit_recovery(plan)
        self.assertEqual(recovered, list(plan.recovered_alerts))
        self.assertEqual(manager.get_fns(), recovered)
        self.assertIn(Attribute.COMPROMISED, manager.reconstructor.host_dict[TARGET].compromise_attributes)
        dag, alerts = manager.get_results()
        self.assertEqual(alerts, [*recovered, trigger])
        self.assertEqual(len(dag.steps), 2)
        self.assertEqual(len(dag.get_adjacent_pairs()), 1)

    def test_partial_support_that_does_not_enable_trigger_is_not_committed(self):
        manager = self.make_manager(length_when_log_flow_exploits=0, length_when_log_states=0)
        support = self.make_flow()
        manager.suspect_dict[support.get_flow_exploit_group_id()] = [support]
        needs_both = AttackType('needs_both', {
            Precondition({Attribute.DISCOVERED}, False), Precondition({Attribute.OTHER}, False),
        }, {Attribute.COMPROMISED})
        trigger = self.make_flow(10, attack=needs_both)
        before = self.snapshot(manager)
        # The simulated support grants DISCOVERED, but OTHER is still missing at the trigger.
        plan = manager._validate_plan(trigger, [support], support.get_flow_exploit_group_id())
        self.assertIsNone(plan)
        self.assertEqual(self.snapshot(manager), before)

    def test_invalid_supporting_alert_rejects_the_entire_proposed_prefix(self):
        manager = self.make_manager()
        first = self.make_flow()
        blocked_type = AttackType('blocked', {Precondition({Attribute.OTHER}, True)}, {Attribute.OTHER})
        blocked = self.make_flow(2, attack=blocked_type)
        before = self.snapshot(manager)
        trigger = manager.generator.to_flow_exploit(self.trigger())
        # The first alert would enable the trigger, but every selected support must itself be valid.
        self.assertIsNone(manager._validate_plan(trigger, [blocked, first]))
        self.assertEqual(self.snapshot(manager), before)

    def test_unsuccessful_recovery_does_not_change_state_or_consume_suspects(self):
        manager = self.make_manager(length_when_log_flow_exploits=0, length_when_log_states=0)
        manager.accept(self.make_event(score=0.5))
        before = self.snapshot(manager)
        with patch.object(manager, '_recover_fns', return_value=None):
            manager.accept(self.trigger(source_ip='203.0.113.8'))
        self.assertEqual(self.snapshot(manager), before)
        self.assertEqual(len(manager.get_fps()), 1)

    def test_failed_alternative_does_not_publish_its_simulated_postconditions(self):
        manager = self.make_manager(length_when_log_flow_exploits=0)
        manager.accept(self.make_event(score=0.5))
        before = self.snapshot(manager)
        # OTHER cannot be enabled; finish is an alternative requiring recovery.
        self.wrong.preconditions = {Precondition({Attribute.OTHER}, True)}
        event = self.make_event(10, score=0.95, scores={'discover': 0.0, 'wrong': 1.0, 'finish': 0.9})
        with patch.object(manager, '_recover_fns', return_value=None):
            manager.accept(event)
        self.assertEqual(self.snapshot(manager), before)

    def test_invalid_primary_plan_leaves_support_available_to_valid_alternative(self):
        manager = self.make_manager(length_when_log_flow_exploits=0)
        manager.accept(self.make_event(score=0.5))
        self.wrong.preconditions = {
            Precondition({Attribute.DISCOVERED}, False), Precondition({Attribute.COMPROMISED}, False),
        }
        requirement = {RecoveryRequirement(self.discover, [SOURCE], TARGET)}
        # Supply a plausible but insufficient primary proposal to exercise final-state validation.
        with patch.object(manager.reconstructor, 'compute_requirements', return_value=requirement):
            manager.accept(self.make_event(10, score=0.95,
                           scores={'discover': 0.0, 'wrong': 1.0, 'finish': 0.9}))
        self.assertEqual(len(manager.get_fns()), 1)
        _, alerts = manager.get_results()
        self.assertEqual([alert.attack_type for alert in alerts], [self.discover, self.finish])
        self.assertNotIn(Attribute.OTHER, manager.reconstructor.host_dict[TARGET].compromise_attributes)
        self.assertEqual(manager.get_fps(), [])

    def test_invalid_high_score_candidate_does_not_hide_a_lower_valid_candidate(self):
        manager = self.make_manager()
        blocked_type = AttackType('blocked', {Precondition({Attribute.OTHER}, True)}, {Attribute.DISCOVERED})
        blocked = self.make_flow(0, attack=blocked_type, anomaly_score=0.9)
        valid = self.make_flow(1, anomaly_score=0.5)
        manager.suspect_dict = {blocked.get_flow_exploit_group_id(): [blocked],
                                valid.get_flow_exploit_group_id(): [valid]}
        requirements = {RecoveryRequirement(attack, [SOURCE], TARGET)
                        for attack in (blocked_type, self.discover)}
        with patch.object(manager.reconstructor, 'compute_requirements', return_value=requirements):
            manager.accept(self.trigger())
        self.assertEqual(manager.get_fns(), [valid])
        self.assertEqual(manager.suspect_dict[blocked.get_flow_exploit_group_id()], [blocked])
        self.assertIn(Attribute.COMPROMISED, manager.reconstructor.host_dict[TARGET].compromise_attributes)

    def test_future_candidates_are_filtered_before_selecting_the_latest_cluster(self):
        manager = self.make_manager()
        manager.accept(self.make_event(0, score=0.5))
        manager.accept(self.make_event(100, score=0.7))
        manager.accept(self.trigger())
        self.assertEqual([flow.start_time for flow in manager.get_fns()], [self.make_flow(0).start_time])
        remaining = [flow for group in manager.suspect_dict.values() for flow in group]
        self.assertEqual([flow.start_time for flow in remaining], [self.make_flow(100).start_time])

    def test_commit_exception_restores_existing_state_and_leaves_logs_untouched(self):
        manager = self.make_manager(length_when_log_flow_exploits=0, length_when_log_states=0)
        manager.accept(self.make_event(-10, score=0.95, scores={'discover': 0.0, 'wrong': 1.0, 'finish': 0.0}))
        manager.accept(self.make_event(0, score=0.5))
        before = self.snapshot(manager)
        existing_buffers = {key: id(flows) for key, flows in manager.reconstructor.return_flow_exploits().items()}
        original_add = manager._add_to_reconstructor

        def failing_add(alert):
            original_add(alert)
            if alert.attack_type == self.finish:
                raise RuntimeError('simulated commit failure after trigger update')

        with patch.object(manager, '_add_to_reconstructor', side_effect=failing_add):
            with self.assertRaisesRegex(RuntimeError, 'simulated commit failure'):
                manager.accept(self.trigger(source_ip='203.0.113.8'))
        self.assertEqual(self.snapshot(manager), before)
        self.assertEqual({key: id(flows) for key, flows in manager.reconstructor.return_flow_exploits().items()},
                         existing_buffers)

    def test_simulation_exception_cannot_leak_state_or_log_records(self):
        manager = self.make_manager(length_when_log_flow_exploits=0)
        manager.accept(self.make_event(score=0.5))
        before = self.snapshot(manager)
        with patch('scenario_reconstructor.scenario_reconstructor.StarNetworkAttackGraphBasedScenarioReconstructor.set_postconditions',
                   side_effect=RuntimeError('simulated validation failure')):
            with self.assertRaisesRegex(RuntimeError, 'simulated validation failure'):
                manager.accept(self.trigger())
        self.assertEqual(self.snapshot(manager), before)

    def test_archive_error_keeps_the_complete_committed_batch_available(self):
        manager = self.make_manager(length_when_log_flow_exploits=0)
        manager.accept(self.make_event(score=0.5))
        with patch('builtins.open', side_effect=OSError('simulated archive error')):
            with self.assertRaises(OSError):
                manager.accept(self.trigger())
        self.assertEqual(len(manager.get_fns()), 1)
        _, alerts = manager.get_results()
        self.assertEqual([alert.attack_type for alert in alerts], [self.discover, self.finish])
        self.assertIn(Attribute.COMPROMISED, manager.reconstructor.host_dict[TARGET].compromise_attributes)
        self.assertTrue(all(not group for group in manager.suspect_dict.values()))
