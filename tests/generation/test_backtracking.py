"""Feasible hierarchical choices, bounded retries, and caller-visible failures."""

from copy import deepcopy
from unittest.mock import patch

import pandas as pd

from scenario_generator import NoFeasibleScenarioError, ScenarioGenerationError, ScenarioSearchLimitError
from tests.support import ProjectTestCase, SOURCE, TARGET


class TestScenarioBacktracking(ProjectTestCase):
    def frame(self, *attacks):
        base = self.make_scenario_frame()
        normal = base[base['label'] == 'normal']
        template = base[base['label'] != 'normal']
        return pd.concat([normal, *(template.assign(label=attack) for attack in attacks)], ignore_index=True)

    def choose_first(self, values):
        return list(values)[0]

    def test_invalid_sources_and_transitions_are_filtered_before_sampling(self):
        generator = self.make_generator(
            self.frame('blocked', 'discover'),
            next_attack_dict={'start': ['blocked', 'discover'], 'discover': ['end']},
            possible_srcs={'blocked': [SOURCE], 'discover': [TARGET, SOURCE]},
            possible_dsts={'blocked': [SOURCE], 'discover': [TARGET]},
        )
        with patch('scenario_generator.search.random.choice', side_effect=self.choose_first):
            generator.generate_scenario()
        self.assertEqual(generator.attack_names, ['discover'])
        self.assertEqual(generator.attack_ips, [(SOURCE, TARGET)])

    def test_backtracking_restores_enabled_hosts_and_tries_another_destination(self):
        bad, good = '10.0.0.3', '10.0.0.4'
        generator = self.make_generator(
            self.frame('seed', 'bridge', 'finish'),
            next_attack_dict={'start': ['seed'], 'seed': ['bridge'], 'bridge': ['finish'], 'finish': ['end']},
            possible_srcs={'seed': [SOURCE], 'bridge': [], 'finish': [SOURCE]},
            possible_dsts={'seed': [bad, good], 'bridge': [bad], 'finish': []},
            enable_src_for={'seed': ['bridge']}, enable_dst_for={'seed': ['finish']},
            final_atk='finish',
        )
        sources, destinations = deepcopy(generator.possible_srcs), deepcopy(generator.possible_dsts)
        with patch('scenario_generator.search.random.choice', side_effect=self.choose_first):
            generator.generate_scenario()
        self.assertEqual(generator.attack_names, ['seed', 'bridge', 'finish'])
        self.assertEqual(generator.attack_ips, [(SOURCE, good), (good, bad), (SOURCE, good)])
        self.assertEqual(generator.possible_srcs, sources)
        self.assertEqual(generator.possible_dsts, destinations)

    def test_final_enabling_constraint_is_applied_before_sampling(self):
        generator = self.make_generator(
            self.frame('discover', 'finish'),
            next_attack_dict={'start': ['discover'], 'discover': ['finish'], 'finish': ['end']},
            possible_srcs={'discover': [SOURCE], 'finish': [SOURCE]},
            possible_dsts={'discover': ['10.0.0.3', TARGET], 'finish': []},
            enable_dst_for={'discover': ['finish']},
            dst_restricted_atks={'finish': [TARGET]}, enabling_atks=['discover'], final_atk='finish',
        )
        with patch('scenario_generator.search.random.choice', side_effect=self.choose_first):
            generator.generate_scenario()
        self.assertEqual(generator.attack_ips, [(SOURCE, TARGET), (SOURCE, TARGET)])

    def test_exhausted_choices_raise_infeasibility_not_a_limit_error(self):
        generator = self.make_generator(next_attack_dict={'start': ['discover'], 'discover': []})
        with self.assertRaises(NoFeasibleScenarioError) as failure:
            generator.generate_scenario()
        self.assertIsInstance(failure.exception, ScenarioGenerationError)
        self.assertTrue(generator.result.empty)
        self.assertEqual(generator.attack_names, [])

    def test_impossible_host_pair_is_rejected_with_an_available_template(self):
        generator = self.make_generator(possible_dsts={'discover': [SOURCE]})
        with self.assertRaises(NoFeasibleScenarioError):
            generator.generate_scenario()

    def test_impossible_enabling_target_is_rejected_instead_of_retrying_forever(self):
        generator = self.make_generator(
            possible_dsts={'discover': [TARGET], 'finish': []},
            dst_restricted_atks={'finish': ['10.0.0.9']},
            enabling_atks=['discover'], final_atk='finish',
        )
        with self.assertRaises(NoFeasibleScenarioError):
            generator.generate_scenario()

    def test_cycle_without_end_reports_depth_limit(self):
        generator = self.make_generator(next_attack_dict={'start': ['discover'], 'discover': ['discover']})
        with self.assertRaises(ScenarioSearchLimitError) as failure:
            generator.generate_scenario(max_steps=3)
        self.assertEqual(failure.exception.limit_name, 'max_steps')
        self.assertEqual(failure.exception.limit, 3)
        self.assertIsInstance(failure.exception, ScenarioGenerationError)
        self.assertEqual(generator.attack_names, [])

    def test_depth_pruned_branch_does_not_prevent_finding_a_shorter_scenario(self):
        generator = self.make_generator(
            self.frame('loop', 'discover'),
            next_attack_dict={'start': ['loop', 'discover'], 'loop': ['loop'], 'discover': ['end']},
            possible_srcs={'loop': [SOURCE], 'discover': [SOURCE]},
            possible_dsts={'loop': [TARGET], 'discover': [TARGET]},
        )
        with patch('scenario_generator.search.random.choice', side_effect=self.choose_first):
            generator.generate_scenario(max_steps=2)
        self.assertEqual(generator.attack_names, ['discover'])

    def test_attempt_limit_does_not_claim_an_untried_branch_is_impossible(self):
        generator = self.make_generator(
            self.frame('loop', 'discover'),
            next_attack_dict={'start': ['loop', 'discover'], 'loop': ['loop'], 'discover': ['end']},
            possible_srcs={'loop': [SOURCE], 'discover': [SOURCE]},
            possible_dsts={'loop': [TARGET], 'discover': [TARGET]},
        )
        with patch('scenario_generator.search.random.choice', side_effect=self.choose_first):
            with self.assertRaises(ScenarioSearchLimitError) as failure:
                generator.generate_scenario(max_search_attempts=2)
        self.assertEqual(failure.exception.limit_name, 'max_search_attempts')
        self.assertEqual(failure.exception.limit, 2)
        self.assertEqual(failure.exception.attempts, 2)

    def test_end_is_allowed_at_the_step_limit_and_directly_from_start(self):
        generator = self.make_generator()
        generator.generate_scenario(max_steps=1, max_search_attempts=2)
        self.assertEqual(generator.attack_names, ['discover'])
        generator.next_attack_dict = {'start': ['end']}
        result = generator.generate_scenario()
        self.assertTrue(result['label'].eq('normal').all())
        self.assertEqual(generator.attack_names, [])
        self.assertEqual(generator.export_results([self.discover]), ([], []))

    def test_failed_request_preserves_last_completed_scenario(self):
        generator = self.make_generator()
        previous = generator.generate_scenario()
        exported = generator.export_results([self.discover])
        names, times = list(generator.attack_names), list(generator.attack_times)
        generator.next_attack_dict = {'start': ['missing']}
        with self.assertRaises(NoFeasibleScenarioError):
            generator.generate_scenario()
        self.assertIs(generator.result, previous)
        self.assertEqual(generator.attack_names, names)
        self.assertEqual(generator.attack_times, times)
        self.assertEqual(generator.export_results([self.discover]), exported)

    def test_search_limits_must_be_positive_integers(self):
        generator = self.make_generator()
        for options, error in (({'max_steps': 0}, ValueError), ({'max_search_attempts': -1}, ValueError),
                               ({'max_steps': 1.5}, TypeError)):
            with self.subTest(options=options):
                with self.assertRaises(error):
                    generator.generate_scenario(**options)
