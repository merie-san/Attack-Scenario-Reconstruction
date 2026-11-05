"""Legacy entry points resolve to the canonical implementations and log readers."""

import subprocess
import sys
from typing import get_type_hints

from metrics import MetricsCalculator
from metrics.causal import causal_quality
from metrics.occurrence import step_recall
from scenario_generator.compute_metrics import MetricsCalculator as LegacyMetricsCalculator
from scenario_reconstructor import models
from scenario_reconstructor.alerts import AlertFactory
from scenario_reconstructor.engine import ScenarioReconstructor
from scenario_reconstructor.manager import ReconstructionManager
from scenario_reconstructor.reconstruction_manager import (
    ExploitGenerator,
    ScenarioReconstructionManager,
)
from scenario_reconstructor.scenario_reconstructor import (
    Exploit,
    ExploitRequirement,
    FlowExploit,
    Preconditions,
    StarNetworkAttackGraphBasedScenarioReconstructor,
    StringToExploitConverter,
    StringToNetworkStateConvertor,
)
from scenario_reconstructor.serialization import AlertStepParser, NetworkStateParser
from tests.support import ProjectTestCase, REPO_ROOT


class TestPublicApiCompatibility(ProjectTestCase):
    def test_legacy_class_names_are_identity_preserving_aliases(self):
        aliases = [
            (FlowExploit, models.FlowAlert), (Exploit, models.AttackStep),
            (Preconditions, models.Precondition), (ExploitRequirement, models.RecoveryRequirement),
            (StarNetworkAttackGraphBasedScenarioReconstructor, ScenarioReconstructor),
            (ScenarioReconstructionManager, ReconstructionManager), (ExploitGenerator, AlertFactory),
            (StringToExploitConverter, AlertStepParser), (StringToNetworkStateConvertor, NetworkStateParser),
        ]
        for legacy, canonical in aliases:
            with self.subTest(name=legacy.__name__):
                self.assertIs(legacy, canonical)
        self.assertIs(get_type_hints(models.AttackStep._matches_context)['value'], models.AttackStep)

    def test_metric_class_api_uses_the_independent_metric_functions(self):
        self.assertIs(LegacyMetricsCalculator, MetricsCalculator)
        self.assertIs(MetricsCalculator.get_scenario_soundness_completeness, causal_quality)
        self.assertIs(MetricsCalculator.get_scenario_step_recall, step_recall)
        steps = [self.make_step()]
        self.assertEqual(MetricsCalculator().get_scenario_step_recall(steps, steps), 1.0)

    def test_established_text_records_restore_canonical_models(self):
        parser = AlertStepParser(self.types)
        alert, step = self.make_flow(), self.make_step()
        self.assertTrue(str(alert).startswith('FlowExploit('))
        self.assertTrue(str(step).startswith('Exploit('))
        self.assertEqual(parser.parse_alert(str(alert)), alert)
        self.assertEqual(parser.from_str_flow_exploit(str(alert)), alert)
        self.assertEqual(parser.parse_step(str(step)), step)
        snapshot = self.make_reconstructor().return_states()[0]
        self.assertEqual(NetworkStateParser(lambda value: value).parse(str(snapshot)), snapshot)

    def test_domain_imports_do_not_load_evaluation_or_training_libraries(self):
        script = (
            'import sys; import scenario_reconstructor; '
            'from scenario_reconstructor.models import FlowAlert; '
            'from scenario_reconstructor.dag import AttackScenarioDAG; '
            'assert not ({"metrics", "pandas", "sklearn"} & sys.modules.keys())'
        )
        result = subprocess.run([sys.executable, '-c', script], cwd=REPO_ROOT,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
