"""Isolated unittest lifecycle and reusable fixtures for the entire test suite."""

import ast
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random
import tempfile
import unittest

import numpy as np
import pandas as pd

from events.models import FlowEvent
from scenario_generator.generator import ScenarioGenerator
from scenario_reconstructor.attack_mapper import AttackMapper
from scenario_reconstructor.engine import ScenarioReconstructor
from scenario_reconstructor.manager import ReconstructionManager
from scenario_reconstructor.models import (
    AttackStep,
    AttackType,
    FlowAlert,
    Host,
    HostAttribute,
    Precondition,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)
SOURCE = '10.0.0.1'
TARGET = '10.0.0.2'


class Attribute(HostAttribute):
    DISCOVERED = 'discovered'
    OTHER = 'other'
    COMPROMISED = 'compromised'


class ProjectTestCase(unittest.TestCase):
    """Give every test fresh fixtures, temporary logs, and reproducible randomness.

    Subclasses overriding setUp must call super().setUp(). Factory names use
    make_ so test attributes such as self.manager cannot shadow their helpers.
    """

    def setUp(self):
        super().setUp()
        self.temp = tempfile.TemporaryDirectory(prefix='asr-regression-')
        self.addCleanup(self.temp.cleanup)
        python_state, numpy_state = random.getstate(), np.random.get_state()
        self.addCleanup(random.setstate, python_state)
        self.addCleanup(np.random.set_state, numpy_state)
        random.seed(42)
        np.random.seed(42)
        self.discover = AttackType('discover', set(), {Attribute.DISCOVERED})
        self.wrong = AttackType('wrong', set(), {Attribute.OTHER})
        self.finish = AttackType(
            'finish', {Precondition({Attribute.DISCOVERED}, False)},
            {Attribute.COMPROMISED},
        )
        self.unknown = AttackType('unknown', set(), set())
        self.types = [self.discover, self.wrong, self.finish]

    def log_path(self, name):
        """Return a path in this test's automatically cleaned temporary folder."""
        return str(Path(self.temp.name) / name)

    def make_reconstructor(self, attacks=None, *, internal_hosts=None,
                           external_host_attributes=None, max_idle_gap=timedelta(seconds=1)):
        paths = [self.log_path(name) for name in
                 ('flow_exploits.log', 'states.log')]
        return ScenarioReconstructor(
            [Host(SOURCE), Host(TARGET)] if internal_hosts is None else internal_hosts,
            set() if external_host_attributes is None else external_host_attributes,
            self.types if attacks is None else attacks, *paths,
            max_idle_gap=max_idle_gap,
        )

    def make_manager(self, *, reconstructor=None, mapper=None,
                     unknown_attack=None, **options):
        return ReconstructionManager(
            self.make_reconstructor() if reconstructor is None else reconstructor,
            AttackMapper(self.types, 0.1) if mapper is None else mapper,
            options.pop('suspect_threshold', 0.2),
            options.pop('anomaly_threshold', 0.8),
            self.unknown if unknown_attack is None else unknown_attack, **options,
        )

    def make_flow(self, second=0, attack=None, duration=1,
                  destination_port='80', **overrides):
        fields = dict(
            main_attack_type=self.discover if attack is None else attack,
            attack_types_alternatives=[], source_ip=SOURCE,
            source_port=str(1000 + second), destination_ip=TARGET,
            destination_port=destination_port, protocol='6',
            start_time=EPOCH + timedelta(seconds=second),
            end_time=EPOCH + timedelta(seconds=second + duration), anomaly_score=0.5,
        )
        fields.update(overrides)
        return FlowAlert(**fields)

    def make_event(self, second=0, score=0.5, scores=None, duration=1, **overrides):
        fields = dict(
            source_ip=SOURCE, source_port=str(1000 + second),
            destination_ip=TARGET, destination_port='80', protocol='6',
            start_time=EPOCH + timedelta(seconds=second),
            end_time=EPOCH + timedelta(seconds=second + duration), anomaly_score=score,
            attack_scores={'discover': 1.0, 'wrong': 0.0, 'finish': 0.0}
            if scores is None else scores,
        )
        fields.update(overrides)
        return FlowEvent(**fields)

    def make_step(self, second=0, attack=None, duration=1, size=1,
                  mean=-1, std=-1, **overrides):
        fields = dict(
            attack_type=self.discover if attack is None else attack,
            size=size, source_ip=SOURCE, destination_ip=TARGET,
            start_time=EPOCH + timedelta(seconds=second),
            end_time=EPOCH + timedelta(seconds=second + duration),
            mean_interflow_time=mean, std_interflow_time=std,
        )
        fields.update(overrides)
        return AttackStep(**fields)

    def make_scenario_frame(self, count=2, spacing_ms=1000, duration_ms=250):
        rows = [dict(
            timestamp=EPOCH + timedelta(milliseconds=i * spacing_ms),
            duration=duration_ms, label='discover', step_number=0,
            src_ip=SOURCE, src_port=str(1000 + i), dst_ip=TARGET,
            dst_port='80', protocol='6', anomaly_score=1.0,
        ) for i in range(count)]
        rows.append(dict(rows[0], label='normal', step_number=-1,
                         anomaly_score=0.0, src_port='9000'))
        return pd.DataFrame(rows)

    def make_generator(self, frame=None, **options):
        config = dict(
            dataframe=self.make_scenario_frame() if frame is None else frame,
            next_attack_dict={'start': ['discover'], 'discover': ['end']},
            enable_src_for={}, enable_dst_for={},
            possible_srcs={'discover': [SOURCE]},
            possible_dsts={'discover': [TARGET]}, dst_restricted_atks={},
            final_atk='discover', enabling_atks=[],
        )
        config.update(options)
        return ScenarioGenerator(**config)


def notebook_cells(filename):
    notebook = json.loads((REPO_ROOT / 'jupyter notebook' / filename).read_text(encoding='utf-8'))
    return [''.join(cell.get('source', [])) for cell in notebook['cells']
            if cell['cell_type'] == 'code']


def notebook_function(filename, name, namespace):
    """Compile only the named real function; never execute a whole notebook."""
    for source in notebook_cells(filename):
        tree = ast.parse(source)
        definitions = [node for node in tree.body
                       if isinstance(node, ast.FunctionDef) and node.name == name]
        if definitions:
            module = ast.Module(body=definitions, type_ignores=[])
            exec(compile(module, f'{filename}:{name}', 'exec'), namespace)
            return namespace[name]
    raise AssertionError(f'Notebook function {name!r} was not found in {filename}')
