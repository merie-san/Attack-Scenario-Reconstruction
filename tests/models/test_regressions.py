"""Identity, temporal, recovery, persistence, and runtime regression contracts."""

from scenario_reconstructor.models import NetworkState, RecoveryRequirement
from scenario_reconstructor.serialization import NetworkStateParser
from tests.support import Attribute, EPOCH, ProjectTestCase, SOURCE, TARGET


class TestIdentityAndSnapshotContracts(ProjectTestCase):
    def test_B05_destination_port_distinguishes_flow_identity(self):
        self.assertNotEqual(self.make_flow(destination_port='80'), self.make_flow(destination_port='443'),
                            'BUG-05: flows to different destination ports are distinct')

    def test_B05_destination_port_distinguishes_metric_identity(self):
        self.assertNotEqual(self.make_flow(destination_port='80').metric_key,
                            self.make_flow(destination_port='443').metric_key,
                            'BUG-05: metrics must not collapse different destination ports')

    def test_B06_equal_exploits_are_interchangeable_dictionary_keys(self):
        first = self.make_step(mean=1.0, std=2.0)
        nearby = self.make_step(mean=1.00005, std=2.0)
        if first == nearby:
            self.assertIn(nearby, {first: 'same exploit'},
                          'BUG-06: objects comparing equal must share dictionary identity')
        else:
            self.assertTrue(first.approx_match(nearby))

    def test_B06_exploit_equality_is_symmetric_with_unknown_statistics(self):
        unknown = self.make_step(mean=-1, std=-1)
        measured = self.make_step(mean=1, std=2)
        self.assertEqual(unknown == measured, measured == unknown,
                         'BUG-06: sentinel statistics cannot make equality asymmetric')

    def test_B06_exploit_equality_is_transitive(self):
        a, b, c = [self.make_step(mean=mean, std=2) for mean in (1.0, 1.000075, 1.00015)]
        self.assertFalse(a == b and b == c and a != c,
                         'BUG-06: tolerant matching must not be object equality')

    def test_B06_requirement_source_order_and_duplicates_have_consistent_identity(self):
        first = RecoveryRequirement(self.discover, [SOURCE], TARGET)
        duplicate = RecoveryRequirement(self.discover, [SOURCE, SOURCE], TARGET)
        self.assertEqual(first, duplicate)
        self.assertIn(duplicate, {first}, 'BUG-06: equal source sets must hash consistently')

    def test_B07_later_host_changes_do_not_rewrite_historical_state(self):
        rec = self.make_reconstructor()
        original = NetworkState.from_dict_of_host(rec.host_dict, EPOCH)
        rec.host_dict[TARGET].update_compromise_attributes({Attribute.DISCOVERED})
        self.assertEqual(original.state[TARGET], set(),
                         'BUG-07: snapshots must copy mutable host attribute sets')

    def test_B19_empty_host_attributes_round_trip(self):
        state = NetworkState({TARGET: set()}, EPOCH)
        restored = NetworkStateParser(Attribute).from_str(str(state))
        self.assertEqual(restored, state)
