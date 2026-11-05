from datetime import datetime

from scenario_reconstructor.models import Host, NetworkState
from tests.fixtures import NetworkAttribute
from tests.support import ProjectTestCase


class TestNetworkState(ProjectTestCase):

    def setUp(self) -> None:
        super().setUp()
        attribute_dict = {"10.0.0.5": {NetworkAttribute.HOST_DISCOVERED}, "10.0.0.6": {
            NetworkAttribute.PORT_SCANNED}}
        self.state = NetworkState(attribute_dict, datetime(2026, 10, 10, 10))

    def test_to_str(self):
        self.assertEqual(str(
            self.state), "NetworkState(state={10.0.0.5={host_discovered}-10.0.0.6={port_scanned}}, time=2026-10-10T10:00:00)")

    def test_from_dict_of_host(self):
        host1 = Host("10.0.0.5")
        host2 = Host("10.0.0.6")
        host1.update_compromise_attributes(
            {NetworkAttribute.HOST_DISCOVERED})
        host2.update_compromise_attributes(
            {NetworkAttribute.PORT_SCANNED})
        self.assertEqual(NetworkState.from_dict_of_host(
            {"10.0.0.5": host1, "10.0.0.6": host2}, datetime(2026, 10, 10, 10)), self.state)


class TestHost(ProjectTestCase):

    def test_update_compromise_attributes(self):
        host = Host("10.0.0.1")
        self.assertEqual(len(host.compromise_attributes), 0)
        host.update_compromise_attributes(
            {NetworkAttribute.HOST_DISCOVERED})
        self.assertIn(NetworkAttribute.HOST_DISCOVERED,
                      host.compromise_attributes)
