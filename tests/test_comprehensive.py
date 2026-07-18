import unittest

import pandas

from scenario_reconstructor.scenario_reconstructor import FlowExploit, AttackType, \
    StarNetworkAttackGraphBasedScenarioReconstructor, Preconditions, HostAttribute, Host, Exploit
from scenario_reconstructor.attack_mapper import AttackMapper
from event_convertor.flow_event import FlowEvent
from scenario_reconstructor.reconstruction_manager import ExploitGenerator, ScenarioReconstructionManager
from datetime import datetime, timedelta
import os
from scenario_reconstructor.reconstruct_cAPTure import *


class TestComprehensive(unittest.TestCase):

    def setUp(self):
        self.steps = [Exploit(NMAP_10_T5, 2, "10.0.0.2", "10.0.0.17", datetime(2026, 7, 17, 15, 46, 0),
                              datetime(2026, 7, 17, 15, 46, 1), -1, -1),
                      Exploit(BRUTE_FORCE_MALFORMED, 2, "10.0.0.2", "10.0.0.17", datetime(2026, 7, 17, 15, 47, 30),
                              datetime(2026, 7, 17, 15, 47, 31), -1, -1),
                      Exploit(NMAP_BANNER, 2, "10.0.0.17", "10.0.0.1", datetime(2026, 7, 17, 15, 49, 0),
                              datetime(2026, 7, 17, 15, 49, 1), -1, -1),
                      Exploit(NMAP_MQTT, 2, "10.0.0.17", "10.0.0.11", datetime(2026, 7, 17, 15, 50, 0),
                              datetime(2026, 7, 17, 15, 50, 1), -1, -1),
                      Exploit(NMAP_BANNER, 2, "10.0.0.17", "10.0.0.5", datetime(2026, 7, 17, 15, 51, 0),
                              datetime(2026, 7, 17, 15, 51, 1), -1, -1),
                      Exploit(SCP_INST, 1, "10.0.0.2", "10.0.0.17", datetime(2026, 7, 17, 15, 52, 0),
                              datetime(2026, 7, 17, 15, 52, 0), -1, -1),
                      Exploit(DOLLAR_CHAR, 1, "10.0.0.17", "10.0.0.1", datetime(2026, 7, 17, 15, 53, 0),
                              datetime(2026, 7, 17, 15, 53, 0), -1, -1), ]

        scenario_dict = {"timestamp": [
            # nmap_10_T5
            datetime(2026, 7, 17, 15, 46, 0),
            datetime(2026, 7, 17, 15, 46, 1),

            # brute_force_malformed
            datetime(2026, 7, 17, 15, 47, 30),
            datetime(2026, 7, 17, 15, 47, 31),

            # nmap_banner
            datetime(2026, 7, 17, 15, 49, 0),
            datetime(2026, 7, 17, 15, 49, 1),

            # nmap_mqtt
            datetime(2026, 7, 17, 15, 50, 0),
            datetime(2026, 7, 17, 15, 50, 1),

            # nmap_banner
            datetime(2026, 7, 17, 15, 51, 0),
            datetime(2026, 7, 17, 15, 51, 1),

            # scp_inst
            datetime(2026, 7, 17, 15, 52, 0),

            # dollar_char
            datetime(2026, 7, 17, 15, 53, 0),

            # normal flows
            datetime(2026, 7, 17, 15, 45, 0),
            datetime(2026, 7, 17, 15, 45, 5),
            datetime(2026, 7, 17, 15, 45, 10),
            datetime(2026, 7, 17, 15, 45, 15),
            datetime(2026, 7, 17, 15, 45, 20),
            datetime(2026, 7, 17, 15, 45, 25),
            datetime(2026, 7, 17, 15, 45, 30),
            datetime(2026, 7, 17, 15, 45, 35),
            datetime(2026, 7, 17, 15, 45, 40),
            datetime(2026, 7, 17, 15, 45, 45),
            datetime(2026, 7, 17, 15, 45, 50),
            datetime(2026, 7, 17, 15, 45, 55),
        ],

            "label": [
                NMAP_10_T5_NAME,
                NMAP_10_T5_NAME,

                BRUTE_FORCE_MALFORMED_NAME,
                BRUTE_FORCE_MALFORMED_NAME,

                NMAP_BANNER_NAME,
                NMAP_BANNER_NAME,

                NMAP_MQTT_NAME,
                NMAP_MQTT_NAME,

                NMAP_BANNER_NAME,
                NMAP_BANNER_NAME,

                SCP_INST_NAME,

                DOLLAR_CHAR_NAME,

                "normal", "normal", "normal", "normal",
                "normal", "normal", "normal", "normal",
                "normal", "normal", "normal", "normal",
            ],

            "step_number": [
                0, 0,
                1, 1,
                2, 2,
                3, 3,
                4, 4,
                5,
                6,
                -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1,
            ],

            "src_ip": [
                "10.0.0.2", "10.0.0.2",
                "10.0.0.2", "10.0.0.2",
                "10.0.0.17", "10.0.0.17",
                "10.0.0.17", "10.0.0.17",
                "10.0.0.17", "10.0.0.17",
                "10.0.0.2",
                "10.0.0.17",

                "10.0.0.4", "10.0.0.5", "10.0.0.6",
                "10.0.0.7", "10.0.0.8", "10.0.0.9",
                "10.0.0.10", "10.0.0.11", "10.0.0.12",
                "10.0.0.13", "10.0.0.14", "10.0.0.15",
            ],

            "dst_ip": [
                "10.0.0.17", "10.0.0.17",
                "10.0.0.17", "10.0.0.17",
                "10.0.0.1", "10.0.0.1",
                "10.0.0.11", "10.0.0.11",
                "10.0.0.5", "10.0.0.5",
                "10.0.0.17",
                "10.0.0.1",

                "10.0.0.5", "10.0.0.6", "10.0.0.7",
                "10.0.0.8", "10.0.0.9", "10.0.0.10",
                "10.0.0.11", "10.0.0.12", "10.0.0.13",
                "10.0.0.14", "10.0.0.15", "10.0.0.16",
            ],

            "src_port": [
                "40000", "40001",
                "40100", "40101",
                "40200", "40201",
                "40300", "40301",
                "40400", "40401",
                "40500",
                "40600",

                "50000", "50001", "50002", "50003",
                "50004", "50005", "50006", "50007",
                "50008", "50009", "50010", "50011",
            ],

            "dst_port": [
                "22", "22",
                "22", "22",
                "1883", "1883",
                "1883", "1883",
                "1883", "1883",
                "22",
                "1883",

                "1883", "1883", "1883", "1883",
                "1883", "1883", "1883", "1883",
                "1883", "1883", "1883", "1883",
            ],

            "protocol": [
                "6", "6",
                "6", "6",
                "6", "6",
                "6", "6",
                "6", "6",
                "6",
                "6",

                "6", "6", "6", "6",
                "6", "6", "6", "6",
                "6", "6", "6", "6",
            ],

            "duration": [
                10, 10,
                50, 50,
                10, 10,
                10, 10,
                10, 10,
                100,
                100,

                10, 10, 10, 10,
                10, 10, 10, 10,
                10, 10, 10, 10,
            ],

            # Generic anomaly score used by the detector.
            "anomaly_score": [
                1, 1,  # nmap_10_T5
                1, 1,  # brute_force_malformed
                1, 1,  # nmap_banner
                1, 1,  # nmap_mqtt
                1, 1,  # nmap_banner
                1,  # scp_inst
                1,  # dollar_char

                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],

            # Per-attack classifier scores.
            "nmap_10_T5": [
                1, 1,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0,
                0,

                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],

            "nmap_mqtt": [
                0, 0,
                0, 0,
                0, 0,
                1, 1,
                0, 0,
                0,
                0,

                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],

            "nmap_banner": [
                0, 0,
                0, 0,
                1, 1,
                0, 0,
                1, 1,
                0,
                0,

                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],

            "brute_force_malformed": [
                0, 0,
                1, 1,
                0, 0,
                0, 0,
                0, 0,
                0,
                0,

                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],

            "dollar_char": [
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0,
                1,

                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],

            "scp_inst": [
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                1,
                0,

                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ]}
        self.scenario_df = pandas.DataFrame(scenario_dict)
        self.scenario_df = self.scenario_df.sort_values(by="timestamp")
        self.flow_convertor = CAPTureFlowEventConvertor()
        self.mapper = AttackMapper(ATK_TYPES, 0)
        self.reconstructor = StarNetworkAttackGraphBasedScenarioReconstructor(HOSTS,
                                                                              {DollarCharHostAttributes.START_MACHINE},
                                                                              ATK_TYPES, "../data/exploits.log",
                                                                              "../data/flow_exploits.log",
                                                                              "../data/states.log",
                                                                              "../data/correlations.log")
        self.manager = ScenarioReconstructionManager(self.reconstructor, self.mapper, 0.1, 0.9,
                                                     UNDETERMINED)
        self.flow_convertor = CAPTureFlowEventConvertor()

        self.alerts = [FlowExploit(NMAP_10_T5, [], "10.0.0.2", "40000", "10.0.0.17", "22", "6",
                                   datetime(2026, 7, 17, 15, 46, 0),
                                   datetime(2026, 7, 17, 15, 46, 0) + timedelta(milliseconds=10), 1, ),
                       FlowExploit(NMAP_10_T5, [], "10.0.0.2", "40001", "10.0.0.17", "22", "6",
                                   datetime(2026, 7, 17, 15, 46, 1),
                                   datetime(2026, 7, 17, 15, 46, 1) + timedelta(milliseconds=10),
                                   1, ),
                       FlowExploit(BRUTE_FORCE_MALFORMED, [], "10.0.0.2", "40100", "10.0.0.17", "22", "6",
                                   datetime(2026, 7, 17, 15, 47, 30),
                                   datetime(2026, 7, 17, 15, 47, 30) + timedelta(milliseconds=50), 1, ),
                       FlowExploit(BRUTE_FORCE_MALFORMED, [], "10.0.0.2", "40101", "10.0.0.17", "22", "6",
                                   datetime(2026, 7, 17, 15, 47, 31),
                                   datetime(2026, 7, 17, 15, 47, 31) + timedelta(milliseconds=50), 1, ),
                       FlowExploit(NMAP_BANNER, [], "10.0.0.17", "40200", "10.0.0.1", "1883", "6",
                                   datetime(2026, 7, 17, 15, 49, 0),
                                   datetime(2026, 7, 17, 15, 49, 0) + timedelta(milliseconds=10), 1, ),
                       FlowExploit(NMAP_BANNER, [], "10.0.0.17", "40201", "10.0.0.1", "1883", "6",
                                   datetime(2026, 7, 17, 15, 49, 1),
                                   datetime(2026, 7, 17, 15, 49, 1) + timedelta(milliseconds=10), 1, ),
                       FlowExploit(NMAP_MQTT, [], "10.0.0.17", "40300", "10.0.0.11", "1883", "6",
                                   datetime(2026, 7, 17, 15, 50, 0),
                                   datetime(2026, 7, 17, 15, 50, 0) + timedelta(milliseconds=10), 1, ),
                       FlowExploit(NMAP_MQTT, [], "10.0.0.17", "40301", "10.0.0.11", "1883", "6",
                                   datetime(2026, 7, 17, 15, 50, 1),
                                   datetime(2026, 7, 17, 15, 50, 1) + timedelta(milliseconds=10), 1, ),
                       FlowExploit(NMAP_BANNER, [], "10.0.0.17", "40400", "10.0.0.5", "1883", "6",
                                   datetime(2026, 7, 17, 15, 51, 0),
                                   datetime(2026, 7, 17, 15, 51, 0) + timedelta(milliseconds=10), 1, ),
                       FlowExploit(NMAP_BANNER, [], "10.0.0.17", "40401", "10.0.0.5", "1883", "6",
                                   datetime(2026, 7, 17, 15, 51, 1),
                                   datetime(2026, 7, 17, 15, 51, 1) + timedelta(milliseconds=10), 1, ),
                       FlowExploit(SCP_INST, [], "10.0.0.2", "40500", "10.0.0.17", "22", "6",
                                   datetime(2026, 7, 17, 15, 52, 0),
                                   datetime(2026, 7, 17, 15, 52, 0) + timedelta(milliseconds=100), 1, ),
                       FlowExploit(DOLLAR_CHAR, [], "10.0.0.17", "40600", "10.0.0.1", "1883", "6",
                                   datetime(2026, 7, 17, 15, 53, 0),
                                   datetime(2026, 7, 17, 15, 53, 0) + timedelta(milliseconds=100), 1, ), ]

    def test_reconstructor(self):
        t_flows = self.flow_convertor.convert(self.scenario_df)

        for t_flow in t_flows:
            self.manager.accept(t_flow)

        p_steps_t, p_alerts_t = self.manager.get_results()

        self.assertEqual(len(p_alerts_t), len(self.alerts))

        for i in range(len(p_steps_t)):
            self.assertTrue(any(p_steps_t[i].approx_match_no_timing(self.steps[j]) for j in range(len(self.steps))))

        for i in range(len(p_alerts_t)):
            self.assertEqual(p_alerts_t[i], self.alerts[i])
