import argparse
import os

import pandas as pd
import numpy as np
from scenario_generator.scenario_generator import CAPTureScenarioGenerator
from event_convertor.flow_event_generator import CAPTureFlowEventConvertor
from attack_mapper import AttackMapper
from reconstruction_manager import ScenarioReconstructionManager
from scenario_reconstructor.scenario_reconstructor import HostAttribute, Preconditions, Host, AttackType, \
    StarNetworkAttackGraphBasedScenarioReconstructor
from scenario_generator.compute_metrics import MetricsCalculator

NEXT_ATTACK_DICT = {"start": ["nmap_10_T5"], "nmap_10_T5": ["nmap_10_T5", "brute_force_malformed"],
                    "nmap_mqtt": ["nmap_mqtt", "nmap_banner", "brute_force_malformed", "scp_inst"],
                    "nmap_banner": ["nmap_mqtt", "nmap_banner", "brute_force_malformed", "scp_inst"],
                    "brute_force_malformed": ["brute_force_malformed", "nmap_mqtt", "nmap_banner"],
                    "dollar_char": ["end"], "scp_inst": ["dollar_char"]}

ENABLE_SRC_FOR = {"brute_force_malformed": ["nmap_mqtt", "nmap_banner"],
                  "scp_inst": ["dollar_char"]}

ENABLE_DST_FOR = {"nmap_10_T5": ["brute_force_malformed"], "brute_force_malformed": ["nmap_mqtt", "nmap_banner"],
                  "nmap_banner": ["dollar_char"], "nmap_mqtt": ["dollar_char"]}

IP_LIST = ["10.0.0." + str(n) for n in range(1, 24)]

IP_LIST.remove("10.0.0.3")

POSSIBLE_SRCS = {"nmap_10_T5": ["10.0.0.2"],
                 "nmap_mqtt": [],
                 "nmap_banner": [],
                 "brute_force_malformed": ["10.0.0.2"],
                 "dollar_char": [], "scp_inst": ["10.0.0.2"]}

POSSIBLE_DSTS = {"nmap_10_T5": [ip for ip in IP_LIST],
                 "nmap_mqtt": [ip for ip in IP_LIST],
                 "nmap_banner": [ip for ip in IP_LIST],
                 "brute_force_malformed": [],
                 "dollar_char": [], "scp_inst": []}

DST_RESTRICTED_ATKS = {"dollar_char": ["10.0.0.1"]}

FINAL_ATK = "dollar_char"
ENABLE_ATKS = ["nmap_mqtt", "nmap_banner"]


class DollarCharHostAttributes(HostAttribute):
    START_MACHINE = "start_machine"
    SSH_DISCOVERED = "ssh_discovered"
    SSH_COMPROMISED = "ssh_compromised"
    MQTT_MACHINE = "mqtt_machine"
    MQTT_DISCOVERED = "mqtt_discovered"
    BROKER_MACHINE = "broker_machine"
    SCRIPTS_INSTALLED = "scripts_installed"
    CRASHED = "crashed"


NMAP_10_T5 = AttackType("nmap_10_T5", {Preconditions({DollarCharHostAttributes.START_MACHINE}, True)},
                        {DollarCharHostAttributes.SSH_DISCOVERED})
NMAP_MQTT = AttackType("nmap_mqtt", {Preconditions({DollarCharHostAttributes.SSH_COMPROMISED}, True)},
                       {DollarCharHostAttributes.MQTT_DISCOVERED})
NMAP_BANNER = AttackType("nmap_mqtt", {Preconditions({DollarCharHostAttributes.SSH_COMPROMISED}, True)},
                         {DollarCharHostAttributes.MQTT_DISCOVERED})
BRUTE_FORCE_MALFORMED = AttackType("brute_force_malformed",
                                   {Preconditions({DollarCharHostAttributes.START_MACHINE}, True),
                                    Preconditions({DollarCharHostAttributes.SSH_DISCOVERED}, False)},
                                   {DollarCharHostAttributes.SSH_COMPROMISED})
DOLLAR_CHAR = AttackType("dollar_char", {Preconditions({DollarCharHostAttributes.MQTT_MACHINE}, True),
                                         Preconditions({DollarCharHostAttributes.SSH_COMPROMISED}, True),
                                         Preconditions({DollarCharHostAttributes.SCRIPTS_INSTALLED}, True),
                                         Preconditions({DollarCharHostAttributes.MQTT_DISCOVERED}, False),
                                         Preconditions({DollarCharHostAttributes.BROKER_MACHINE}, False)},
                         {DollarCharHostAttributes.CRASHED})
SCP_INST = AttackType("scp_inst", {Preconditions({DollarCharHostAttributes.START_MACHINE}, True),
                                   Preconditions({DollarCharHostAttributes.SSH_COMPROMISED}, False)},
                      {DollarCharHostAttributes.SCRIPTS_INSTALLED})
UNDETERMINED = AttackType("undetermined", {Preconditions(
    {DollarCharHostAttributes.START_MACHINE, DollarCharHostAttributes.SSH_COMPROMISED}, True)},
                          {DollarCharHostAttributes.SSH_DISCOVERED, DollarCharHostAttributes.MQTT_DISCOVERED,
                           DollarCharHostAttributes.SSH_COMPROMISED, DollarCharHostAttributes.CRASHED,
                           DollarCharHostAttributes.SCRIPTS_INSTALLED})
ATK_TYPES = [NMAP_MQTT, NMAP_10_T5, NMAP_BANNER, BRUTE_FORCE_MALFORMED, DOLLAR_CHAR, SCP_INST]

HOSTS = [Host(ip) for ip in IP_LIST if ip != "10.0.0.1" and ip != "10.0.0.2"]
for host in HOSTS:
    host.update_compromise_attributes({DollarCharHostAttributes.MQTT_MACHINE})
BROKER = Host("10.0.0.1")
BROKER.update_compromise_attributes({DollarCharHostAttributes.BROKER_MACHINE})
HOSTS.append(BROKER)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="reconstructScenario",
                                     description="Reconstruct scenarios and compute metrics from the cAPTure dataset, with provided macros defined in the same python file")
    parser.add_argument("-f", "--file", required=True, help="file name")
    parser.add_argument("-t", "--times", required=True, help="number of evaluation cycles", default=100, type=int)
    parser.add_argument("--anomaly-threshold", required=True, help="threshold for alert generation", default=0.8,
                        type=float)
    parser.add_argument("--suspect-threshold", required=True, help="threshold for suspicion addition", default=0.4,
                        type=float)
    parser.add_argument("--type-threshold", required=True, help="threshold for attack type mapping", default=0.2,
                        type=float)
    args = parser.parse_args()
    if args.anomaly_threshold <= 0 or args.suspect_threshold < 0:
        raise argparse.ArgumentTypeError(
            f"Illegal threshold value: anomaly_threshold-{args.anomaly_threshold} suspect_threshold-{args.suspect_threshold}")
    if not args.file.endswith(".csv"):
        raise argparse.ArgumentTypeError("File must be a csv file")
    if not os.path.exists(args.file):
        raise argparse.ArgumentTypeError("File does not exist")
    reconstruction_df = pd.read_csv(args.file)
    reconstruction_df = reconstruction_df.sort_values(by="timestamp")
    generator = CAPTureScenarioGenerator(reconstruction_df, NEXT_ATTACK_DICT, IP_LIST, ENABLE_SRC_FOR, ENABLE_DST_FOR,
                                         POSSIBLE_SRCS, POSSIBLE_DSTS, DST_RESTRICTED_ATKS, FINAL_ATK, ENABLE_ATKS)
    flow_convertor = CAPTureFlowEventConvertor()
    metrics_calc = MetricsCalculator()
    mapper = AttackMapper(ATK_TYPES, args.type_threshold)
    reconstructor = StarNetworkAttackGraphBasedScenarioReconstructor(HOSTS, {DollarCharHostAttributes.START_MACHINE},
                                                                     ATK_TYPES, "../data/exploits.log",
                                                                     "../data/flow_exploits.log", "../data/states.log",
                                                                     "../data/correlations.log")
    manager = ScenarioReconstructionManager(reconstructor, mapper, args.suspect_threshold, args.anomaly_threshold,
                                            UNDETERMINED)

    delta_tn_perc_list = []
    delta_fp_perc_list = []
    delta_fn_perc_list = []
    delta_tp_perc_list = []
    soundness_list = []
    completeness_list = []
    exact_matches = 0
    approx_matches = 0
    order_matches = 0
    u_order_matches = 0
    box_matches = 0
    u_box_matches = 0
    end_step_matches = 0

    print("starting to run the iterations...")

    for i in range(args.times):
        print("generating new scenario...")
        scenario_df = generator.generate_scenario(10)
        steps, alerts = generator.export_results(ATK_TYPES, mapper)
        print("converting scenario in flow objects...")
        flows = flow_convertor.convert(scenario_df)
        print("reconstructing scenario from flow objects...")
        for flow in flows:
            manager.accept(flow)
        print("calculating metrics...")
        p_steps, p_alerts = manager.get_results()
        manager.reset()
        tn, fp, fn, tp = metrics_calc.get_detection_confusion_matrix_capture(scenario_df, args.anomaly_threshold)
        tn_r, fp_r, fn_r, tp_r = metrics_calc.get_reconstruction_confusion_matrix_capture(scenario_df, p_alerts)
        delta_tn_perc_list.append((tn - tn_r) * 100 / tn)
        delta_fp_perc_list.append((fp - fp_r) * 100 / fp)
        delta_fn_perc_list.append((fn - fn_r) * 100 / fn)
        delta_tp_perc_list.append((tp - tp_r) * 100 / tp)
        soundness_list.append(metrics_calc.get_soundness(p_steps, steps, p_alerts, alerts))
        completeness_list.append(metrics_calc.get_completeness(p_steps, steps, p_alerts, alerts))
        exact_matches += int(metrics_calc.scenario_exact_full_match(p_steps, steps))
        approx_matches += int(metrics_calc.scenario_approx_full_match(p_steps, steps))
        order_matches += int(metrics_calc.scenario_full_order_match(p_steps, steps))
        u_order_matches += int(metrics_calc.scenario_unique_order_match(p_steps, steps))
        box_matches += int(metrics_calc.scenario_full_box_match(p_steps, steps))
        u_box_matches += int(metrics_calc.scenario_unique_box_match(p_steps, steps))
        end_step_matches += int(metrics_calc.scenario_end_step_match(p_steps, steps))

    print(f"mean percentage of true negative deviation of reconstruction results from initial intrusion detection results: {float(np.mean(delta_tn_perc_list)):.3f}")
    print(
        f"mean percentage of false positives deviation of reconstruction results from initial intrusion detection results: {float(np.mean(delta_fp_perc_list)):.3f}")
    print(
        f"mean percentage of false negatives deviation of reconstruction results from initial intrusion detection results: {float(np.mean(delta_fn_perc_list)):.3f}")
    print(
        f"mean percentage of true negatives deviation of reconstruction results from initial intrusion detection results: {float(np.mean(delta_tp_perc_list)):.3f}")
    print(f"mean soundness of reconstructed steps: {float(np.mean(soundness_list)):.3f}")
    print(f"mean completeness of reconstructed steps: {float(np.mean(completeness_list)):.3f}")
    print(f"percentage of exact matches: {exact_matches*100/args.times:.3f}")
    print(f"percentage of approximate matches: {approx_matches * 100 / args.times:.3f}")
    print(f"percentage of order matches: {order_matches * 100 / args.times:.3f}")
    print(f"percentage of order matches without repetition: {u_box_matches * 100 / args.times:.3f}")
    print(f"percentage of box matches: {box_matches * 100 / args.times:.3f}")
    print(f"percentage of box matches without repetition: {u_box_matches * 100 / args.times:.3f}")
    print(f"percentage of end-step matches: {end_step_matches * 100 / args.times:.3f}")