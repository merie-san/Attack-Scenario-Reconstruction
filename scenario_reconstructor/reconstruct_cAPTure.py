import argparse
import os
import pandas as pd
import numpy as np
from scenario_generator.scenario_generator import CAPTureScenarioGenerator
from event_convertor.flow_event_generator import CAPTureFlowEventConvertor
from scenario_reconstructor.attack_mapper import AttackMapper
from scenario_reconstructor.reconstruction_manager import ScenarioReconstructionManager
from scenario_reconstructor.scenario_reconstructor import HostAttribute, Preconditions, Host, AttackType, \
    StarNetworkAttackGraphBasedScenarioReconstructor
from scenario_generator.compute_metrics import MetricsCalculator

SCP_INST_NAME = "scp_inst"

DOLLAR_CHAR_NAME = "dollar_char"

BRUTE_FORCE_MALFORMED_NAME = "brute_force_malformed"

NMAP_BANNER_NAME = "nmap_banner"

NMAP_MQTT_NAME = "nmap_mqtt"

NMAP_10_T5_NAME = "nmap_10_T5"

NEXT_ATTACK_DICT = {"start": [NMAP_10_T5_NAME], NMAP_10_T5_NAME: [NMAP_10_T5_NAME, BRUTE_FORCE_MALFORMED_NAME],
                    NMAP_MQTT_NAME: [NMAP_MQTT_NAME, NMAP_BANNER_NAME, BRUTE_FORCE_MALFORMED_NAME, SCP_INST_NAME],
                    NMAP_BANNER_NAME: [NMAP_MQTT_NAME, NMAP_BANNER_NAME, BRUTE_FORCE_MALFORMED_NAME, SCP_INST_NAME],
                    BRUTE_FORCE_MALFORMED_NAME: [BRUTE_FORCE_MALFORMED_NAME, NMAP_MQTT_NAME, NMAP_BANNER_NAME],
                    DOLLAR_CHAR_NAME: ["end"], SCP_INST_NAME: [DOLLAR_CHAR_NAME]}

ENABLE_SRC_FOR = {BRUTE_FORCE_MALFORMED_NAME: [NMAP_MQTT_NAME, NMAP_BANNER_NAME],
                  SCP_INST_NAME: [DOLLAR_CHAR_NAME]}

ENABLE_DST_FOR = {NMAP_10_T5_NAME: [BRUTE_FORCE_MALFORMED_NAME],
                  BRUTE_FORCE_MALFORMED_NAME: [NMAP_MQTT_NAME, NMAP_BANNER_NAME,
                                               SCP_INST_NAME],
                  NMAP_BANNER_NAME: [DOLLAR_CHAR_NAME], NMAP_MQTT_NAME: [DOLLAR_CHAR_NAME]}

IP_LIST = ["10.0.0." + str(n) for n in range(1, 24)]

IP_LIST.remove("10.0.0.3")

SUBNET_IPS = ["10.0.0." + str(n) for n in range(1, 24) if n != 2 and n != 3]

MQTT_NODE_IPS = ["10.0.0." + str(n) for n in range(4, 24)]

POSSIBLE_SRCS = {NMAP_10_T5_NAME: ["10.0.0.2"],
                 NMAP_MQTT_NAME: [],
                 NMAP_BANNER_NAME: [],
                 BRUTE_FORCE_MALFORMED_NAME: ["10.0.0.2"],
                 DOLLAR_CHAR_NAME: [], SCP_INST_NAME: ["10.0.0.2"]}

POSSIBLE_DSTS = {NMAP_10_T5_NAME: [ip for ip in IP_LIST],
                 NMAP_MQTT_NAME: [ip for ip in IP_LIST],
                 NMAP_BANNER_NAME: [ip for ip in IP_LIST],
                 BRUTE_FORCE_MALFORMED_NAME: [],
                 DOLLAR_CHAR_NAME: [], SCP_INST_NAME: []}

DST_RESTRICTED_ATKS = {DOLLAR_CHAR_NAME: ["10.0.0.1"], NMAP_10_T5_NAME: SUBNET_IPS, NMAP_MQTT_NAME: SUBNET_IPS,
                       NMAP_BANNER_NAME: SUBNET_IPS, BRUTE_FORCE_MALFORMED_NAME: MQTT_NODE_IPS,
                       SCP_INST_NAME: MQTT_NODE_IPS}

FINAL_ATK = DOLLAR_CHAR_NAME
ENABLE_ATKS = [NMAP_MQTT_NAME, NMAP_BANNER_NAME]


class DollarCharHostAttributes(HostAttribute):
    START_MACHINE = "start_machine"
    SSH_DISCOVERED = "ssh_discovered"
    SSH_COMPROMISED = "ssh_compromised"
    MQTT_MACHINE = "mqtt_machine"
    MQTT_DISCOVERED = "mqtt_discovered"
    BROKER_MACHINE = "broker_machine"
    SCRIPTS_INSTALLED = "scripts_installed"
    CRASHED = "crashed"


NMAP_10_T5 = AttackType(NMAP_10_T5_NAME, {Preconditions({DollarCharHostAttributes.START_MACHINE}, True)},
                        {DollarCharHostAttributes.SSH_DISCOVERED})
NMAP_MQTT = AttackType(NMAP_MQTT_NAME, {Preconditions({DollarCharHostAttributes.SSH_COMPROMISED}, True)},
                       {DollarCharHostAttributes.MQTT_DISCOVERED})
NMAP_BANNER = AttackType(NMAP_BANNER_NAME, {Preconditions({DollarCharHostAttributes.SSH_COMPROMISED}, True)},
                         {DollarCharHostAttributes.MQTT_DISCOVERED})
BRUTE_FORCE_MALFORMED = AttackType(BRUTE_FORCE_MALFORMED_NAME,
                                   {Preconditions({DollarCharHostAttributes.START_MACHINE}, True),
                                    Preconditions({DollarCharHostAttributes.SSH_DISCOVERED}, False)},
                                   {DollarCharHostAttributes.SSH_COMPROMISED})
DOLLAR_CHAR = AttackType(DOLLAR_CHAR_NAME, {Preconditions({DollarCharHostAttributes.MQTT_MACHINE}, True),
                                            Preconditions(
                                                {DollarCharHostAttributes.SSH_COMPROMISED}, True),
                                            Preconditions(
                                                {DollarCharHostAttributes.SCRIPTS_INSTALLED}, True),
                                            Preconditions(
                                                {DollarCharHostAttributes.MQTT_DISCOVERED}, False),
                                            Preconditions({DollarCharHostAttributes.BROKER_MACHINE}, False)},
                         {DollarCharHostAttributes.CRASHED})
SCP_INST = AttackType(SCP_INST_NAME, {Preconditions({DollarCharHostAttributes.START_MACHINE}, True),
                                      Preconditions({DollarCharHostAttributes.SSH_COMPROMISED}, False)},
                      {DollarCharHostAttributes.SCRIPTS_INSTALLED})
UNDETERMINED = AttackType("undetermined", {Preconditions(
    {DollarCharHostAttributes.START_MACHINE, DollarCharHostAttributes.SSH_COMPROMISED}, True)},
                          {DollarCharHostAttributes.SSH_DISCOVERED, DollarCharHostAttributes.MQTT_DISCOVERED,
                           DollarCharHostAttributes.SSH_COMPROMISED, DollarCharHostAttributes.CRASHED,
                           DollarCharHostAttributes.SCRIPTS_INSTALLED})
ATK_TYPES = [NMAP_MQTT, NMAP_10_T5, NMAP_BANNER,
             BRUTE_FORCE_MALFORMED, DOLLAR_CHAR, SCP_INST]

HOSTS = [Host(ip) for ip in IP_LIST if ip != "10.0.0.1" and ip != "10.0.0.2"]
for host in HOSTS:
    host.update_compromise_attributes({DollarCharHostAttributes.MQTT_MACHINE})
BROKER = Host("10.0.0.1")
BROKER.update_compromise_attributes({DollarCharHostAttributes.BROKER_MACHINE})
HOSTS.append(BROKER)
initial_attributes = {host: set(host.compromise_attributes) for host in HOSTS}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="reconstructScenario",
                                     description="Reconstruct scenarios and compute metrics from the cAPTure dataset, with provided macros defined in the same python file")
    parser.add_argument("-f", "--file", required=True, help="file name")
    parser.add_argument(
        "-t", "--times", help="number of evaluation cycles", default=100, type=int)
    parser.add_argument(
        "-l", "--log", help="where to log results", default="./log.txt", type=str)
    parser.add_argument("--anomaly-threshold", help="threshold for alert generation", default=0.8,
                        type=float)
    parser.add_argument("--suspect-threshold", help="threshold for suspicion addition", default=0.4,
                        type=float)
    parser.add_argument("--type-threshold", help="threshold for attack type mapping", default=0.2,
                        type=float)
    parser.add_argument("--tolerance", help="tolerance when comparing timestamps, in milliseconds", default=2000,
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
    generator = CAPTureScenarioGenerator(reconstruction_df, NEXT_ATTACK_DICT, ENABLE_SRC_FOR, ENABLE_DST_FOR,
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

    tn_list = []
    fp_list = []
    fn_list = []
    tp_list = []
    tnr_list = []
    fpr_list = []
    fnr_list = []
    tpr_list = []
    step_soundness_list = []
    step_completeness_list = []
    scenario_recall_list = []
    scenario_precision_list = []
    scenario_recall_nt_list = []
    scenario_precision_nt_list = []
    scenario_soundness_list = []
    scenario_completeness_list = []
    false_negative_scenarios_actual = []
    false_negative_scenarios_predicted = []
    print("starting to run the iterations...")

    for i in range(args.times):
        print("generating new scenario...")
        scenario_df = generator.generate_scenario(10)
        steps, alerts = generator.export_results(ATK_TYPES)
        print("actual exploits:")
        print("\n".join([str(step) for step in steps]) + "")
        print("actual alerts:")
        print("\n".join([str(alert) for alert in alerts[-20:]]) + "")
        print("converting scenario in flow objects...")
        flows = flow_convertor.convert(scenario_df)
        print("reconstructing scenario from flow objects...")
        for flow in flows:
            manager.accept(flow)
        p_steps, p_alerts = manager.get_results()
        print("predicted exploits:")
        print("\n".join([str(step) for step in p_steps]))
        print("predicted alerts:")
        print("\n".join([str(alert) for alert in p_alerts[-20:]]))
        print("predicted false negatives")
        print("\n".join([str(fn) for fn in manager.get_fns()]))
        print("predicted false positives")
        print("\n".join([str(fp) for fp in manager.get_fps()]))
        print("calculating metrics...")
        tn, fp, fn, tp = metrics_calc.get_detection_confusion_matrix(
            scenario_df, args.anomaly_threshold)
        tn_r, fp_r, fn_r, tp_r = metrics_calc.get_reconstruction_confusion_matrix(
            scenario_df, p_alerts)
        tn_list.append(tn)
        fp_list.append(fp)
        fn_list.append(fn)
        tp_list.append(tp)
        tnr_list.append(tn_r)
        fpr_list.append(fp_r)
        fnr_list.append(fn_r)
        tpr_list.append(tp_r)
        step_soundness, step_completeness = metrics_calc.get_step_soundness_completeness(
            p_steps, steps, p_alerts, alerts, UNDETERMINED)
        step_soundness_list.append(step_soundness)
        step_completeness_list.append(step_completeness)
        scenario_recall_list.append(metrics_calc.get_scenario_step_recall(
            p_steps, steps, args.tolerance, UNDETERMINED))
        scenario_precision_list.append(metrics_calc.get_scenario_step_precision(
            p_steps, steps, args.tolerance, UNDETERMINED))
        scenario_recall_nt_list.append(
            metrics_calc.get_scenario_step_recall_no_timing(p_steps, steps, UNDETERMINED))
        scenario_precision_nt_list.append(
            metrics_calc.get_scenario_step_precision_no_timing(p_steps, steps, UNDETERMINED))
        scenario_soundness, scenario_completeness = metrics_calc.get_scenario_soundness_completeness(
            p_steps, steps, UNDETERMINED)
        scenario_soundness_list.append(scenario_soundness)
        scenario_completeness_list.append(scenario_completeness)
        if fn_r > fn:
            false_negative_scenarios_actual.append(steps)
            false_negative_scenarios_predicted.append(p_steps)
        manager.reset(initial_attributes)

    with open(args.log, "w") as f:

        f.write(
            f"mean ID true negatives: {float(np.mean(tn_list))}, mean REC true negatives: {float(np.mean(tnr_list))}\n")
        f.write(
            f"mean ID false positives: {float(np.mean(fp_list))}, mean REC false positives: {float(np.mean(fpr_list))}\n")
        f.write(
            f"mean ID false negatives: {float(np.mean(fn_list))}, mean REC false negatives: {float(np.mean(fnr_list))}\n")
        f.write(
            f"mean ID true positives: {float(np.mean(tp_list))}, mean REC true positives: {float(np.mean(tpr_list))}\n")

        f.write(
            f"mean soundness of reconstructed steps: {float(np.mean(step_soundness_list))}\n")
        f.write(
            f"mean completeness of reconstructed steps: {float(np.mean(step_completeness_list))}\n")
        f.write(
            f"mean precision of reconstructed scenarios: {float(np.mean(scenario_precision_list))}\n")
        f.write(
            f"mean recall of reconstructed scenarios: {float(np.mean(scenario_recall_list))}\n")
        f.write(
            f"mean precision of reconstructed scenarios (no timing): {float(np.mean(scenario_precision_nt_list))}\n")
        f.write(
            f"mean recall of reconstructed scenarios (no timing): {float(np.mean(scenario_recall_nt_list))}\n")
        f.write(
            f"mean soundness of reconstructed scenarios: {float(np.mean(scenario_soundness_list))}\n")
        f.write(
            f"mean completeness of reconstructed scenarios: {float(np.mean(scenario_completeness_list))}\n")

    with open(args.log.removesuffix(".txt") + "_fn_generating_scenarios.txt", "w") as f:
        for i in range(len(false_negative_scenarios_actual)):
            f.write("actual scenario\n")
            f.write(", ".join(str(exploit) for exploit in false_negative_scenarios_actual[i]) + "\n")
            f.write("predicted scenario\n")
            f.write(", ".join(str(exploit) for exploit in false_negative_scenarios_predicted[i]) + "\n")
