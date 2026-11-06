"""cAPTure dollar_char attack definitions, generation rules, and host initialization."""
from scenario_reconstructor.models import AttackType, Host, HostAttribute, Precondition

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


NMAP_10_T5 = AttackType(NMAP_10_T5_NAME, {Precondition({DollarCharHostAttributes.START_MACHINE}, True)},
                        {DollarCharHostAttributes.SSH_DISCOVERED})
NMAP_MQTT = AttackType(NMAP_MQTT_NAME, {Precondition({DollarCharHostAttributes.SSH_COMPROMISED}, True)},
                       {DollarCharHostAttributes.MQTT_DISCOVERED})
NMAP_BANNER = AttackType(NMAP_BANNER_NAME, {Precondition({DollarCharHostAttributes.SSH_COMPROMISED}, True)},
                         {DollarCharHostAttributes.MQTT_DISCOVERED})
BRUTE_FORCE_MALFORMED = AttackType(BRUTE_FORCE_MALFORMED_NAME,
                                   {Precondition({DollarCharHostAttributes.START_MACHINE}, True),
                                    Precondition({DollarCharHostAttributes.SSH_DISCOVERED}, False)},
                                   {DollarCharHostAttributes.SSH_COMPROMISED})
DOLLAR_CHAR = AttackType(DOLLAR_CHAR_NAME, {Precondition({DollarCharHostAttributes.MQTT_MACHINE}, True),
                                            Precondition(
                                                {DollarCharHostAttributes.SSH_COMPROMISED}, True),
                                            Precondition(
                                                {DollarCharHostAttributes.SCRIPTS_INSTALLED}, True),
                                            Precondition(
                                                {DollarCharHostAttributes.MQTT_DISCOVERED}, False),
                                            Precondition({DollarCharHostAttributes.BROKER_MACHINE}, False)},
                         {DollarCharHostAttributes.CRASHED})
SCP_INST = AttackType(SCP_INST_NAME, {Precondition({DollarCharHostAttributes.START_MACHINE}, True),
                                      Precondition({DollarCharHostAttributes.SSH_COMPROMISED}, False)},
                      {DollarCharHostAttributes.SCRIPTS_INSTALLED})
UNDETERMINED = AttackType("undetermined", {Precondition(
    {DollarCharHostAttributes.START_MACHINE, DollarCharHostAttributes.SSH_COMPROMISED}, True)},
                          {DollarCharHostAttributes.SSH_DISCOVERED, DollarCharHostAttributes.MQTT_DISCOVERED,
                           DollarCharHostAttributes.SSH_COMPROMISED, DollarCharHostAttributes.CRASHED,
                           DollarCharHostAttributes.SCRIPTS_INSTALLED})
ATK_TYPES = [NMAP_MQTT, NMAP_10_T5, NMAP_BANNER,
             BRUTE_FORCE_MALFORMED, DOLLAR_CHAR, SCP_INST]

def create_hosts() -> list[Host]:
    hosts = [Host(ip) for ip in IP_LIST if ip != "10.0.0.1" and ip != "10.0.0.2"]
    for host in hosts:
        host.update_compromise_attributes({DollarCharHostAttributes.MQTT_MACHINE})
    broker = Host("10.0.0.1")
    broker.update_compromise_attributes({DollarCharHostAttributes.BROKER_MACHINE})
    hosts.append(broker)
    return hosts


HOSTS = create_hosts()
BROKER = HOSTS[-1]
initial_attributes = {host: set(host.compromise_attributes) for host in HOSTS}


__all__ = ['SCP_INST_NAME', 'DOLLAR_CHAR_NAME', 'BRUTE_FORCE_MALFORMED_NAME', 'NMAP_BANNER_NAME', 'NMAP_MQTT_NAME', 'NMAP_10_T5_NAME', 'NEXT_ATTACK_DICT', 'ENABLE_SRC_FOR', 'ENABLE_DST_FOR', 'IP_LIST', 'SUBNET_IPS', 'MQTT_NODE_IPS', 'POSSIBLE_SRCS', 'POSSIBLE_DSTS', 'DST_RESTRICTED_ATKS', 'FINAL_ATK', 'ENABLE_ATKS', 'NMAP_10_T5', 'NMAP_MQTT', 'NMAP_BANNER', 'BRUTE_FORCE_MALFORMED', 'DOLLAR_CHAR', 'SCP_INST', 'UNDETERMINED', 'ATK_TYPES', 'HOSTS', 'BROKER', 'initial_attributes', 'DollarCharHostAttributes', 'create_hosts']
