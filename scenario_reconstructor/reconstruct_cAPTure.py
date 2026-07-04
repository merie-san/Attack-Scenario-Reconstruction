import argparse
from scenario_generator.scenario_generator import CAPTureScenarioGenerator
from event_convertor.flow_event_generator import CAPTureFlowEventConvertor
from event_convertor.flow_event import FlowEvent
from attack_mapper import AttackMapper
from reconstruction_manager import ExploitGenerator, ScenarioReconstructionManager
from scenario_reconstructor.scenario_reconstructor import HostAttribute, Preconditions, Host, AttackType, FlowExploit, Exploit, ExploitRequirement, StarNetworkAttackGraphBasedScenarioReconstructor

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="generate cAPTure dataset derived scenario, reconstruct and derive metrics")
