"""Shared example attributes for model and reconstruction tests."""

from scenario_reconstructor.models import HostAttribute


class NetworkAttribute(HostAttribute):
    HOST_DISCOVERED = "host_discovered"
    PORT_SCANNED = "port_scanned"
    HOST_VULNERABLE = "host_vulnerable"
    HOST_COMPROMISED = "host_compromised"
