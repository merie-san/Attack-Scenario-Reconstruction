"""Validated IP-address helpers for flow preparation."""
import ipaddress


def is_ipv4(value) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except (ValueError, TypeError):
        return False


def filter_ipv4_flows(frame):
    """Copy flows whose source and destination are both valid IPv4 addresses."""
    return frame[frame["src_ip"].map(is_ipv4) & frame["dst_ip"].map(is_ipv4)].copy()
