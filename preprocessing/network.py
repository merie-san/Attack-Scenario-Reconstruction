"""Validated IP-address and MAC-to-IPv4 resolution helpers for flow preparation."""
import ipaddress

import pandas as pd

_ENDPOINT_COLUMNS = (("src_mac", "src_ip"), ("dst_mac", "dst_ip"))


def is_ipv4(value) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except (ValueError, TypeError):
        return False


def filter_ipv4_flows(frame):
    """Copy flows whose source and destination are both valid IPv4 addresses."""
    return frame[frame["src_ip"].map(is_ipv4) & frame["dst_ip"].map(is_ipv4)].copy()


def build_mac_to_ipv4(dfs) -> dict[str, str]:
    """Collect a MAC-to-IPv4 lookup table across an iterable of flow DataFrames."""
    if isinstance(dfs, pd.DataFrame):
        raise TypeError("build_mac_to_ipv4 expects an iterable of DataFrames, not a single DataFrame")
    mapping: dict[str, str] = {}
    for df in dfs:
        for mac_col, ip_col in _ENDPOINT_COLUMNS:
            is_v4 = df[ip_col].map(is_ipv4)
            pairs = df.loc[is_v4, [mac_col, ip_col]].drop_duplicates()
            mapping.update(zip(pairs[mac_col], pairs[ip_col]))
    return mapping


def resolve_ipv6_with_mac(df: pd.DataFrame, mappings: dict[str, str]) -> tuple[pd.DataFrame, int]:
    """Replace IPv6 addresses using MAC mappings and count unresolved IPv6 endpoints."""
    resolved = df.copy()
    not_found = 0
    for mac_col, ip_col in _ENDPOINT_COLUMNS:
        is_v6 = resolved[ip_col].astype(str).str.contains(":", regex=False)
        mapped = resolved[mac_col].map(mappings)
        not_found += int((is_v6 & mapped.isna()).sum())
        resolved[ip_col] = resolved[ip_col].where(~(is_v6 & mapped.notna()), mapped)
    return resolved, not_found
