## Imports
# Libraries
import os
from pathlib import Path
from scapy.all import IP, UDP
from scapy.layers.dns import DNS, DNSQR
import pytest
# Package
import signature_extraction.application_layer as app_layer
from signature_extraction.network import FlowFingerprint, NetworkPattern


### VARIABLES ###

# Paths
self_path = os.path.abspath(__file__)
self_dir = os.path.dirname(self_path)

# DNS request packet
pkt_dns_request_a = (
    IP(src="192.168.1.2", dst="192.168.1.1") /
    UDP(sport=12345, dport=53) /
    DNS(
        rd=1,
        qd=DNSQR(qname="www.example.com")
    )
)
dns_dict = {
    "src": "192.168.1.2",
    "dst": "192.168.1.1",
    "sport": 12345,
    "dport": 53,
    "transport_protocol": "UDP",
    "application_layer": app_layer.DNS(pkt_dns_request_a)
}

# TCP packets
tcp_dict = {
    "src": "192.168.1.2",
    "dst": "192.168.1.3",
    "sport": 1111,
    "dport": 2222,
    "transport_protocol": "TCP"
}
tcp_dict_b = {
    "src": "192.168.1.2",
    "dst": "192.168.1.3",
    "sport": 3333,
    "dport": 4444,
    "transport_protocol": "TCP"
}

# UDP packet
udp_dict = {
    "src": "192.168.1.4",
    "dst": "192.168.1.5",
    "sport": 3333,
    "dport": 4444,
    "transport_protocol": "UDP"
}


### TEST FUNCTIONS ###

def test_empty() -> None:
    """
    Test an empty `NetworkPattern`.
    """
    pattern = NetworkPattern()
    assert len(pattern) == 0
    assert pattern.get_flows() == []


def test_constructor() -> None:
    """
    Test the constructor of the class `NetworkPattern`.
    """
    flow = FlowFingerprint(dns_dict)
    pattern = NetworkPattern([flow])
    assert len(pattern) == 1
    assert pattern.get_flows() == [flow]


def test_load_from_csv() -> None:
    """
    Test the class method `load_from_csv`.
    """
    csv_file_path = os.path.join(self_dir, "signature.csv")
    pattern = NetworkPattern.load_from_csv(csv_file_path)
    assert len(pattern) == 3


def test_set_flows() -> None:
    """
    Test the method `set_flows`.
    """
    # Initialize NetworkPattern
    pattern = NetworkPattern()
    assert len(pattern) == 0
    assert pattern.get_flows() == []

    # Add flow
    flow = FlowFingerprint(dns_dict)
    pattern.set_flows([flow])
    assert len(pattern) == 1
    assert pattern.get_flows() == [flow]


def test_add_flow() -> None:
    """
    Test the method `add_flow`.
    """
    # Initialize NetworkPattern
    pattern = NetworkPattern()
    assert len(pattern) == 0
    assert pattern.get_flows() == []

    # Add flow
    flow_a = FlowFingerprint(dns_dict)
    pattern.add_flow(flow_a)
    assert len(pattern) == 1
    assert pattern.get_flows() == [flow_a]

    # Add another flow
    flow_b = FlowFingerprint(tcp_dict)
    pattern.add_flow(flow_b)
    assert len(pattern) == 2
    assert pattern.get_flows() == [flow_a, flow_b]

    # Find flows
    assert pattern.find_matching_flow(flow_a) == (0, flow_a)
    assert pattern.find_matching_flow(flow_b) == (1, flow_b)


def test_find_matching_flow() -> None:
    """
    Test the method `find_matching_flow`.
    """
    flow_a = FlowFingerprint(dns_dict)
    flow_b = FlowFingerprint(tcp_dict)
    flow_c = FlowFingerprint(tcp_dict_b)
    flow_d = FlowFingerprint(udp_dict)
    pattern = NetworkPattern([flow_a, flow_b])
    assert pattern.find_matching_flow(flow_a) == (0, flow_a)
    assert pattern.find_matching_flow(flow_b) == (1, flow_b)
    assert pattern.find_matching_flow(flow_c) == (1, flow_b)
    with pytest.raises(ValueError):
        pattern.find_matching_flow(flow_d)


def test_to_df() -> None:
    """
    Test the method `to_df`.
    """
    flow_a = FlowFingerprint(dns_dict)
    flow_b = FlowFingerprint(tcp_dict)
    pattern = NetworkPattern([flow_a, flow_b])
    df = pattern.to_df()
    assert len(df) == 2


def test_to_csv(tmp_path: Path) -> None:
    """
    Test the method `to_csv`.

    Args:
        tmp_path (Path): Path to the temporary directory.
    """
    flow_a = FlowFingerprint(dns_dict)
    flow_b = FlowFingerprint(tcp_dict)
    pattern = NetworkPattern([flow_a, flow_b])
    csv_file_path = os.path.join(tmp_path, "signature.csv")
    pattern.to_csv(csv_file_path)
    assert os.path.isfile(csv_file_path)
