## Imports
# Libraries
import os
from pathlib import Path
from scapy.all import IP, UDP
from scapy.layers.dns import DNS, DNSQR
# Package
import signature_extraction.application_layer as app_layer
from signature_extraction.network import Packet, Flow, FlowFingerprint


### VARIABLES ###

# DNS request packet
pkt_dns_request_a = (
    IP(src="192.168.1.2", dst="192.168.1.1") /
    UDP(sport=12345, dport=53) /
    DNS(
        rd=1,
        qd=DNSQR(qname="www.example.com")
    )
)
pkt_dict = {
    "src": "192.168.1.2",
    "dst": "192.168.1.1",
    "sport": 12345,
    "dport": 53,
    "transport_protocol": "UDP",
    "application_layer": app_layer.DNS(pkt_dns_request_a)
}

pkt_dns_request_b = (
    IP(src="192.168.1.3", dst="192.168.1.1") /
    UDP(sport=6666, dport=53) /
    DNS(
        rd=1,
        qd=DNSQR(qname="www.example.com")
    )
)


### TEST FUNCTIONS ###

def test_constructor() -> None:
    """
    Test the constructor of the class `FlowFingerprint`.
    """
    flow = FlowFingerprint(pkt_dict)
    assert flow.src == "192.168.1.2"
    assert flow.dst == "192.168.1.1"
    assert flow.transport_protocol == "UDP"
    assert isinstance(flow.application_layer, app_layer.DNS)
    # Ports
    assert 53 in flow.ports
    assert flow.ports[53]["number"] == 1
    assert flow.ports[53]["host"] == "192.168.1.1"


def test_build_from_pkt() -> None:
    """
    Test the class method `build_from_pkt`.
    """
    pkt = Packet.build_from_pkt(pkt_dns_request_a)
    flow = FlowFingerprint.build_from_pkt(pkt)
    assert flow.src == "192.168.1.2"
    assert flow.dst == "192.168.1.1"
    assert flow.transport_protocol == "UDP"
    assert isinstance(flow.application_layer, app_layer.DNS)
    # Ports
    assert 53 in flow.ports
    assert flow.ports[53]["number"] == 1
    assert flow.ports[53]["host"] == "192.168.1.1"


def test_build_from_flow() -> None:
    """
    Test the class method `build_from_pkt`.
    """
    pkt = Packet.build_from_pkt(pkt_dns_request_a)
    f = Flow.build_from_pkt(pkt)
    flow = FlowFingerprint.build_from_flow(f)
    assert flow.src == "192.168.1.2"
    assert flow.dst == "192.168.1.1"
    assert flow.transport_protocol == "UDP"
    assert isinstance(flow.application_layer, app_layer.DNS)
    # Ports
    assert 53 in flow.ports
    assert flow.ports[53]["number"] == 1
    assert flow.ports[53]["host"] == "192.168.1.1"


def test_add_ports() -> None:
    """
    Test the method `add_ports`.
    """
    # Initialize FlowFingerprint
    flow = FlowFingerprint(pkt_dict)

    # Create new flow
    pkt_b = Packet.build_from_pkt(pkt_dns_request_b)
    f_2 = Flow.build_from_pkt(pkt_b)
    flow.add_ports(dict(f_2))

    # Verify fields
    assert 53 in flow.ports
    assert flow.ports[53]["number"] == 2
    assert flow.ports[53]["host"] == "192.168.1.1"
    assert flow.get_fixed_port() == (53, "192.168.1.1")


def test_add_flow() -> None:
    """
    Test the method `add_flow`.
    """
    # Initialize FlowFingerprint
    flow = FlowFingerprint(pkt_dict)

    # Add new flow
    pkt_b = Packet.build_from_pkt(pkt_dns_request_b)
    f_2 = Flow.build_from_pkt(pkt_b)
    flow.add_flow(f_2)

    # Verify fields
    assert 53 in flow.ports
    assert flow.ports[53]["number"] == 2
    assert flow.ports[53]["host"] == "192.168.1.1"
    assert flow.get_fixed_port() == (53, "192.168.1.1")


def test_extract_policy() -> None:
    """
    Test the method `extract_policy`.
    """
    # Initialize FlowFingerprint object
    flow = FlowFingerprint(pkt_dict)

    # Execute function under test
    device_ipv4 = "192.168.1.2"
    policy = flow.extract_policy(device_ipv4)

    # Verification
    assert policy["bidirectional"]
    assert policy["protocols"]["ipv4"]["src"] == "self"
    assert policy["protocols"]["ipv4"]["dst"] == "192.168.1.1"
    assert policy["protocols"]["udp"]["dst-port"] == 53
    assert policy["protocols"]["dns"]["qtype"] == "A"
    assert policy["protocols"]["dns"]["domain-name"] == "www.example.com"
    assert not policy["protocols"]["dns"]["response"]


def test_translate_to_firewall(tmp_path: Path) -> None:
    """
    Test the method `translate_to_firewall`.

    Args:
        tmp_path (Path): path to a temporary directory
    """
    # Initialize FlowFingerprint object
    flow = FlowFingerprint(pkt_dict)

    # Execute function under test
    device_name = "test"
    device_ipv4 = "192.168.1.2"
    flow.translate_to_firewall(device_name, device_ipv4, tmp_path)

    # Verification
    assert os.path.isfile(os.path.join(tmp_path, "firewall.nft"))
    assert os.path.isfile(os.path.join(tmp_path, "nfqueues.c"))
    assert os.path.isfile(os.path.join(tmp_path, "CMakeLists.txt"))
