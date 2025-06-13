## Imports
# Libraries
import os
from pathlib import Path
from scapy.all import IP, UDP
from scapy.layers.dns import DNS, DNSQR
# Package
import signature_extraction.application_layer as app_layer
from signature_extraction.network import Packet, FlowFingerprint


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
    "network_protocol": "IPv4",
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

pkt_dns_request_c = (
    IP(src="192.168.1.1", dst="192.168.1.2") /
    UDP(sport=53, dport=12345) /
    DNS(
        rd=0,
        qd=DNSQR(qname="www.example.com")
    )
)

pkt_dict_d = {
    "network_protocol": "IPv4",
    "src": "192.168.1.1",
    "dst": "192.168.1.2",
    "sport": 53,
    "dport": 12345,
    "transport_protocol": "TCP"
}


# Initialize FlowFingerprints
f_1 = FlowFingerprint(pkt_dict)
pkt_b = Packet.build_from_pkt(pkt_dns_request_b)
f_2 = FlowFingerprint(pkt_b)
pkt_c = Packet.build_from_pkt(pkt_dns_request_c)
f_3 = FlowFingerprint(pkt_c)
f_4 = FlowFingerprint(pkt_dict_d)


### TEST FUNCTIONS ###

def test_constructor_dict() -> None:
    """
    Test the constructor of the class `FlowFingerprint`,
    with a dictionary as input.
    """
    flow = FlowFingerprint(pkt_dict)
    assert flow.network_protocol == "IPv4"
    assert flow.src == "192.168.1.2"
    assert flow.dst == "192.168.1.1"
    assert flow.transport_protocol == "UDP"
    assert isinstance(flow.application_layer, app_layer.DNS)
    # Ports
    assert ("192.168.1.1", 53) in flow.ports
    assert flow.ports[("192.168.1.1", 53)] == 1


def test_constructor_pkt() -> None:
    """
    Test the constructor of the class `FlowFingerprint`,
    with a Packet as input.
    """
    pkt = Packet.build_from_pkt(pkt_dns_request_a)
    flow = FlowFingerprint(pkt)
    assert flow.network_protocol == "IPv4"
    assert flow.src == "192.168.1.2"
    assert flow.dst == "192.168.1.1"
    assert flow.transport_protocol == "UDP"
    assert isinstance(flow.application_layer, app_layer.DNS)
    # Ports
    assert ("192.168.1.1", 53) in flow.ports
    assert flow.ports[("192.168.1.1", 53)] == 1


def test_add_ports() -> None:
    """
    Test the method `add_ports`.
    """
    # Initialize FlowFingerprint
    flow = FlowFingerprint(pkt_dict)

    # Create new flow
    pkt_b = Packet.build_from_pkt(pkt_dns_request_b)
    f_2 = FlowFingerprint(pkt_b)
    flow.add_ports(f_2)

    # Verify fields
    assert ("192.168.1.1", 53) in flow.ports
    assert flow.ports[("192.168.1.1", 53)] == 2
    assert ("192.168.1.1", 53) in flow.get_fixed_ports()


def test_add_flow() -> None:
    """
    Test the method `add_flow`,
    with a Flow as argument.
    """
    # Initialize FlowFingerprint
    flow = FlowFingerprint(pkt_dict)

    # Add new flow
    pkt_c = Packet.build_from_pkt(pkt_dns_request_c)
    f_2 = FlowFingerprint(pkt_c)
    flow.add_flow(f_2)

    # Verify fields
    assert ("192.168.1.1", 53) in flow.ports
    assert flow.ports[("192.168.1.1", 53)] == 2
    assert ("192.168.1.1", 53) in flow.get_fixed_ports()
    assert ("192.168.1.2", 12345) in flow.ports
    assert flow.ports[("192.168.1.2", 12345)] == 2
    assert ("192.168.1.2", 12345) not in flow.get_fixed_ports()


def test_add_flow_fingerprint() -> None:
    """
    Test the method `add_flow`,
    with a FlowFingerprint as argument.
    """
    # Initialize FlowFingerprint
    flow = FlowFingerprint(pkt_dict)

    # Add new FlowFingerprint
    pkt_b = Packet.build_from_pkt(pkt_dns_request_b)
    f_2 = FlowFingerprint(pkt_b)
    flow.add_flow(f_2)

    # Verify fields
    assert ("192.168.1.1", 53) in flow.ports
    assert flow.ports[("192.168.1.1", 53)] == 2
    assert ("192.168.1.1", 53) in flow.get_fixed_ports()


def test_match_hosts() -> None:
    """
    Test the method `match_hosts`,
    which compares the hosts of two FlowFingerprints.
    """
    # Initialize FlowFingerprints
    f_1 = FlowFingerprint(pkt_dict)
    pkt_b = Packet.build_from_pkt(pkt_dns_request_b)
    f_2 = FlowFingerprint(pkt_b)
    pkt_c = Packet.build_from_pkt(pkt_dns_request_c)
    f_3 = FlowFingerprint(pkt_c)
    f_4 = FlowFingerprint(pkt_dict_d)

    # Verify host matching
    assert not f_1.match_hosts(f_2)
    assert f_1.match_hosts(f_3)
    assert f_1.match_hosts(f_4)


def test_get_different_hosts() -> None:
    """
    Test the method `get_different_hosts`,
    which extracts the hosts different between both FlowFingerprints.
    """
    assert f_1.get_different_hosts(f_2) == set([("192.168.1.2", "192.168.1.3")])
    assert f_1.get_different_hosts(f_3) == set()
    assert f_1.get_different_hosts(f_4) == set()


def test_match_ports() -> None:
    """
    Test the method `match_ports`,
    which compares the fixed ports of two FlowFingerprints.
    """
    assert not f_1.match_ports(f_2)
    assert f_1.match_ports(f_3)
    assert f_1.match_ports(f_4)


def test_get_different_ports() -> None:
    """
    Test the method `get_different_ports`,
    which extracts the ports different between both FlowFingerprints.
    """
    assert f_1.get_different_ports(f_2) == set()
    assert f_1.get_different_ports(f_3) == set()
    assert f_1.get_different_ports(f_4) == set()


def test_match_flow() -> None:
    """
    Test the method `match_flow`,
    which compares two FlowFingerprints.
    """
    # Initialize FlowFingerprint
    flow_fingerprint = FlowFingerprint(pkt_dict)

    # Verify match with other flows
    pkt_b = Packet.build_from_pkt(pkt_dns_request_b)
    f_2 = FlowFingerprint(pkt_b)
    assert not flow_fingerprint.match_flow(f_2)
    pkt_c = Packet.build_from_pkt(pkt_dns_request_c)
    f_3 = FlowFingerprint(pkt_c)
    assert flow_fingerprint.match_flow(f_3)
    f_4 = FlowFingerprint(pkt_dict_d)
    assert not flow_fingerprint.match_flow(f_4)


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
