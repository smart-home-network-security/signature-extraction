## Imports
# Libraries
from scapy.all import IP, TCP
# Package
from signature_extraction.classes import PacketFingerprint


### VARIABLES ###
pkt_dict_a = {
    "src": "192.168.1.1",
    "dst": "192.168.1.2",
    "transport_protocol": "TCP",
    "sport": 80,
    "dport": 80,
    "application_protocol": "HTTP",
    "timestamp": 1234567890,
    "length": 100
}
pkt_dict_b = {
    "src": "192.168.1.1",
    "dst": "192.168.1.2",
    "transport_protocol": "TCP",
    "sport": 80,
    "dport": 80,
    "application_protocol": "HTTP",
    "timestamp": 1234567891,
    "length": 200
}
pkt_dict_c = {
    "src": "192.168.1.1",
    "dst": "192.168.1.2",
    "transport_protocol": "TCP",
    "sport": 81,
    "dport": 82,
    "application_protocol": "HTTP",
    "timestamp": 1234567892,
    "length": 300
}


### TEST FUNCTIONS ###

def test_constructor() -> None:
    """
    Test the constructor of the class `PacketFingerprint`.
    """
    pkt_fingerprint = PacketFingerprint(pkt_dict_a)
    assert pkt_fingerprint.id == 0
    assert pkt_fingerprint.src == pkt_dict_a["src"]
    assert pkt_fingerprint.dst == pkt_dict_a["dst"]
    assert pkt_fingerprint.transport_protocol == pkt_dict_a["transport_protocol"]
    assert pkt_fingerprint.sport == pkt_dict_a["sport"]
    assert pkt_fingerprint.dport == pkt_dict_a["dport"]
    assert pkt_fingerprint.application_protocol == pkt_dict_a["application_protocol"]
    assert pkt_fingerprint.timestamp == pkt_dict_a["timestamp"]
    assert pkt_fingerprint.length == pkt_dict_a["length"]


def test_build_from_packet() -> None:
    """
    Test the class method `build_from_packet` of the class `PacketFingerprint`.
    """
    packet = (
        IP(src="192.168.1.1", dst="192.168.1.2") /
        TCP(sport=80, dport=80)
    )
    pkt_len = len(packet)

    pkt_fingerprint = PacketFingerprint.build_from_packet(packet)
    assert pkt_fingerprint.id == 1
    assert pkt_fingerprint.src == "192.168.1.1"
    assert pkt_fingerprint.dst == "192.168.1.2"
    assert pkt_fingerprint.transport_protocol == "TCP"
    assert pkt_fingerprint.sport == 80
    assert pkt_fingerprint.dport == 80
    assert pkt_fingerprint.length == pkt_len


def test_eq() -> None:
    """
    Test the equality operator of the class `PacketFingerprint`.
    """
    pkt_fingerprint_a = PacketFingerprint(pkt_dict_a)
    pkt_fingerprint_b = PacketFingerprint(pkt_dict_b)
    pkt_fingerprint_c = PacketFingerprint(pkt_dict_c)

    assert pkt_fingerprint_a == pkt_fingerprint_a
    assert pkt_fingerprint_a == pkt_fingerprint_b
    assert pkt_fingerprint_a != pkt_fingerprint_c
    assert pkt_fingerprint_b == pkt_fingerprint_a
    assert pkt_fingerprint_b == pkt_fingerprint_b
    assert pkt_fingerprint_b != pkt_fingerprint_c
    assert pkt_fingerprint_c != pkt_fingerprint_a
    assert pkt_fingerprint_c != pkt_fingerprint_b
    assert pkt_fingerprint_c == pkt_fingerprint_c
