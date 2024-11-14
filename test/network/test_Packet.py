## Imports
# Libraries
from scapy.all import IP, TCP, Raw
# Package
from signature_extraction.utils import DnsTableKeys
from signature_extraction.network import Packet


### VARIABLES ###
pkt_dict_a = {
    "src": "192.168.1.1",
    "dst": "192.168.1.2",
    "transport_protocol": "TCP",
    "sport": 80,
    "dport": 80,
    "application_layer": "HTTP",
    "timestamp": 1234567890,
    "length": 100
}
pkt_dict_b = {
    "src": "192.168.1.1",
    "dst": "192.168.1.2",
    "transport_protocol": "TCP",
    "sport": 80,
    "dport": 80,
    "application_layer": "HTTP",
    "timestamp": 1234567891,
    "length": 200
}
pkt_dict_c = {
    "src": "192.168.1.1",
    "dst": "192.168.1.2",
    "transport_protocol": "TCP",
    "sport": 81,
    "dport": 82,
    "application_layer": "HTTP",
    "timestamp": 1234567892,
    "length": 300
}


### TEST FUNCTIONS ###

def test_constructor() -> None:
    """
    Test the constructor of the class `Packet`.
    """
    pkt = Packet(pkt_dict_a)
    assert pkt.src == pkt_dict_a["src"]
    assert pkt.dst == pkt_dict_a["dst"]
    assert pkt.transport_protocol == pkt_dict_a["transport_protocol"]
    assert pkt.sport == pkt_dict_a["sport"]
    assert pkt.dport == pkt_dict_a["dport"]
    assert pkt.application_layer == pkt_dict_a["application_layer"]
    assert pkt.timestamp == pkt_dict_a["timestamp"]
    assert pkt.length == pkt_dict_a["length"]


def test_build_from_packet() -> None:
    """
    Test the class method `build_from_pkt` of the class `Packet`.
    """
    packet = (
        IP(src="192.168.1.1", dst="192.168.1.2") /
        TCP(sport=80, dport=80)
    )
    pkt_len = len(packet)

    pkt = Packet.build_from_pkt(packet)
    assert pkt.src == "192.168.1.1"
    assert pkt.dst == "192.168.1.2"
    assert pkt.transport_protocol == "TCP"
    assert pkt.sport == 80
    assert pkt.dport == 80
    assert pkt.length == pkt_len


def test_build_from_packet_error() -> None:
    """
    Test the class method `build_from_pkt` of the class `Packet`,
    when an error occurs.
    """
    packet = (
        IP(src="192.168.1.1", dst="192.168.1.2") /
        TCP(sport=80, dport=8080) /
        Raw(b"\x01\x02\x03\x04")
    )
    pkt_len = len(packet)

    pkt = Packet.build_from_pkt(packet)
    assert pkt.src == "192.168.1.1"
    assert pkt.dst == "192.168.1.2"
    assert pkt.transport_protocol == "TCP"
    assert pkt.sport == 80
    assert pkt.dport == 8080
    assert pkt.length == pkt_len


def test_eq() -> None:
    """
    Test the equality operator of the class `Packet`.
    """
    pkt_a = Packet(pkt_dict_a)
    pkt_b = Packet(pkt_dict_b)
    pkt_c = Packet(pkt_dict_c)

    assert pkt_a == pkt_a
    assert pkt_a == pkt_b
    assert pkt_a != pkt_c
    assert pkt_b == pkt_a
    assert pkt_b == pkt_b
    assert pkt_b != pkt_c
    assert pkt_c != pkt_a
    assert pkt_c != pkt_b
    assert pkt_c == pkt_c


def test_set_domain_names() -> None:
    """
    Test the method `set_domain_names` of the class `Packet`.
    """
    # Build DNS table
    dns_table = {
        DnsTableKeys.IP.name: {
            "192.168.1.1": "www.example1.com",
            "192.168.1.2": "server2.example.com",
        },
        DnsTableKeys.ALIAS.name: {
            "server2.example.com": "www.example2.com"
        }
    }

    # Build packet & set domain names
    pkt = Packet(pkt_dict_a)
    pkt.set_domain_names(dns_table)

    # Verify domain names
    assert pkt.src == "www.example1.com"
    assert pkt.dst == "www.example2.com"
