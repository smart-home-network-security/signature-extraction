## Imports
# Package
from signature_extraction.classes import FlowFingerprint


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
pkt_dict_d = {
    "src": "192.168.1.2",
    "dst": "192.168.1.1",
    "transport_protocol": "TCP",
    "sport": 80,
    "dport": 80,
    "application_protocol": "HTTP",
    "timestamp": 1234567893,
    "length": 100
}
pkt_dict_e = {
    "src": "192.168.1.3",
    "dst": "192.168.1.4",
    "transport_protocol": "TCP",
    "sport": 80,
    "dport": 80,
    "application_protocol": "HTTP",
    "timestamp": 1234567894,
    "length": 100
}
pkt_dict_f = {
    "src": "192.168.1.1",
    "dst": "192.168.1.2",
    "transport_protocol": "UDP",
    "sport": 80,
    "dport": 80,
    "application_protocol": "DNS",
    "timestamp": 1234567895,
    "length": 100
}


### TEST FUNCTIONS ###

def test_constructor() -> None:
    """
    Test the constructor of the class `FlowFingerprint`.
    """
    pkts = [pkt_dict_a, pkt_dict_b]
    flow_fingerprint = FlowFingerprint(pkts)

    assert flow_fingerprint.src == pkt_dict_a["src"]
    assert flow_fingerprint.dst == pkt_dict_a["dst"]
    assert flow_fingerprint.transport_protocol == pkt_dict_a["transport_protocol"]
    assert flow_fingerprint.sport == pkt_dict_a["sport"]
    assert flow_fingerprint.dport == pkt_dict_a["dport"]
    assert flow_fingerprint.application_protocol == pkt_dict_a["application_protocol"]
    assert flow_fingerprint.timestamp == pkt_dict_a["timestamp"]
    assert flow_fingerprint.count == 2
    assert flow_fingerprint.length == pkt_dict_a["length"] + pkt_dict_b["length"]


def test_build_from_packet() -> None:
    """
    Test the class method `build_from_packet` of the class `FlowFingerprint`.
    """
    packet = FlowFingerprint.build_from_packet(pkt_dict_a)

    assert packet.src == pkt_dict_a["src"]
    assert packet.dst == pkt_dict_a["dst"]
    assert packet.transport_protocol == pkt_dict_a["transport_protocol"]
    assert packet.sport == pkt_dict_a["sport"]
    assert packet.dport == pkt_dict_a["dport"]
    assert packet.application_protocol == pkt_dict_a["application_protocol"]
    assert packet.timestamp == pkt_dict_a["timestamp"]
    assert packet.count == 1
    assert packet.length == pkt_dict_a["length"]


def test_eq() -> None:
    """
    Test the equality operator of the class `FlowFingerprint`.
    """
    flow_a = FlowFingerprint([pkt_dict_a])
    flow_b = FlowFingerprint([pkt_dict_b])
    flow_c = FlowFingerprint([pkt_dict_c])

    assert flow_a == flow_a
    assert flow_a == flow_b
    assert flow_a != flow_c
    assert flow_b == flow_a
    assert flow_b == flow_b
    assert flow_b != flow_c
    assert flow_c != flow_a
    assert flow_c != flow_b
    assert flow_c == flow_c


def test_match_host() -> None:
    """
    Test the method `match_host` of the class `FlowFingerprint`.
    """
    flow_a = FlowFingerprint([pkt_dict_a])
    flow_b = FlowFingerprint([pkt_dict_b])
    flow_c = FlowFingerprint([pkt_dict_c])
    flow_d = FlowFingerprint([pkt_dict_d])
    flow_e = FlowFingerprint([pkt_dict_e])
    flow_f = FlowFingerprint([pkt_dict_f])

    assert flow_a.match_host(flow_a)
    assert flow_a.match_host(flow_b)
    assert flow_a.match_host(flow_c)
    assert flow_a.match_host(flow_d)
    assert not flow_a.match_host(flow_e)
    assert flow_a.match_host(flow_f)
    assert flow_b.match_host(flow_a)
    assert flow_b.match_host(flow_b)
    assert flow_b.match_host(flow_c)
    assert flow_b.match_host(flow_d)
    assert not flow_b.match_host(flow_e)
    assert flow_b.match_host(flow_f)
    assert flow_c.match_host(flow_a)
    assert flow_c.match_host(flow_b)
    assert flow_c.match_host(flow_c)
    assert flow_c.match_host(flow_d)
    assert not flow_c.match_host(flow_e)
    assert flow_c.match_host(flow_f)
    assert flow_d.match_host(flow_a)
    assert flow_d.match_host(flow_b)
    assert flow_d.match_host(flow_c)
    assert flow_d.match_host(flow_d)
    assert flow_d.match_host(flow_f)
    assert not flow_d.match_host(flow_e)
    assert not flow_e.match_host(flow_a)
    assert not flow_e.match_host(flow_b)
    assert not flow_e.match_host(flow_c)
    assert not flow_e.match_host(flow_d)
    assert not flow_e.match_host(flow_f)


def test_match_basic() -> None:
    """
    Test the method `match_basic` of the class `FlowFingerprint`.
    """
    flow_a = FlowFingerprint([pkt_dict_a])
    flow_b = FlowFingerprint([pkt_dict_b])
    flow_c = FlowFingerprint([pkt_dict_c])
    flow_d = FlowFingerprint([pkt_dict_d])
    flow_e = FlowFingerprint([pkt_dict_e])
    flow_f = FlowFingerprint([pkt_dict_f])

    assert flow_a.match_basic(flow_a)
    assert flow_a.match_basic(flow_b)
    assert flow_a.match_basic(flow_c)
    assert flow_a.match_basic(flow_d)
    assert not flow_a.match_basic(flow_e)
    assert not flow_a.match_basic(flow_f)
    assert flow_b.match_basic(flow_a)
    assert flow_b.match_basic(flow_b)
    assert flow_b.match_basic(flow_c)
    assert flow_b.match_basic(flow_d)
    assert not flow_b.match_basic(flow_e)
    assert not flow_b.match_basic(flow_f)
    assert flow_c.match_basic(flow_a)
    assert flow_c.match_basic(flow_b)
    assert flow_c.match_basic(flow_c)
    assert flow_c.match_basic(flow_d)
    assert not flow_c.match_basic(flow_e)
    assert not flow_c.match_basic(flow_f)
    assert flow_d.match_basic(flow_a)
    assert flow_d.match_basic(flow_b)
    assert flow_d.match_basic(flow_c)
    assert flow_d.match_basic(flow_d)
    assert not flow_d.match_basic(flow_e)
    assert not flow_e.match_basic(flow_a)
    assert not flow_e.match_basic(flow_b)
    assert not flow_e.match_basic(flow_c)
    assert not flow_e.match_basic(flow_d)
    assert not flow_e.match_basic(flow_f)
    assert not flow_f.match_basic(flow_a)
    assert not flow_f.match_basic(flow_b)
    assert not flow_f.match_basic(flow_c)
    assert not flow_f.match_basic(flow_d)
    assert not flow_f.match_basic(flow_e)
