## Imports
# Package
from signature_extraction.classes import Flow


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
    Test the constructor of the class `Flow`.
    """
    pkts = [pkt_dict_a, pkt_dict_b]
    flow = Flow(pkts)

    assert flow.src == pkt_dict_a["src"]
    assert flow.dst == pkt_dict_a["dst"]
    assert flow.transport_protocol == pkt_dict_a["transport_protocol"]
    assert flow.sport == pkt_dict_a["sport"]
    assert flow.dport == pkt_dict_a["dport"]
    assert flow.application_protocol == pkt_dict_a["application_protocol"]
    assert flow.timestamp == pkt_dict_a["timestamp"]
    assert flow.count == 2
    assert flow.length == pkt_dict_a["length"] + pkt_dict_b["length"]


def test_build_from_packet() -> None:
    """
    Test the class method `build_from_packet` of the class `Flow`.
    """
    packet = Flow.build_from_packet(pkt_dict_a)

    assert packet.src == pkt_dict_a["src"]
    assert packet.dst == pkt_dict_a["dst"]
    assert packet.transport_protocol == pkt_dict_a["transport_protocol"]
    assert packet.sport == pkt_dict_a["sport"]
    assert packet.dport == pkt_dict_a["dport"]
    assert packet.application_protocol == pkt_dict_a["application_protocol"]
    assert packet.timestamp == pkt_dict_a["timestamp"]
    assert packet.count == 1
    assert packet.length == pkt_dict_a["length"]


def test_compare_full() -> None:
    """
    Test the method `compare_full` of the class `Flow`.
    """
    flow_a = Flow([pkt_dict_a])
    flow_b = Flow([pkt_dict_b])
    flow_c = Flow([pkt_dict_c])

    assert flow_a.compare_full(flow_a)
    assert flow_a.compare_full(flow_b)
    assert not flow_a.compare_full(flow_c)
    assert flow_b.compare_full(flow_a)
    assert flow_b.compare_full(flow_b)
    assert not flow_b.compare_full(flow_c)
    assert not flow_c.compare_full(flow_a)
    assert not flow_c.compare_full(flow_b)
    assert flow_c.compare_full(flow_c)


def test_match_host() -> None:
    """
    Test the method `match_host` of the class `Flow`.
    """
    flow_a = Flow([pkt_dict_a])
    flow_b = Flow([pkt_dict_b])
    flow_c = Flow([pkt_dict_c])
    flow_d = Flow([pkt_dict_d])
    flow_e = Flow([pkt_dict_e])
    flow_f = Flow([pkt_dict_f])

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
    Test the method `match_basic` of the class `Flow`.
    """
    flow_a = Flow([pkt_dict_a])
    flow_b = Flow([pkt_dict_b])
    flow_c = Flow([pkt_dict_c])
    flow_d = Flow([pkt_dict_d])
    flow_e = Flow([pkt_dict_e])
    flow_f = Flow([pkt_dict_f])

    assert flow_a == flow_a
    assert flow_a == flow_b
    assert flow_a == flow_c
    assert flow_a == flow_d
    assert flow_a != flow_e
    assert flow_a != flow_f
    assert flow_b == flow_a
    assert flow_b == flow_b
    assert flow_b == flow_c
    assert flow_b == flow_d
    assert flow_b != flow_e
    assert flow_b != flow_f
    assert flow_c == flow_a
    assert flow_c == flow_b
    assert flow_c == flow_c
    assert flow_c == flow_d
    assert flow_c != flow_e
    assert flow_c != flow_f
    assert flow_d == flow_a
    assert flow_d == flow_b
    assert flow_d == flow_c
    assert flow_d == flow_d
    assert flow_d != flow_e
    assert flow_e != flow_a
    assert flow_e != flow_b
    assert flow_e != flow_c
    assert flow_e != flow_d
    assert flow_e != flow_f
    assert flow_f != flow_a
    assert flow_f != flow_b
    assert flow_f != flow_c
    assert flow_f != flow_d
    assert flow_f != flow_e
