## Imports
# Libraries
from scapy.all import IP, UDP
import scapy.layers.dhcp as dhcp
# Package
import signature_extraction.utils.distance as distance
from signature_extraction.application_layer import DHCP


### VARIABLES ###

## DHCP Discover packets
dhcp_discover_layer = (
    dhcp.BOOTP(chaddr="00:11:22:33:44:55") /
    dhcp.DHCP(options=[("message-type", "discover"), "end"])
)
dhcp_discover_pkt = (
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    dhcp_discover_layer
)

dhcp_discover_layer_2 = (
    dhcp.BOOTP(chaddr="00:11:22:33:44:66") /
    dhcp.DHCP(options=[("message-type", "discover"), "end"])
)

# DHCP Offer packet
dhcp_offer_layer = (
    dhcp.BOOTP(chaddr="00:11:22:33:44:55") /
    dhcp.DHCP(options=[("message-type", "offer"), "end"])
)
dhcp_offer_pkt = (
    IP(src="192.168.1.1", dst="192.168.1.2") /
    UDP(sport=67, dport=68) /
    dhcp_offer_layer
)

# DHCP Request packet
dhcp_request_layer = (
    dhcp.BOOTP(chaddr="00:11:22:33:44:55") /
    dhcp.DHCP(options=[("message-type", "request"), "end"])
)
dhcp_request_pkt = (
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    dhcp_request_layer
)

# DHCP Ack packet
dhcp_ack_layer = (
    dhcp.BOOTP(chaddr="00:11:22:33:44:55") /
    dhcp.DHCP(options=[("message-type", "ack"), "end"])
)
dhcp_ack_pkt = (
    IP(src="192.168.1.1", dst="192.168.1.2") /
    UDP(sport=67, dport=68) /
    dhcp_ack_layer
)

# Concrete objects
dhcp_discover = DHCP(dhcp_discover_layer)
dhcp_discover_2 = DHCP(dhcp_discover_layer_2)
dhcp_offer = DHCP(dhcp_offer_layer)
dhcp_request = DHCP(dhcp_request_layer)
dhcp_ack = DHCP(dhcp_ack_layer)


## From policy's protocol dictionary

# DHCP discover
dhcp_discover_policy_dict = {
    "client-mac": "00:11:22:33:44:55",
    "type": "discover"
}
dhcp_discover_from_policy = DHCP(dhcp_discover_policy_dict)

# DHCP offer
dhcp_offer_policy_dict = {
    "client-mac": "00:11:22:33:44:55",
    "type": "offer"
}
dhcp_offer_from_policy = DHCP(dhcp_offer_policy_dict)


### TEST FUNCTIONS ###

def test_dhcp_discover() -> None:
    """
    Test the constructor with a DHCP Discover packet.
    """
    dhcp_pkt = DHCP(dhcp_discover_pkt)
    assert dhcp_pkt.protocol_name == "DHCP"
    assert dhcp_pkt.get_protocol_name() == "DHCP"
    assert dhcp_pkt.client_mac == "00:11:22:33:44:55"
    assert dhcp_pkt.message_type == "discover"

    dhcp_dict = dict(dhcp_pkt)
    assert dhcp_dict["client_mac"] == "00:11:22:33:44:55"
    assert dhcp_dict["message_type"] == "discover"


def test_dhcp_offer() -> None:
    """
    Test the constructor with a DHCP Offer packet.
    """
    dhcp_pkt = DHCP(dhcp_offer_pkt)
    assert dhcp_pkt.protocol_name == "DHCP"
    assert dhcp_pkt.get_protocol_name() == "DHCP"
    assert dhcp_pkt.client_mac == "00:11:22:33:44:55"
    assert dhcp_pkt.message_type == "offer"

    dhcp_dict = dict(dhcp_pkt)
    assert dhcp_dict["client_mac"] == "00:11:22:33:44:55"
    assert dhcp_dict["message_type"] == "offer"


def test_dhcp_request() -> None:
    """
    Test the constructor with a DHCP Request packet.
    """
    dhcp_pkt = DHCP(dhcp_request_pkt)
    assert dhcp_pkt.protocol_name == "DHCP"
    assert dhcp_pkt.get_protocol_name() == "DHCP"
    assert dhcp_pkt.client_mac == "00:11:22:33:44:55"
    assert dhcp_pkt.message_type == "request"

    dhcp_dict = dict(dhcp_pkt)
    assert dhcp_dict["client_mac"] == "00:11:22:33:44:55"
    assert dhcp_dict["message_type"] == "request"


def test_dhcp_ack() -> None:
    """
    Test the constructor with a DHCP Ack packet.
    """
    dhcp_pkt = DHCP(dhcp_ack_pkt)
    assert dhcp_pkt.protocol_name == "DHCP"
    assert dhcp_pkt.get_protocol_name() == "DHCP"
    assert dhcp_pkt.client_mac == "00:11:22:33:44:55"
    assert dhcp_pkt.message_type == "ack"

    dhcp_dict = dict(dhcp_pkt)
    assert dhcp_dict["client_mac"] == "00:11:22:33:44:55"
    assert dhcp_dict["message_type"] == "ack"


def test_dhcp_discover_from_policy() -> None:
    """
    Test the constructor with a policy's protocol dictionary,
    which describes a DHCP Discover message.
    """
    assert dhcp_discover_from_policy.protocol_name == "DHCP"
    assert dhcp_discover_from_policy.get_protocol_name() == "DHCP"
    assert dhcp_discover_from_policy.client_mac == "00:11:22:33:44:55"
    assert dhcp_discover_from_policy.message_type == "discover"


def test_dhcp_offer_from_policy() -> None:
    """
    Test the constructor with a policy's protocol dictionary,
    which describes a DHCP Offer message.
    """
    assert dhcp_offer_from_policy.protocol_name == "DHCP"
    assert dhcp_offer_from_policy.get_protocol_name() == "DHCP"
    assert dhcp_offer_from_policy.client_mac == "00:11:22:33:44:55"
    assert dhcp_offer_from_policy.message_type == "offer"


def test_eq() -> None:
    """
    Test the equality operator.
    """
    assert dhcp_discover == dhcp_discover
    assert dhcp_discover != dhcp_discover_2
    assert dhcp_discover == dhcp_offer
    assert dhcp_discover == dhcp_request
    assert dhcp_discover == dhcp_ack
    assert dhcp_offer    == dhcp_request
    assert dhcp_offer    == dhcp_ack
    assert dhcp_request  == dhcp_ack
    assert dhcp_discover == dhcp_discover_from_policy
    assert dhcp_discover == dhcp_offer_from_policy


def test_hash() -> None:
    """
    Test the hash function.
    """
    assert hash(dhcp_discover) == hash(dhcp_offer)
    assert hash(dhcp_discover) != hash(dhcp_discover_2)
    assert hash(dhcp_discover) == hash(dhcp_request)
    assert hash(dhcp_discover) == hash(dhcp_ack)
    assert hash(dhcp_offer)    == hash(dhcp_request)
    assert hash(dhcp_offer)    == hash(dhcp_ack)
    assert hash(dhcp_request)  == hash(dhcp_ack)


def test_diff() -> None:
    """
    Test the diff function,
    which extracts the difference between two DHCP objects.
    """
    assert dhcp_discover.diff(dhcp_discover) == {}
    assert dhcp_discover.diff(dhcp_discover_2) == {
        DHCP.DhcpFields.CLIENT_MAC.value: (dhcp_discover.client_mac, dhcp_discover_2.client_mac)
    }
    assert dhcp_discover.diff(dhcp_offer) == {
        DHCP.DhcpFields.MESSAGE_TYPE.value: (dhcp_discover.message_type, dhcp_offer.message_type)
    }
    assert dhcp_discover.diff(dhcp_request) == {
        DHCP.DhcpFields.MESSAGE_TYPE.value: (dhcp_discover.message_type, dhcp_request.message_type)
    }
    assert dhcp_discover.diff(dhcp_ack) == {
        DHCP.DhcpFields.MESSAGE_TYPE.value: (dhcp_discover.message_type, dhcp_ack.message_type)
    }


def test_compute_distance() -> None:
    """
    Test the distance function.
    """
    dhcp_discover = DHCP(dhcp_discover_layer)
    dhcp_discover_2 = DHCP(dhcp_discover_layer_2)
    dhcp_offer = DHCP(dhcp_offer_layer)
    dhcp_request = DHCP(dhcp_request_layer)
    dhcp_ack = DHCP(dhcp_ack_layer)

    assert dhcp_discover.compute_distance(dhcp_discover) == 0
    assert dhcp_discover.compute_distance(dhcp_discover_2) == DHCP.WEIGHT_CLIENT * distance.ONE + DHCP.WEIGHT_TYPE * distance.ZERO
    assert dhcp_discover.compute_distance(dhcp_offer) == DHCP.WEIGHT_CLIENT * distance.ZERO + DHCP.WEIGHT_TYPE * distance.ONE
    assert dhcp_discover.compute_distance(dhcp_request) == DHCP.WEIGHT_CLIENT * distance.ZERO + DHCP.WEIGHT_TYPE * distance.ONE
    assert dhcp_discover.compute_distance(dhcp_ack) == DHCP.WEIGHT_CLIENT * distance.ZERO + DHCP.WEIGHT_TYPE * distance.ONE
