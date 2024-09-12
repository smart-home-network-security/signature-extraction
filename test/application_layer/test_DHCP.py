## Imports
# Libraries
from scapy.all import IP, UDP
import scapy.layers.dhcp as dhcp
# Package
from signature_extraction.application_layer import DHCP


### VARIABLES ###

# DHCP Discover packet
dhcp_discover = (
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    dhcp.BOOTP(chaddr="00:11:22:33:44:55") /
    dhcp.DHCP(options=[("message-type", "discover"), "end"])
)

# DHCP Offer packet
dhcp_offer = (
    IP(src="192.168.1.1", dst="192.168.1.2") /
    UDP(sport=67, dport=68) /
    dhcp.BOOTP(chaddr="00:11:22:33:44:55") /
    dhcp.DHCP(options=[("message-type", "offer"), "end"])
)

# DHCP Request packet
dhcp_request = (
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    dhcp.BOOTP(chaddr="00:11:22:33:44:55") /
    dhcp.DHCP(options=[("message-type", "request"), "end"])
)

# DHCP Ack packet
dhcp_ack = (
    IP(src="192.168.1.1", dst="192.168.1.2") /
    UDP(sport=67, dport=68) /
    dhcp.BOOTP(chaddr="00:11:22:33:44:55") /
    dhcp.DHCP(options=[("message-type", "ack"), "end"])
)


### TEST FUNCTIONS ###

def test_dhcp_discover() -> None:
    """
    Test the constructor with a DHCP Discover packet.
    """
    dhcp_pkt = DHCP(dhcp_discover)
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
    dhcp_pkt = DHCP(dhcp_offer)
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
    dhcp_pkt = DHCP(dhcp_request)
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
    dhcp_pkt = DHCP(dhcp_ack)
    assert dhcp_pkt.protocol_name == "DHCP"
    assert dhcp_pkt.get_protocol_name() == "DHCP"
    assert dhcp_pkt.client_mac == "00:11:22:33:44:55"
    assert dhcp_pkt.message_type == "ack"

    dhcp_dict = dict(dhcp_pkt)
    assert dhcp_dict["client_mac"] == "00:11:22:33:44:55"
    assert dhcp_dict["message_type"] == "ack"
