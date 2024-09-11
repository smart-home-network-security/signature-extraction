## Imports
# Libraries
from scapy.all import Packet
from scapy.layers.dhcp import BOOTP
# Package
from .ApplicationLayer import ApplicationLayer
from signature_extraction.utils.packet_utils import get_last_layer


class DHCP(ApplicationLayer):
    """
    DHCP Application Layer Protocol.
    """
    protocol_name = "DHCP"
    dhcp_types = {
        "discover": 1,
        "offer":    2,
        "request":  3,
        "decline":  4,
        "ack":      5,
        "nak":      6,
        "release":  7,
        "inform":   8
    }


    def __init__(self, pkt: Packet) -> None:
        """
        Constructor of the DHCP class.
        """
        # Client MAC address
        bootp_layer = pkt.getlayer(BOOTP)
        self.client_mac = bootp_layer.chaddr.decode()
        # DHCP message type
        dhcp_options_layer = get_last_layer(pkt)
        self.message_type = dhcp_options_layer.options[0][1]
