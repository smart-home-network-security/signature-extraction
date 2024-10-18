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
    

    def __eq__(self, other: ApplicationLayer) -> bool:
        """
        Check if two DHCP packet layers pertain to the same data transfer.

        Args:
            other (ApplicationLayer): Other ApplicationLayer object
        Returns:
            bool: True if the two DHCP layers are equivalent
        """
        # Other object is not a DHCP layer, return False
        if not isinstance(other, DHCP):
            return False
        
        # Other object is a DHCP layer,
        # compare qtype and qname
        return self.qtype == other.qtype and self.qname == other.qname
