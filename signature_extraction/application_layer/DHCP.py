## Imports
# Libraries
from __future__ import annotations
from scapy.all import Packet
from scapy.layers.dhcp import BOOTP
from fractions import Fraction
# Package
from .ApplicationLayer import ApplicationLayer
from signature_extraction.utils import get_last_layer
from signature_extraction.utils.distance import discrete_distance


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
        # compare client_mac.
        return self.client_mac == other.client_mac


    def __hash__(self) -> int:
        """
        Hash function for the DHCP class,
        based on the client MAC address.

        Returns:
            int: hash value of the DHCP object.
        """
        attrs = ("client_mac", self.client_mac)
        return hash((self.protocol_name, attrs))


    def compute_distance(self, other: DHCP) -> Fraction:
        """
        Compute the distance between this and another DHCP layer.

        Args:
            other (DHCP): Other DHCP object
        Returns:
            Fraction: distance between this and another DHCP layer
        """
        # If other is not a DHCP layer, distance is maximal (1)
        if not isinstance(other, DHCP):
            return Fraction(1)
        

        WEIGHT_CLIENT = Fraction(1, 2)
        WEIGHT_TYPE   = Fraction(1, 2)

        # Client hardware address
        # 0 if identical, 1 if different
        distance_client_mac = discrete_distance(self.client_mac, other.client_mac)

        # Message type
        # 0 if identical, 1 if different
        distance_type = discrete_distance(self.message_type, other.message_type)

        return WEIGHT_CLIENT * distance_client_mac + WEIGHT_TYPE * distance_type
