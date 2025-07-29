## Imports
# Libraries
from __future__ import annotations
from typing import Any
from enum import StrEnum
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

    # Distance metrics weights
    WEIGHT_CLIENT = Fraction(1, 2)
    WEIGHT_TYPE   = Fraction(1, 2)

    class DhcpFields(StrEnum):
        """
        DHCP Fields.
        """
        CLIENT_MAC   = "client_mac"
        MESSAGE_TYPE = "message_type"


    def __init__(self, data: dict | Packet) -> None:
        """
        Constructor of the DHCP class.

        Args:
            data (dict | Packet): DHCP data, either from a policy's protocol dictionary or a scapy packet.
        """
        # Given data is the policy's protocol dictionary
        if isinstance(data, dict):
            self.set_attr_from_dict("client_mac", data, "client-mac")
            self.set_attr_from_dict("message_type", data, "type")

        # Given data is a scapy packet
        elif isinstance(data, Packet):
            # Client MAC address
            bootp_layer = data.getlayer(BOOTP)
            self.client_mac = bootp_layer.chaddr.decode()
            # DHCP message type
            dhcp_options_layer = get_last_layer(data)
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
        return self.compare_attrs(other, "client_mac")


    def __hash__(self) -> int:
        """
        Hash function for the DHCP class,
        based on the client MAC address.

        Returns:
            int: hash value of the DHCP object.
        """
        attrs = ("client_mac", self.client_mac)
        return hash((self.protocol_name, attrs))
    

    def diff(self, other: DHCP) -> dict[str, tuple[Any, Any]]:
        """
        Compute the difference between this and another DHCP layer object.
        The difference is defined as a dictionary,
        with keys being the protocol field names,
        and the values being a tuple of the two different values.

        Args:
            other (DHCP): Other DHCP object
        Returns:
            dict[str, tuple[Any, Any]]: difference between this and another DHCP layer
        """
        # Initialize the difference dictionary
        diff = {}

        # If other is not a CoAP layer, return empty dictionary
        if not isinstance(other, DHCP):
            return diff
        
        # Client hardware address
        if self.client_mac != other.client_mac:
            diff[DHCP.DhcpFields.CLIENT_MAC.value] = (self.client_mac, other.client_mac)
        
        # Message type
        if self.message_type != other.message_type:
            diff[DHCP.DhcpFields.MESSAGE_TYPE.value] = (self.message_type, other.message_type)
        
        return diff


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
        

        # Client hardware address
        # 0 if identical, 1 if different
        distance_client_mac = discrete_distance(self.client_mac, other.client_mac)

        # Message type
        # 0 if identical, 1 if different
        distance_type = discrete_distance(self.message_type, other.message_type)

        return (
            DHCP.WEIGHT_CLIENT * distance_client_mac +
            DHCP.WEIGHT_TYPE * distance_type
        )
