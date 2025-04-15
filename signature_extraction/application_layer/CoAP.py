## Imports
# Libraries
from __future__ import annotations
from typing import Union, Iterator
from enum import IntEnum
from scapy.all import Packet
from scapy.contrib.coap import CoAP, coap_codes
from fractions import Fraction
# Package
from .ApplicationLayer import ApplicationLayer
from signature_extraction.utils.distance import discrete_distance, levenshtein_ratio


class CoAP(ApplicationLayer):
    """
    CoAP Application Layer Protocol.
    """
    protocol_name = "CoAP"


    class CoAPType(IntEnum):
        """
        CoAP Type.
        """
        CON = 0
        NON = 1
        ACK = 2
        RST = 3


    @staticmethod
    def is_uri_path(coap_option_key: Union[int, str]) -> bool:
        """
        Check if the given CoAP option key is the URI path.

        Args:
            coap_option (Union[int, str]): CoAP option key.
        Returns:
            bool: True if the CoAP option key is the URI path, False otherwise.
        """
        return coap_option_key == 11 or coap_option_key == "Uri-Path"


    def __init__(self, pkt: Packet) -> None:
        """
        Constructor of the CoAP class.

        Args:
            pkt (Packet): CoAP packet.
        """
        coap_layer = pkt.getlayer(CoAP.protocol_name)

        # Request or response
        type = CoAP.CoAPType(coap_layer.type)
        self.is_request = type == CoAP.CoAPType.CON or type == CoAP.CoAPType.NON

        # Code and URI path are only considered for requests
        if self.is_request:
            # CoAP code
            self.code = coap_codes[coap_layer.code]
            # URI path
            self.uri_path = None
            for key, value in coap_layer.options:
                if CoAP.is_uri_path(key):
                    self.uri_path = self.uri_path + f"/{value}" if self.uri_path is not None else f"/{value}"

    
    def __eq__(self, other: ApplicationLayer) -> bool:
        """
        Check if two CoAP packet layers pertain to the same data transfer.

        Args:
            other (ApplicationLayer): Other ApplicationLayer object
        Returns:
            bool: True if the two CoAP layers are equivalent
        """
        # Other object is not an CoAP layer, return False
        if not isinstance(other, CoAP):
            return False
        
        ## Other object is a CoAP layer.
        
        if self.is_request and other.is_request:
            # Both objects are requests
            # ==> Compare code and URI path
            return (
                self.code == other.code and
                self.uri_path == other.uri_path
            )
        
        # One of the two objects is a response.
        # We cannot compare any field,
        # as responses do not contain URI data.
        return True
    

    def __iter__(self) -> Iterator:
        """
        Iterate over the relevant class attributes.

        Returns:
            Iterator: iterator over the relevant class attributes
        """
        yield "response", not self.is_request
        if self.is_request:
            yield "code", self.code
            yield "uri",  self.uri_path


    def __hash__(self) -> int:
        """
        Hash function for the CoAP class.
        Conservatively returns the same value for all CoAP objects.

        Returns:
            int: hash value of the CoAP object
        """
        return hash(self.protocol_name)
    

    def compute_distance(self, other: CoAP) -> Fraction:
        """
        Compute the distance between this and another CoAP layer.

        Args:
            other (CoAP): Other CoAP object
        Returns:
            Fraction: distance between this and another CoAP layer
        """
        # If other is not a CoAP layer, distance is maximal (1.0)
        if not isinstance(other, CoAP):
            return Fraction(1)
        

        WEIGHT_CODE = Fraction(1, 2)
        WEIGHT_URI  = Fraction(1, 2)

        # CoAP code
        # 0 if identical, 1 if different
        distance_code = Fraction(1)
        try:
            distance_code = discrete_distance(self.code, other.code)
        except AttributeError:
            pass

        # URI path
        # Levenshtein distance
        distance_uri = Fraction(1)
        try:
            distance_uri = levenshtein_ratio(self.uri_path, other.uri_path)
        except AttributeError:
            pass
        
        return WEIGHT_CODE * distance_code + WEIGHT_URI * distance_uri
