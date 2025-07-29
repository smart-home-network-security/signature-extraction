## Imports
# Libraries
from __future__ import annotations
from typing import Union, Iterator, Any
from enum import IntEnum, StrEnum
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

    # Distance metrics weights
    WEIGHT_CODE = Fraction(1, 2)
    WEIGHT_URI  = Fraction(1, 2)

    class CoAPFields(StrEnum):
        """
        CoAP Fields.
        """
        CODE = "code"
        URI  = "uri"

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


    def __init__(self, data: dict | Packet) -> None:
        """
        Constructor of the CoAP class.

        Args:
            data (dict | Packet): CoAP data, either from a policy's protocol dictionary or a scapy packet.
        """
        # Given data is the policy's protocol dictionary
        if isinstance(data, dict):
            self.set_attr_from_dict("type", data, "type")
            self.set_attr_from_dict("code", data, "method")
            self.set_attr_from_dict("uri_path", data, "uri")
            self.is_request = data.get("response", True)

        # Given data is a scapy packet
        elif isinstance(data, Packet):
            coap_layer = data.getlayer(CoAP.protocol_name)

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
        
        if self.compare_attrs(other, "is_request"):
            # Both objects are requests
            # ==> Compare code and URI path
            return (
                self.compare_attrs(other, "code") and
                self.compare_attrs(other, "uri_path")
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
    

    def diff(self, other: CoAP) -> dict[str, tuple[Any, Any]]:
        """
        Compute the difference between this and another CoAP layer object.
        The difference is defined as a dictionary,
        with keys being the protocol field names,
        and the values being a tuple of the two different values.

        Args:
            other (CoAP): Other CoAP object
        Returns:
            dict[str, tuple[Any, Any]]: difference between this and another CoAP layer
        """
        # Initialize the difference dictionary
        diff = {}

        # If other is not a CoAP layer, return empty dictionary
        if not isinstance(other, CoAP):
            return diff

        # If both objects are responses,
        # return empty dictionary
        if not self.is_request and not other.is_request:
            return diff

        # CoAP code
        if hasattr(self, "code") and not hasattr(other, "code"):
            diff[CoAP.CoAPFields.CODE.value] = (self.code, None)
        elif not hasattr(self, "code") and hasattr(other, "code"):
            diff[CoAP.CoAPFields.CODE.value] = (None, other.code)
        elif (hasattr(self, "code") and hasattr(other, "code") and
              self.code != other.code):
            diff[CoAP.CoAPFields.CODE.value] = (self.code, other.code)

        # URI path
        if hasattr(self, "uri_path") and not hasattr(other, "uri_path"):
            diff[CoAP.CoAPFields.URI.value] = (self.uri_path, None)
        elif not hasattr(self, "uri_path") and hasattr(other, "uri_path"):
            diff[CoAP.CoAPFields.URI.value] = (None, other.uri_path)
        elif (hasattr(self, "uri_path") and hasattr(other, "uri_path") and
              self.uri_path != other.uri_path):
            diff[CoAP.CoAPFields.URI.value] = (self.uri_path, other.uri_path)

        return diff
    

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
        
        # If both objects are responses,
        # distance is 0 (identical)
        if not self.is_request and not other.is_request:
            return Fraction(0)


        # CoAP code
        distance_code = Fraction(1)
        if not hasattr(self, "code") and not hasattr(other, "code"):
            # Neither of the two objects provide a CoAP code
            distance_uri = Fraction(0)
        else:
            # General case: discrete distance
            try:
                distance_code = discrete_distance(self.code, other.code)
            except AttributeError:
                pass

        # URI path
        distance_uri = Fraction(1)
        if not hasattr(self, "uri_path") and not hasattr(other, "uri_path"):
            # Neither of the two objects provide a URI path
            distance_uri = Fraction(0)
        else:
            # General case: Levenshtein distance
            try:
                distance_uri = levenshtein_ratio(self.uri_path, other.uri_path)
            except AttributeError:
                pass
        
        return (
            CoAP.WEIGHT_CODE * distance_code +
            CoAP.WEIGHT_URI * distance_uri
        )
