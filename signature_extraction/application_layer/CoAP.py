## Imports
# Libraries
from typing import Union, Iterator
from enum import IntEnum
from scapy.all import Packet
from scapy.contrib.coap import CoAP, coap_codes
# Package
from .ApplicationLayer import ApplicationLayer


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
        yield "request", self.is_request
        if self.is_request:
            yield "code", self.code
            yield "uri",  self.uri_path


    def __hash__(self) -> int:
        """
        Hash function for the ApplicationLayer class.

        Returns:
            int: hash value of the ApplicationLayer object.
        """
        return super().__hash__()
