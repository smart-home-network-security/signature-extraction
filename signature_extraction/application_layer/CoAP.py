## Imports
# Libraries
from typing import Union
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
        self.type = CoAP.CoAPType(coap_layer.type)
        self.code = coap_codes[coap_layer.code]

        # URI path
        self.uri_path = None
        for key, value in coap_layer.options:
            if CoAP.is_uri_path(key):
                self.uri_path = self.uri_path + f"/{value}" if self.uri_path is not None else f"/{value}"
