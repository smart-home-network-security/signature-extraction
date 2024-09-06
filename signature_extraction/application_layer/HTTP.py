## Imports
# Libraries
from scapy.all import Packet
from scapy.layers.http import HTTP, HTTPRequest
# Package
from .ApplicationLayer import ApplicationLayer
from signature_extraction.utils.packet_utils import get_last_layer


class HTTP(ApplicationLayer):
    """
    HTTP Application Layer Protocol.
    """
    protocol_name = "HTTP"

    @staticmethod
    def is_http_request(pkt: Packet) -> bool:
        """
        Check if the HTTP packet is a request.
        """
        return isinstance(get_last_layer(pkt), HTTPRequest)


    def __init__(self, pkt: Packet) -> None:
        """
        Constructor of the HTTP class.
        """
        application_layer = pkt.getlayer("HTTP")
        self.is_request = HTTP.is_http_request(pkt)
        self.method = application_layer.Method.decode() if self.is_request else None
        self.path = application_layer.Path.decode() if self.is_request else None
    

    def __repr__(self) -> str:
        """
        String representation of the HTTP class.
        """
        return f"HTTP - Request: {self.is_request}, Method: {self.method}, Path: \"{self.path}\""
