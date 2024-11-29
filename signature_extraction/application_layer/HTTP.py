## Imports
# Libraries
from typing import Iterator
from scapy.all import Packet, Raw
import scapy.layers as scapy
# Package
from .ApplicationLayer import ApplicationLayer
from signature_extraction.utils import get_last_layer


class HTTP(ApplicationLayer):
    """
    HTTP Application Layer Protocol.
    """
    protocol_name = "HTTP"

    @staticmethod
    def is_response(pkt: Packet) -> bool:
        """
        Check if the HTTP packet is a request.
        """
        return isinstance(get_last_layer(pkt), scapy.http.HTTPResponse)


    def __init__(self, pkt: Packet) -> None:
        """
        Constructor of the HTTP class.

        Args:
            pkt (Packet): HTTP packet.
        """
        if pkt.haslayer(scapy.http.HTTP):
            application_layer = pkt.getlayer(scapy.http.HTTP)
        else:
            application_layer = scapy.http.HTTP(pkt.getlayer(Raw).getfieldval("load"))

        self.response = HTTP.is_response(application_layer)
        self.method = application_layer.Method.decode() if not self.response else None

        # URI
        uri = application_layer.Path.decode() if not self.response else None
        if uri is not None and "?" in uri:
            uri = uri.split("?")[0]
            uri += "*" if not uri.endswith("*") else ""
        self.uri = uri

    
    def __eq__(self, other: ApplicationLayer) -> bool:
        """
        Check if two HTTP packet layers pertain to the same data transfer.

        Args:
            other (ApplicationLayer): Other ApplicationLayer object
        Returns:
            bool: True if the two HTTP layers are equivalent
        """
        # Other object is not an HTTP layer, return False
        if not isinstance(other, HTTP):
            return False
        
        ## Other object is an HTTP layer

        if not self.response and not other.response:        
            # Both objects are requests,
            # compare method & URI
            self_uri = self.uri[:-1] if self.uri.endswith(("*", "?")) else self.uri
            other_uri = other.uri[:-1] if other.uri.endswith(("*", "?")) else other.uri
            return self.method == other.method and self_uri == other_uri
    
        # If one of the two objects is a response,
        # we cannot compare the fields.
        # ==> conservatively return True
        return True
    

    def __iter__(self) -> Iterator:
        """
        Iterate over the relevant class attributes.

        Returns:
            Iterator: iterator over the relevant class attributes
        """
        yield "response", self.response
        if self.method is not None:
            yield "method", self.method
        if self.uri is not None:
            yield "uri", self.uri
    

    def __hash__(self) -> int:
        """
        Hash function for the HTTP class.
        Conservatively returns the same value for all HTTP objects.

        Returns:
            int: hash value of the HTTP object
        """
        return hash(self.protocol_name)
