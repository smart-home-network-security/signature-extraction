## Imports
# Libraries
from scapy.all import Packet, Raw
import scapy.layers as scapy
# Package
from .ApplicationLayer import ApplicationLayer
from signature_extraction.utils.packet_utils import get_last_layer


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

        if self.response or other.response:
            # If one of the two objects is a response,
            # we cannot compare the fields.
            # ==> conservatively return True
            return True
        
        # Both objects are requests,
        # compare method & URI
        self_uri = self.uri[:-1] if self.uri.endswith(("*", "?")) else self.uri
        other_uri = other.uri[:-1] if other.uri.endswith(("*", "?")) else other.uri
        return self.method == other.method and self_uri == other_uri
    

    def __hash__(self) -> int:
        """
        Hash function for the ApplicationLayer class.

        Returns:
            int: hash value of the ApplicationLayer class.
        """
        return super().__hash__()
