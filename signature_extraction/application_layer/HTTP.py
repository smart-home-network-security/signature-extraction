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
