## Imports
# Libraries
from enum import IntEnum
from scapy.all import Packet
from scapy.layers.dns import DNS, dnstypes
# Package
from .ApplicationLayer import ApplicationLayer


class DNS(ApplicationLayer):
    """
    DNS Application Layer Protocol.
    """
    protocol_name = "DNS"


    class DNSQR(IntEnum):
        """
        DNS QR flag.
        """
        QUERY    = 0
        RESPONSE = 1

 
    def __init__(self, pkt: Packet) -> None:
        """
        Constructor of the DNS class.
        """
        application_layer = pkt.getlayer("DNS")
        self.qr = DNS.DNSQR(application_layer.qr) if application_layer.qr else DNS.DNSQR.QUERY
        self.qtype = dnstypes.get(application_layer.qd.qtype, "Unknown")
        self.qname = application_layer.qd.qname.decode()
