from scapy.all import Packet
from scapy.layers.dns import DNS, DNSQR, DNSRR, dnstypes, dnsqtypes
from .ApplicationLayer import ApplicationLayer

class DNS(ApplicationLayer):
    """
    DNS Application Layer Protocol.
    """
    protocol_name = "DNS"
 
    def __init__(self, pkt: Packet) -> None:
        """
        Constructor of the DNS class.
        """
        application_layer = pkt.getlayer("DNS")
        print(application_layer)
