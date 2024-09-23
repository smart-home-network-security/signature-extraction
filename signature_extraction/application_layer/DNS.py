## Imports
# Libraries
from typing import Iterator
from scapy.all import Packet
from scapy.layers.dns import dnstypes
# Package
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
        self.response = application_layer.qr == 1 if application_layer.qr else False
        self.qtype    = dnstypes.get(application_layer.qd[0].qtype, "Unknown")
        self.qname    = application_layer.qd[0].qname.decode()[:-1]

    
    def __iter__(self) -> Iterator:
        """
        Iterate over the class attributes.

        Returns:
            Iterator: iterator over the class attributes
        """
        for attr, value in self.__dict__.items():
            if attr == "qname":
                attr = "domain-name"
            yield attr, value
