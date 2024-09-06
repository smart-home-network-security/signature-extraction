from scapy.all import Packet
from scapy.layers.dhcp import DHCP, DHCPTypes
from .ApplicationLayer import ApplicationLayer

class DHCP(ApplicationLayer):
    """
    DHCP Application Layer Protocol.
    """
    protocol_name = "DHCP"
 
    def __init__(self, pkt: Packet) -> None:
        """
        Constructor of the DHCP class.
        """
        application_layer = pkt.getlayer("DHCP")
        print(application_layer)
