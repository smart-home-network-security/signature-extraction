from scapy.all import Packet
from scapy.contrib.coap import CoAP, coap_codes
from .ApplicationLayer import ApplicationLayer

class CoAP(ApplicationLayer):
    """
    CoAP Application Layer Protocol.
    """
    protocol_name = "CoAP"
 
    def __init__(self, pkt: Packet) -> None:
        """
        Constructor of the CoAP class.
        """
        application_layer = pkt.getlayer("CoAP")
        print(application_layer)
