## Imports
# Libraries
import scapy.all as scapy
from scapy.all import IP, IPv6, TCP, UDP
# Custom
from signature_extraction.utils.packet_utils import get_last_layer


class PacketFingerprint:
    """
    Packet fingeprint.
    """
    id = 0


    def __init__(self, pkt: scapy.Packet) -> None:
        """
        Packet fingerprint constructor.

        Args:
            pkt (scapy.Packet): Packet to initialize with.
        """
        self.id = PacketFingerprint.id
        PacketFingerprint.id += 1

        # Network layer: hosts (src & dst)
        if pkt.haslayer(IP):
            self.src = pkt.getlayer(IP).src
            self.dst = pkt.getlayer(IP).dst
        elif pkt.haslayer(IPv6):
            self.src = pkt.getlayer(IPv6).src
            self.dst = pkt.getlayer(IPv6).dst

        # Transport layer: protocol & ports
        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            self.transport_protocol = pkt.getlayer(2).name
            self.sport = pkt.sport
            self.dport = pkt.dport

        # Application layer
        self.application_protocol = get_last_layer(pkt).name
        # TODO: application-specific data
        #self.application_data = get_application_data(pkt)

        # Packet length
        self.length = len(pkt)

    
    def to_dict(self) -> dict:
        """
        Convert the packet fingerprint to a dictionary.

        Returns:
            dict: contains the PacketFingerprint attributes.
        """
        return {
            "id":                   self.id,
            "src":                  self.src,
            "dst":                  self.dst,
            "transport_protocol":   self.transport_protocol,
            "sport":                self.sport,
            "dport":                self.dport,
            "application_protocol": self.application_protocol,
            "length":               self.length
        }
