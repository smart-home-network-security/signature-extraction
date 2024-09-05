## Imports
# Libraries
from typing import Iterator
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

        # Metadata
        self.length = len(pkt)
        self.timestamp = pkt.time

    
    def __repr__(self) -> str:
        """
        String representation of a PacketFingerprint object.

        Returns:
            str: String representation of a PacketFingerprint object.
        """
        # ID
        s = f"[{self.id}] "
        # Timestamp
        s = f"{self.timestamp}:"
        # Source: host & port
        s += f" {self.src}:{self.sport} ->"
        # Destination: host & port
        s += f" {self.dst}:{self.dport}"
        # Transport protocol
        s += f" [{self.transport_protocol}]"
        # Application data
        s += f" ({self.application_protocol})"
        # Length
        s += f" {self.length} bytes"

        return s

    
    def __iter__(self) -> Iterator:
        """
        Iterate over the packet fingerprint attributes.
        """
        yield "id", self.id
        yield "timestamp", self.timestamp
        yield "src", self.src
        yield "dst", self.dst
        yield "transport_protocol", self.transport_protocol
        yield "sport", self.sport
        yield "dport", self.dport
        yield "application_protocol", self.application_protocol
        yield "length", self.length
