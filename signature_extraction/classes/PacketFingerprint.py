## Imports
# Libraries
from __future__ import annotations
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


    def __init__(self, pkt: dict) -> None:
        """
        Flow fingerprint constructor.

        Args:
            pkt (dict): dictionary containing the packet fingerprint attributes.
        """
        self.id = PacketFingerprint.id
        PacketFingerprint.id += 1
        self.src                  = pkt["src"]
        self.dst                  = pkt["dst"]
        self.transport_protocol   = pkt["transport_protocol"]
        self.sport                = pkt["sport"]
        self.dport                = pkt["dport"]
        self.application_protocol = pkt["application_protocol"]
        self.timestamp            = pkt["timestamp"]
        self.length               = pkt["length"]


    @classmethod
    def build_from_packet(cls, pkt: scapy.Packet) -> PacketFingerprint:
        """
        Build a PacketFingerprint object from a scapy packet.

        Args:
            pkt (scapy.Packet): Packet to initialize with.
        Returns:
            PacketFingerprint: Packet fingerprint.
        """
        # Initialize packet dictionary
        pkt_dict = {}

        # Network layer: hosts (src & dst)
        if pkt.haslayer(IP):
            pkt_dict["src"] = pkt.getlayer(IP).src
            pkt_dict["dst"] = pkt.getlayer(IP).dst
        elif pkt.haslayer(IPv6):
            pkt_dict["src"] = pkt.getlayer(IPv6).src
            pkt_dict["dst"] = pkt.getlayer(IPv6).dst

        # Transport layer: protocol & ports
        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            pkt_dict["transport_protocol"] = pkt.getlayer(2).name
            pkt_dict["sport"] = pkt.sport
            pkt_dict["dport"] = pkt.dport

        # Application layer
        pkt_dict["application_protocol"] = get_last_layer(pkt).name
        # TODO: application-specific data
        #pkt_dict["application_data"] = get_application_data(pkt)

        # Metadata
        pkt_dict["length"] = len(pkt)
        pkt_dict["timestamp"] = pkt.time

        # Create PacketFingerprint object
        return cls(pkt_dict)

    
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
