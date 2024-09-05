from __future__ import annotations
from typing import List, Iterator
from .PacketFingerprint import PacketFingerprint


class FlowFingerprint:

    def __init__(self, pkts: List[dict]) -> None:
        """
        Flow fingerprint constructor.

        Args:
            pkt (dict): dictionary containing the flow fingerprint attributes.
        """
        # Get the first packet to intiialize the flow fingerprint
        pkt = pkts[0]
        self.src                  = pkt["src"]
        self.dst                  = pkt["dst"]
        self.transport_protocol   = pkt["transport_protocol"]
        self.sport                = pkt["sport"]
        self.dport                = pkt["dport"]
        self.application_protocol = pkt["application_protocol"]
        self.timestamp            = pkt["timestamp"]

        # Compute flow length
        self.length = sum(pkt["length"] for pkt in pkts)


    
    @classmethod
    def build_from_packet(cls, pkt: PacketFingerprint) -> FlowFingerprint:
        """
        Build a flow fingerprint from a packet fingerprint.

        Args:
            pkt (PacketFingerprint): Packet fingerprint to build from.
        Returns:
            FlowFingerprint: Flow fingerprint.
        """
        return cls(pkt.to_dict())
    

    def __repr__(self) -> str:
        """
        String representation of a FlowFingerprint object.

        Returns:
            str: String representation of a FlowFingerprint object.
        """
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

        Returns:
            Iterable: Iterator over the packet fingerprint attributes.
        """
        yield "timestamp", self.timestamp
        yield "src", self.src
        yield "dst", self.dst
        yield "transport_protocol", self.transport_protocol
        yield "sport", self.sport
        yield "dport", self.dport
        yield "application_protocol", self.application_protocol
        yield "length", self.length
