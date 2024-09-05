from __future__ import annotations
from typing import List, Iterator
from .PacketFingerprint import PacketFingerprint


class FlowFingerprint:
    """
    Summary of a network flow, containing the following attributes:
        - Timestamp
        - Source & destination hosts
        - Transport protocol
        - Source & destination ports
        - Application protocol
        - Length
    """

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
    

    def __eq__(self, other: FlowFingerprint) -> bool:
        """
        Compare two FlowFingerprint objects.

        Args:
            other (FlowFingerprint): Flow fingerprint to compare with.
        Returns:
            bool: True if the flow fingerprints are equal, False otherwise.
        """
        # If other object is not a FlowFingerprint, return False
        if not isinstance(other, FlowFingerprint):
            return False
        
        # If other object is a FlowFingerprint, compare attributes
        return (
            self.src == other.src
            and self.dst == other.dst
            and self.transport_protocol == other.transport_protocol
            and self.sport == other.sport
            and self.dport == other.dport
            and self.application_protocol == other.application_protocol
        )
    

    def str_base(self) -> str:
        """
        String representation of the base flow fingerprint attributes,
        without timestamp and length.

        Returns:
            str: String representation of the base flow fingerprint attributes.
        """
        # Source: host & port
        s = f"{self.src}:{self.sport} ->"
        # Destination: host & port
        s += f" {self.dst}:{self.dport}"
        # Transport protocol
        s += f" [{self.transport_protocol}]"
        # Application data
        s += f" ({self.application_protocol})"

        return s


    def __repr__(self) -> str:
        """
        String representation of a FlowFingerprint object.

        Returns:
            str: String representation of a FlowFingerprint object.
        """
        # Timestamp
        s = f"{self.timestamp}: "
        # Base attributes
        s += self.str_base()
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
