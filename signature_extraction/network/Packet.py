## Imports
# Libraries
from __future__ import annotations
from typing import Iterator
import scapy.all as scapy
from scapy.all import IP, IPv6, TCP, UDP
# Package
from signature_extraction.application_layer import ApplicationLayer


class Packet:
    """
    Summary of a packet, containing the following attributes:
        - Timestamp
        - Source & destination hosts
        - Transport protocol
        - Source & destination ports
        - Application protocol
        - Length
    """
    id = 0


    def __init__(self, pkt: dict) -> None:
        """
        Flow fingerprint constructor.

        Args:
            pkt (dict): dictionary containing the packet fingerprint attributes.
        """
        self.id = Packet.id
        Packet.id += 1
        self.src                  = pkt["src"]
        self.dst                  = pkt["dst"]
        self.transport_protocol   = pkt.get("transport_protocol", None)
        self.sport                = pkt.get("sport", None)
        self.dport                = pkt.get("dport", None)
        self.application_layer    = pkt.get("application_layer", None)
        self.timestamp            = pkt["timestamp"]
        self.length               = pkt["length"]


    @classmethod
    def build_from_pkt(cls, pkt: scapy.Packet) -> Packet:
        """
        Build a Packet object from a scapy packet.

        Args:
            pkt (scapy.Packet): Packet to initialize with.
        Returns:
            Packet: Packet fingerprint.
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
            if pkt.haslayer(TCP):
                pkt_dict["transport_protocol"] = "TCP"
            elif pkt.haslayer(UDP):
                pkt_dict["transport_protocol"] = "UDP"
            pkt_dict["sport"] = pkt.sport
            pkt_dict["dport"] = pkt.dport

        # Application layer
        try:
            pkt_dict["application_layer"] = ApplicationLayer.init_protocol(pkt)
        except ValueError:
            pkt_dict["application_layer"] = None

        # Metadata
        pkt_dict["length"] = len(pkt)
        pkt_dict["timestamp"] = pkt.time

        # Create Packet object
        return cls(pkt_dict)
    

    def __eq__(self, other: Packet) -> bool:
        """
        Compare two Packet objects.

        Args:
            other (Packet): Packet fingerprint to compare with.
        Returns:
            bool: True if the flow fingerprints are equal, False otherwise.
        """
        # If other object is not a Packet, return False
        if not isinstance(other, Packet):
            return False
        
        # If other object is a Packet, compare attributes
        return (
            self.src == other.src
            and self.dst == other.dst
            and self.transport_protocol == other.transport_protocol
            and self.sport == other.sport
            and self.dport == other.dport
            and self.application_layer == other.application_layer
        )
    

    def __lt__(self, other: Packet) -> bool:
        """
        Check if this Packet is less than another Packet.

        Args:
            other (Packet): Packet to compare with.
        Returns:
            bool: True if this Packet is less than the other Packet, False otherwise.
        Raises:
            ValueError: If the other object is not a Packet.
        """
        # If other object is not a Packet, raise an error
        if not isinstance(other, Packet):
            return NotImplemented
        
        # If other object is a Packet, compare timestamps
        return self.timestamp < other.timestamp
    

    def __gt__(self, other: Packet) -> bool:
        """
        Check if this Packet is greater than another Packet.

        Args:
            other (Packet): Packet to compare with.
        Returns:
            bool: True if this Packet is greater than the other Packet, False otherwise.
        Raises:
            ValueError: If the other object is not a Packet.
        """
        # If other object is not a Packet, raise an error
        if not isinstance(other, Packet):
            return NotImplemented
        
        # If other object is a Packet, compare timestamps
        return self.timestamp > other.timestamp

    
    def __repr__(self) -> str:
        """
        String representation of a Packet object.

        Returns:
            str: String representation of a Packet object.
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
        s += f" ({self.application_layer})"
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
        yield "application_layer", self.application_layer
        yield "length", self.length

    
    def set_domain_names(self, domain_names: dict) -> None:
        """
        Replace IP addresses with domain names in the Packet.

        Args:
            domain_names (dict): dictionary of domain names associated with IP addresses.
        """
        src_replaced = False
        dst_replaced = False

        for domain_name, ip_addresses in domain_names.items():            
            if self.src in ip_addresses:
                self.src = domain_name
                src_replaced = True
            if self.dst in ip_addresses:
                self.dst = domain_name
                dst_replaced = True
            
            # Early stopping
            if src_replaced and dst_replaced:
                return
