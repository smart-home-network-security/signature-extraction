## Imports
# Libraries
from __future__ import annotations
from typing import List, Iterator
import scapy.all as scapy
from scapy.all import IP, IPv6, TCP, UDP
# Package
from signature_extraction.utils import DnsTableKeys, if_correct_type, guess_network_protocol, get_domain_name_from_ip
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


    @staticmethod
    def replace_ips_with_domains(pkts: List[Packet], dns_table: dict) -> List[Packet]:
        """
        Replace IP addresses with corresponding domain names in a list of packets.
        Given list will be modified in-place.
        The DNS table has the following format:
            {
                DnsTableKeys.IP: {
                    ip_address: domain_name,
                    ...
                },
                DnsTableKeys.ALIAS: {
                    canonical_name: alias,
                    ...
                }
            }

        Args:
            pkts (List[Packet]): List of packets.
            dns_table (dict): Dictionary containing IP addresses and their associated domain names.
        Returns:
            List[Packet]: the given list of packets, with IP addresses replaced by domain names.
        """
        for pkt in pkts:
            pkt.set_domain_names(dns_table)

        return pkts


    def __init__(self, pkt: dict) -> None:
        """
        Packet constructor.

        Args:
            pkt (dict): dictionary containing the packet attributes.
        """
        self.id = Packet.id
        Packet.id += 1

        self.src = if_correct_type(pkt["src"], str)
        self.dst = if_correct_type(pkt["dst"], str)

        # Set network-layer protocol
        self.network_protocol = "IPv4"  # Default: IPv4
        if "network_protocol" in pkt:
            self.network_protocol = if_correct_type(pkt["network_protocol"], str, "IPv4")
        else:
            # Guess network protocol from hosts
            for host in (self.src, self.dst):
                try:
                    self.network_protocol = guess_network_protocol(host)
                    break
                except ValueError:
                    pass

        self.transport_protocol   = if_correct_type(pkt.get("transport_protocol", None), str)
        self.sport                = if_correct_type(pkt.get("sport", None), int)
        self.dport                = if_correct_type(pkt.get("dport", None), int)
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
            pkt_dict["network_protocol"] = "IPv4"
            pkt_dict["src"] = pkt.getlayer(IP).src
            pkt_dict["dst"] = pkt.getlayer(IP).dst
        elif pkt.haslayer(IPv6):
            pkt_dict["network_protocol"] = "IPv6"
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
        except (ValueError, AttributeError):
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
            self.network_protocol == other.network_protocol
            and self.src == other.src
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
        yield "network_protocol", self.network_protocol
        yield "src", self.src
        yield "dst", self.dst
        yield "transport_protocol", self.transport_protocol
        yield "sport", self.sport
        yield "dport", self.dport
        yield "application_layer", self.application_layer
        yield "length", self.length

    
    def set_domain_names(self, dns_table: dict) -> None:
        """
        Replace IP addresses with domain names in the Packet.

        Args:
            dns_table (dict): dictionary of IP addresses and their corresponding domain name
        """
        if DnsTableKeys.IP.name in dns_table:
            
            # Source address
            try:
                self.src = get_domain_name_from_ip(self.src, dns_table)
            except KeyError:
                pass

            # Destination address
            try:
                self.dst = get_domain_name_from_ip(self.dst, dns_table)
            except KeyError:
                pass
