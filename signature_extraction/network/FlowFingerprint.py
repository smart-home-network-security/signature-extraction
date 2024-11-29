## Imports
# Libraries
from __future__ import annotations
from typing import Union, Iterator
import os
import time
from ipaddress import IPv4Address
# Package
from .Packet import Packet
from signature_extraction.utils import is_known_port, compare_hosts
from profile_translator_blocklist import translate_policy
# Logging
import importlib
import logging
module_relative_path = importlib.import_module(__name__).__name__
logger = logging.getLogger(module_relative_path)


class FlowFingerprint:
    """
    Fingerprint of a network flow,
    matching only the following attributes:
        - Source & destination hosts
        - Transport protocol
        - Fixed port (to be computed)
        - Application protocol
    """

    def __init__(self, flow_data: Union[dict, Packet, list]) -> None:
        """
        FlowFingerprint constructor.

        Args:
            flow_data (dict | Packet | list): flow fingerprint data.
        """
        # Set FlowFingerprint as bidirectional by default
        self.bidirectional = True

        self.count = 1  # Number of flows added to this FlowFingerprint

        # If given data is not a dictionary, convert it
        if isinstance(flow_data, Packet):
            flow_data = dict(flow_data)
        elif isinstance(flow_data, list):
            first_item = flow_data[0]
            if isinstance(first_item, Packet):
                flow_data = dict(first_item)
            else:
                flow_data = first_item

        # Set attributes
        self.src                = flow_data["src"]
        self.dst                = flow_data["dst"]
        self.transport_protocol = flow_data["transport_protocol"]
        self.application_layer  = flow_data.get("application_layer", None)
        if not self.application_layer:
            self.application_layer = None
 
        # Initialize ports (to be computed)
        self.ports = {}
        self._add_ports(flow_data)
    

    def get_fixed_ports(self) -> set[(str, int)]:
        """
        Compute the fixed port of the FlowFingerprint.

        Returns:
            Tuple[int, str]: Fixed port number and corresponding host.
        """
        # Initialize fixed_ports
        fixed_ports = set()

        # Iterate over hosts and ports
        for (host, port), count in self.ports.items():

            # Current port number is considered as fixed if ...
            if (
                is_known_port(port, self.transport_protocol) or  # ... it is a well-known port
                (count > 1 and count == self.count)              # ... it was used for all flows
            ):
                fixed_ports.add((host, port))

        # Return fixed ports
        return fixed_ports


    def _add_ports(self, flow_dict: dict = {}) -> dict:
        """
        Add ports' data from a dictionary.

        Args:
            flow_dict (dict): dictionary to add ports' data from.
        Returns:
            dict: Updated ports dictionary.
        """
        # Source host & port
        src = flow_dict["src"]
        sport = flow_dict["sport"]
        src_sport = (src, sport)
        self.ports[src_sport] = self.ports.get(src_sport, 0) + 1
        
        # Destination host & port
        dst = flow_dict["dst"]
        dport = flow_dict["dport"]
        dst_dport = (dst, dport)
        self.ports[dst_dport] = self.ports.get(dst_dport, 0) + 1

        return self.ports
    

    def add_ports(self, other: FlowFingerprint) -> dict:
        """
        Add ports from a given FlowFingerprint object.

        Args:
            flow_fingerprint (FlowFingerprint): FlowFingerprint object to add ports from.
        Returns:
            dict: Updated ports dictionary.
        """
        # If other object is not an FlowFingerprint, return False
        if not isinstance(other, FlowFingerprint):
            return False
        
        for (host, port), count in other.ports.items():
            try:
                h, p = next((h, p) for h, p in self.ports if compare_hosts(h, host) and p == port)
                self.ports[(h, p)] += count
            except StopIteration:
                self.ports[(host, port)] = count

        return self.ports


    def add_flow(self, flow: FlowFingerprint) -> None:
        """
        Add attributes of the given FlowFingerprint object to this FlowFingerprint.

        Args:
            flow (FlowFingerprint): FlowFingerprint object to add.
        """
        # Update attributes if needed
        self.src = flow.src if not self.src else self.src
        self.dst = flow.dst if not self.dst else self.dst
        self.transport_protocol = flow.transport_protocol if not self.transport_protocol else self.transport_protocol
        self.application_layer = flow.application_layer if not self.application_layer else self.application_layer
        self.count += flow.count
        self.add_ports(flow)

    
    def match_host(self, other: FlowFingerprint) -> bool:
        """
        Match FlowFingerprint objects based on source and destination hosts,
        regardless of the direction.

        Args:
            other (FlowFingerprint): FlowFingerprint to match with.
        Returns:
            bool: True if the FlowFingerprints' hosts match, False otherwise.
        """
        # If other object is not an FlowFingerprint, return False
        if not isinstance(other, FlowFingerprint):
            return False
        
        are_hosts_matching = (
            compare_hosts(self.src, other.src) and compare_hosts(self.dst, other.dst) or
            compare_hosts(self.src, other.dst) and compare_hosts(self.dst, other.src)
        )
        return are_hosts_matching
    

    def match_ports(self, other: FlowFingerprint) -> bool:
        """
        Check if the ports of given FlowFingerprint object,
        match the ports of this FlowFingerprint object.

        Args:
            other (FlowFingerprint): FlowFingerprint to match with.
        Returns:
            bool: True if the given FlowFingerprints' ports match, False otherwise.
        """
        # If other object is not an FlowFingerprint, return False
        if not isinstance(other, FlowFingerprint):
            return False
        
        for (host, port) in other.ports.keys():
            try:
                h, p = next((h, p) for h, p in self.ports if compare_hosts(h, host))
                if (h, p) in self.get_fixed_ports() and port != p:
                    return False
            except StopIteration:
                return False
        
        return True

    
    def match_flow(self, other: FlowFingerprint) -> bool:
        """
        Compare the given FlowFingerprint with this FlowFingerprint,
        based on the following attributes:
            - Hosts (in any direction)
            - Fixed port
            - Transport protocol
            - Application layer protocol

        Args:
            other (FlowFingerprint): FlowFingerprint to match with.
        Returns:
            bool: True if the given FlowFingerprint matches, False otherwise.
        """
        # If other object is not a FlowFingerprint, return False
        if not isinstance(other, FlowFingerprint):
            return False
        
        # If other object is a FlowFingerprint, compare attributes:
        are_flow_matching = (
            # Hosts (in any direction)
            self.match_host(other) and
            # Fixed port
            self.match_ports(other) and
            # Transport protocol
            self.transport_protocol == other.transport_protocol and
            # Application layer protocol
            self.application_layer == other.application_layer
        )
        return are_flow_matching


    def __repr__(self) -> str:
        """
        String representation of a FlowFingerprint object.

        Returns:
            str: String representation of a FlowFingerprint object.
        """
        fixed_ports = self.get_fixed_ports()

        ## Hosts
        # Source
        s = f"{self.src}"
        for host, port in fixed_ports:
            if host == self.src:
                s += f":{port}"
        s += " <-> "
        # Destination
        s += f"{self.dst}"
        for host, port in fixed_ports:
            if host == self.dst:
                s += f":{port}"

        ## Protocol(s)
        # Transport layer
        s += f" [{self.transport_protocol}"
        # Application layer
        if self.application_layer is not None and self.application_layer != self.transport_protocol:
            s += f" / {self.application_layer}"
        s += "]"

        return s

    
    def __iter__(self) -> Iterator:
        """
        Iterate over the packet fingerprint attributes.

        Returns:
            Iterable: Iterator over the packet fingerprint attributes.
        """
        fixed_ports = self.get_fixed_ports()

        ## Hosts
        # Source
        yield "src", self.src
        for host, port in fixed_ports:
            if host == self.src:
                yield "sport", port
        else:
            yield "sport", None
        # Destination
        yield "dst", self.dst
        for host, port in fixed_ports:
            if host == self.dst:
                yield "dport", port
        else:
            yield "dport", None

        ## Protocol(s)
        # Transport layer
        yield "transport_protocol", self.transport_protocol
        # Application layer
        if self.application_layer != self.transport_protocol:
            yield "application_layer", self.application_layer
        else:
            yield "application_layer", None


    def get_id(self) -> str:
        """
        Generate an identifier for this FlowFingerprint.

        Returns:
            str: Identifier for this FlowFingerprint.
        """
        id = f"{self.src}-{self.dst}_{self.transport_protocol}"
        fixed_ports = self.get_fixed_ports()

        # Hosts & ports
        if fixed_ports:
            is_fixed_port = False
            for host, port in fixed_ports:
                if host == self.src:
                    is_fixed_port = True
                    id += f"_src_{port}"
                elif host == self.dst:
                    is_fixed_port = True
                    id += f"_dst_{port}"
            if not is_fixed_port:
                id += f"_{port}"
            
        # Application layer
        if self.application_layer is not None:
            id += f"_{repr(self.application_layer)}"
        
        return id

    
    def get_unique_id(self) -> str:
        """
        Generate a unique identifier for this FlowFingerprint,
        based on the current time.

        Returns:
            str: Unique identifier for this FlowFingerprint.
        """
        return f"{self.get_id()}_{int(time.time())}"


    def extract_policy(self, ipv4: IPv4Address) -> dict:
        """
        Extract a profile-compliant policy from this FlowFingerprint.
        
        Args:
            ipv4 (IPv4Address): IP address of the device.
        Returns:
            dict: Policy extracted from the FlowFingerprint.
        """
        # Hosts
        src_ip = "self" if self.src == str(ipv4) else self.src.replace("*","$")
        dst_ip = "self" if self.dst == str(ipv4) else self.dst.replace("*","$")
        policy = {
            "protocols": {
                "ipv4": {"src": src_ip, "dst": dst_ip}
            }
        }

        # Protocols
        protocol = self.transport_protocol.lower()
        fixed_ports = self.get_fixed_ports()
        if fixed_ports:
            is_fixed_port = False
            for host, port in fixed_ports:
                if host == self.src:
                    is_fixed_port = True
                    if protocol not in policy["protocols"]:
                        policy["protocols"][protocol] = {}
                    policy["protocols"][protocol]["src-port"] = port
                elif host == self.dst:
                    is_fixed_port = True
                    if protocol not in policy["protocols"]:
                        policy["protocols"][protocol] = {}
                    policy["protocols"][protocol]["dst-port"] = port
            if not is_fixed_port:
                policy["protocols"][protocol] = {}
        else:
            policy["protocols"][protocol] = {}

        # Application layer protocol
        if self.application_layer is not None:
            app_protocol = self.application_layer.get_protocol_name().lower()
            attrs = dict(self.application_layer)
            if "domain-name" in attrs:
                attrs["domain-name"] = attrs["domain-name"].replace("*","$")
            policy["protocols"][app_protocol] = attrs
        
        policy["bidirectional"] = self.bidirectional

        return policy


    def translate_to_firewall(self, device_name: str, ipv4: IPv4Address, output_dir: str = os.getcwd()) -> None:
        """
        Translate the FlowFingerprint to a firewall rule.

        Args:
            device_name (str): Name of the device.
            ipv4 (IPv4Address): IP address of the device.
            output_dir (str): Output directory. Optional, defaults to the current working directory.
        """
        # Validate output directory
        if not os.path.isdir(output_dir):
            logger.warning(f"Output directory {output_dir} does not exist. Using current directory.")
            output_dir = os.getcwd()
        
        # Device metadata
        device = {
            "name": device_name,
            "ipv4": str(ipv4)
        }

        policy = self.extract_policy(ipv4)
        translate_policy(device, policy, output_dir=output_dir)
