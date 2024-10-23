## Imports
# Libraries
from __future__ import annotations
from typing import Iterator
import os
from ipaddress import IPv4Address
import uuid
# Package
from .Packet import Packet
from .BaseFlow import BaseFlow
from .Flow import Flow
from signature_extraction.utils.packet_utils import is_known_port
from profile_translator_blocklist import translate_policy
# Logging
import importlib
import logging
module_relative_path = importlib.import_module(__name__).__name__
logger = logging.getLogger(module_relative_path)


class FlowFingerprint(BaseFlow):
    """
    Fingerprint of a network flow,
    matching only the following attributes:
        - Source & destination hosts
        - Transport protocol
        - Fixed port (to be computed)
        - Application protocol
    """

    def __init__(self, flow_dict: dict = {}) -> None:
        """
        FlowFingerprint constructor.

        Args:
            flow_dict (dict): dictionary containing the flow fingerprint attributes.
        """
        # Initialize with super-class constructor
        super().__init__()

        self.count = 1  # Number of flows added to this FlowFingerprint

        # Set attributes
        self.src                = flow_dict["src"]
        self.dst                = flow_dict["dst"]
        self.transport_protocol = flow_dict["transport_protocol"]
        self.application_layer  = flow_dict.get("application_layer", None)
        if not self.application_layer:
            self.application_layer = None
 
        # Initialize ports (to be computed)
        self.ports = {}
        self.add_ports(flow_dict)
        self.fixed_ports = set()


    @classmethod
    def build_from_pkt(cls, pkt: Packet) -> FlowFingerprint:
        """
        Build a FlowFingerprint object from a Packet object.

        Args:
            pkt (Packet): Packet object to build from.
        Returns:
            FlowFingerprint: Flow fingerprint.
        """
        return cls(dict(pkt))
    

    @classmethod
    def build_from_flow(cls, flow: Flow) -> FlowFingerprint:
        """
        Build a FlowFingerprint object from a Flow object.

        Args:
            flow (Flow): Flow object to build from.
        Returns:
            FlowFingerprint: Flow fingerprint.
        """
        return cls(dict(flow))
    

    def get_fixed_ports(self) -> set[(str, int)]:
        """
        Compute the fixed port of the FlowFingerprint.

        Returns:
            Tuple[int, str]: Fixed port number and corresponding host.
        """
        # If already computed, return it
        if self.fixed_ports:
            return self.fixed_ports

        # Iterate over hosts and ports
        for (host, port), count in self.ports.items():

            # Current port number is considered as fixed if ...
            if (
                is_known_port(port, self.transport_protocol) or  # ... it is a well-known port
                (count > 1 and count == self.count)              # ... it was used for all flows
            ):
                self.fixed_ports.add((host, port))

        # Return fixed ports
        return self.fixed_ports


    def add_ports(self, flow_dict: dict = {}) -> None:
        """
        Add ports from a Flow object.

        Args:
            flow (Flow): Flow object to add ports from.
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
    

    def add_flow(self, flow: Flow) -> None:
        """
        Add attributes of the given Flow object to the FlowFingerprint.

        Args:
            flow (Flow): Flow object to add.
        """
        # Increment flow count
        self.count += 1

        # Set attributes if not initialized
        self.src = flow.src if not self.src else self.src
        self.dst = flow.dst if not self.dst else self.dst
        self.transport_protocol = flow.transport_protocol if not self.transport_protocol else self.transport_protocol
        self.application_layer = flow.application_layer if not self.application_layer else self.application_layer

        # Add flow ports
        self.add_ports(dict(flow))

    
    def match_flow(self, other: BaseFlow) -> bool:
        """
        Compare the given BaseFlow with this FlowFingerprint,
        based on the following attributes:
            - Hosts (in any direction)
            - Fixed port
            - Transport protocol
            - Application layer protocol

        Args:
            other (BaseFlow): BaseFlow to match with.
        Returns:
            bool: True if the given BaseFlow matches, False otherwise.
        """
        # If other object is not a BaseFlow or one of its subclasses, return False
        if not isinstance(other, BaseFlow):
            return False
        
        # If other object is a BaseFlow, compare attributes:
        if (
            # Hosts (in any direction)
            self.match_host(other) and
            # Transport protocol
            self.transport_protocol == other.transport_protocol and
            # Application layer protocol
            self.application_layer == other.application_layer
        ):
            ## Ports
            fixed_ports = self.get_fixed_ports()

            # Given flow is an instance of the subclass Flow
            if isinstance(other, Flow):
                pred = (
                    lambda host, port:
                        (host == other.src and port == other.sport) or
                        (host == other.dst and port == other.dport)
                )
                return all(pred(host, port) for host, port in fixed_ports)
                
            # Given flow is an instance of the subclass FlowFingerprint
            elif isinstance(other, FlowFingerprint):
                return fixed_ports == other.get_fixed_ports()


        # No matching flow found        
        return False


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
        Generate a unique identifier for this FlowFingerprint.

        Returns:
            str: Unique identifier for this FlowFingerprint.
        """
        return f"{self.get_id()}_{str(uuid.uuid4())}"


    def extract_policy(self, ipv4: IPv4Address) -> dict:
        """
        Extract a profile-compliant policy from this FlowFingerprint.
        
        Args:
            ipv4 (IPv4Address): IP address of the device.
        Returns:
            dict: Policy extracted from the FlowFingerprint.
        """
        # Hosts
        src_ip = "self" if self.src == str(ipv4) else self.src
        dst_ip = "self" if self.dst == str(ipv4) else self.dst
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
            policy["protocols"][app_protocol] = dict(self.application_layer)
        
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
