## Imports
# Libraries
from __future__ import annotations
from typing import Tuple, Iterator
import os
from ipaddress import IPv4Address
# Package
from .Packet import Packet
from .BaseFlow import BaseFlow
from .Flow import Flow
from signature_extraction.utils.packet_utils import is_known_port
from profile_translator_blocklist import translate_policy


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
        self.fixed_port = None


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
    

    def get_fixed_port(self) -> Tuple[int, str]:
        """
        Compute the fixed port of the flow fingerprint.

        Returns:
            Tuple[int, str]: Fixed port number and corresponding host.
        """
        ports_sorted = sorted(self.ports.items(), key=lambda item: item[1]["number"], reverse=True)

        # If one of the port numbers is well-known, return it
        for port, data in ports_sorted:
            if is_known_port(port, self.transport_protocol):
                self.fixed_port = (port, data["host"])
                return self.fixed_port

        # Else, return the most used port
        self.fixed_port = (ports_sorted[0][0], ports_sorted[0][1]["host"])
        return self.fixed_port


    def add_ports(self, flow_dict: dict = {}) -> None:
        """
        Add ports from a Flow object.

        Args:
            flow (Flow): Flow object to add ports from.
        """
        # Source port
        sport = flow_dict["sport"]
        if sport not in self.ports:
            self.ports[sport] = {"number": 1, "host": flow_dict["src"]}
        else:
            self.ports[sport]["number"] += 1
        
        # Destination port
        dport = flow_dict["dport"]
        if dport not in self.ports:
            self.ports[dport] = {"number": 1, "host": flow_dict["dst"]}
        else:
            self.ports[dport]["number"] += 1

        return self.ports
    

    def add_flow(self, flow: Flow) -> None:
        """
        Add attributes of the given Flow object to the FlowFingerprint.

        Args:
            flow (Flow): Flow object to add.
        """
        # Set attributes if not initialized
        self.src = flow.src if not self.src else self.src
        self.dst = flow.dst if not self.dst else self.dst
        self.transport_protocol = flow.transport_protocol if not self.transport_protocol else self.transport_protocol
        self.application_layer = flow.application_layer if not self.application_layer else self.application_layer

        # Add flow ports
        self.add_ports(dict(flow))


    def __repr__(self) -> str:
        """
        String representation of a FlowFingerprint object.

        Returns:
            str: String representation of a FlowFingerprint object.
        """
        port_number, port_host = self.get_fixed_port()

        ## Hosts
        # Source
        s = f"{self.src}"
        if port_host == self.src:
            s += f":{port_number}"
        s += " <-> "
        # Destination
        s += f" {self.dst}"
        if port_host == self.dst:
            s += f":{port_number}"

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
        port_number, port_host = self.get_fixed_port()

        ## Hosts
        # Source
        yield "src", self.src
        if port_host == self.src:
            yield "sport", port_number
        else:
            yield "sport", None
        # Destination
        yield "dst", self.dst
        if port_host == self.dst:
            yield "dport", port_number
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
        if self.application_layer is not None:
            return repr(self.application_layer)
        else:
            port_number, port_host = self.get_fixed_port()
            if port_host == self.src:
                host = "src"
            elif port_host == self.dst:
                host = "dst"
            return f"{self.transport_protocol}_{host}_{port_number}"


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
        port_number, port_host = self.get_fixed_port()
        if port_host == self.src:
            policy["protocols"][protocol] = {"src-port": port_number}
        elif port_host == self.dst:
            policy["protocols"][protocol] = {"dst-port": port_number}

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
            print(f"Output directory {output_dir} does not exist. Using current directory.")
            output_dir = os.getcwd()
        
        # Device metadata
        device = {
            "name": device_name,
            "ipv4": str(ipv4)
        }

        policy = self.extract_policy(ipv4)
        translate_policy(device, policy, output_dir=output_dir)
