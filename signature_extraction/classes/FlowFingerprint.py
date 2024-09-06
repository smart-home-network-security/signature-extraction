from __future__ import annotations
from typing import Tuple, Iterator
from .BaseFlow import BaseFlow
from .Flow import Flow
from signature_extraction.utils.packet_utils import is_known_port


class FlowFingerprint(BaseFlow):
    """
    Fingerprint of a network flow,
    matching only the following attributes:
        - Source & destination hosts
        - Transport protocol
        - Fixed port (to be computed)
        - Application protocol
    """

    def __init__(self, flow: Flow = None) -> None:
        """
        Flow fingerprint constructor.

        Args:
            flow (Flow): Flow object to initialize with.
        """
        self.src                  = flow.src if flow else None
        self.dst                  = flow.dst if flow else None
        self.transport_protocol   = flow.transport_protocol if flow else None
        self.application_protocol = flow.application_protocol if flow else None
 
        # Initialize ports (to be computed)
        self.ports = {}
        if flow:
            self.add_ports(flow)
        self.fixed_port = None


    
    # @classmethod
    # def build_from_flow(cls, flow: Flow) -> FlowFingerprint:
    #     """
    #     Build a flow fingerprint from a packet fingerprint.

    #     Args:
    #         pkt (PacketFingerprint): Packet fingerprint to build from.
    #     Returns:
    #         FlowFingerprint: Flow fingerprint.
    #     """
    #     return cls(dict(flow))


    def add_ports(self, flow: Flow) -> None:
        """
        Add ports from a Flow object.

        Args:
            flow (Flow): Flow object to add ports from.
        """
        # Source port
        if flow.sport not in self.ports:
            self.ports[flow.sport] = {"number": 1, "host": flow.src}
        else:
            self.ports[flow.sport]["number"] += 1
        
        # Destination port
        if flow.dport not in self.ports:
            self.ports[flow.dport] = {"number": 1, "host": flow.dst}
        else:
            self.ports[flow.dport]["number"] += 1

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
        self.application_protocol = flow.application_protocol if not self.application_protocol else self.application_protocol

        # Add flow ports
        self.add_ports(flow)

    
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


    def __repr__(self) -> str:
        """
        String representation of a FlowFingerprint object.

        Returns:
            str: String representation of a FlowFingerprint object.
        """
        # Source: host & port
        s = f"{self.src} ->"
        # Destination: host & port
        s += f" {self.dst}"
        # Transport protocol
        s += f" [{self.transport_protocol}]"
        # Application data
        s += f" ({self.application_protocol})"

        return s

    
    def __iter__(self) -> Iterator:
        """
        Iterate over the packet fingerprint attributes.

        Returns:
            Iterable: Iterator over the packet fingerprint attributes.
        """
        yield "src", self.src
        yield "dst", self.dst
        yield "transport_protocol", self.transport_protocol
        yield "fixed_port", self.fixed_port
        yield "application_protocol", self.application_protocol
