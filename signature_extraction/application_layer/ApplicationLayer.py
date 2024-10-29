from __future__ import annotations
from typing import Iterator
import importlib
from scapy.all import Packet, Raw
from scapy.layers import http, dns, dhcp
from scapy.contrib.coap import CoAP


class ApplicationLayer:
    """
    Application layer protocol.
    """

    characters_to_replace = ["/", "*", "=", "?"]


    @staticmethod
    def get_protocol(pkt: Packet) -> str:
        """
        Get the application layer protocol name.

        Args:
            pkt (Packet): packet to extract the application layer protocol from.
        Returns:
            str: application layer protocol name.
        Raises:
            ValueError: unknown application layer protocol.
        """
        if pkt.haslayer(dns.DNS):
            return "DNS"
        elif pkt.haslayer(dhcp.DHCP):
            return "DHCP"
        elif pkt.haslayer(CoAP):
            return "CoAP"

        # HTTP
        elif pkt.haslayer(http.HTTP):
            return "HTTP"
        elif pkt.haslayer(Raw):
            http_layer = http.HTTP(pkt.getlayer(Raw).getfieldval("load"))
            if http_layer.haslayer(http.HTTPRequest) or http_layer.haslayer(http.HTTPResponse):
                return "HTTP"
        
        raise ValueError("Unknown application layer protocol.")
    
    
    @classmethod
    def init_protocol(c, pkt: Packet) -> ApplicationLayer:
        """
        Initialize an application layer protocol.

        Args:
            protocol_name (str): name of the application layer protocol.
        Returns:
            ApplicationLayer: application layer protocol.
        """
        protocol_name = ApplicationLayer.get_protocol(pkt)
        package = importlib.import_module(__name__).__name__.rpartition(".")[0]
        protocol_module = importlib.import_module(f"{package}.{protocol_name}")
        cls = getattr(protocol_module, protocol_name)
        return cls(pkt)
    

    def get_protocol_name(self) -> str:
        """
        Retrieve this ApplicationLayer object's protocol name.

        Return:
            str: protocol name
        """
        return self.protocol_name


    def __iter__(self) -> Iterator:
        """
        Iterate over the class attributes.

        Returns:
            Iterator: iterator over the class attributes
        """
        for attr, value in self.__dict__.items():
            yield attr, value

    
    def __str__(self) -> str:
        """
        String representation of the ApplicationLayer class.

        Returns:
            str: string representation of the ApplicationLayer class.
        """
        attrs = [f"{attr}: {value}" if value is not None else "" for attr, value in self]
        return f"{self.protocol_name} - {', '.join(attrs)}"


    def __repr__(self) -> str:
        """
        String representation of the ApplicationLayer class.

        Returns:
            str: string representation of the ApplicationLayer class.
        """
        attrs = [f"{attr}-{value}" if value is not None else "" for attr, value in self]
        s = f"{self.protocol_name}_{'_'.join(attrs)}"
        for char in ApplicationLayer.characters_to_replace:
            if char in s:
                s = s.replace(char, "-")
        return s
    

    def __hash__(self) -> int:
        """
        Hash function for the ApplicationLayer class.

        Returns:
            int: hash value of the ApplicationLayer class.
        """
        return hash((self.protocol_name, tuple(dict(self).items())))
