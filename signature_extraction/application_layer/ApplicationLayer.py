from __future__ import annotations
from typing import Iterator, Any
import importlib
from scapy.all import Packet, Raw
from scapy.layers import http, dns, dhcp
from scapy.contrib.coap import CoAP
from fractions import Fraction


class ApplicationLayer:
    """
    Application layer protocol.
    """

    characters_to_replace = [" ", "/", "*", "=", "?"]


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
    
    
    @staticmethod
    def init_protocol(data_protocol: dict | Packet, name_protocol: str = None) -> ApplicationLayer:
        """
        Initialize an application-layer protocol object,
        from either a policy's protocol dictionary or a scapy packet.

        Args:
            data (dict | scapy.Packet): application-layer protocol data.
        Returns:
            ApplicationLayer: application layer protocol object.
        """
        # If the given data is a scapy packet, extract the protocol name
        if isinstance(data_protocol, Packet):
            name_protocol = ApplicationLayer.get_protocol(data_protocol)
        
        # Instantiate the concrete protocol object
        package = importlib.import_module(__name__).__name__.rpartition(".")[0]
        protocol_module = importlib.import_module(f"{package}.{name_protocol}")
        cls = getattr(protocol_module, name_protocol)
        return cls(data_protocol)
    

    def set_attr_from_dict(self, attr: str, data: dict, field: str) -> None:
        """
        Set an attribute of this object from a dictionary.

        Args:
            attr (str): name of the attribute to set.
            data (dict): dictionary containing the data.
            field (str): key in the dictionary to retrieve the value from.
        """
        try:
            setattr(self, attr, data[field])
        except KeyError:
            pass
    

    def compare_attrs(self, other: ApplicationLayer, attr: str) -> bool:
        """
        Compare an attribute of this object with the same attribute of another object.

        Args:
            other (ApplicationLayer): other application layer protocol.
            attr (str): name of the attribute to compare.
        Returns:
            bool: True if the two attributes are equal, False otherwise.
        """
        # Other object is not an ApplicationLayer, return False
        if not isinstance(other, ApplicationLayer):
            return False
        
        # If the attribute is not present in both objects, return True
        if not hasattr(self, attr) and not hasattr(other, attr):
            return True
        
        # Try comparing the attributes
        try:
            return getattr(self, attr) == getattr(other, attr)
        except AttributeError:
            return False


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
    

    def __eq__(self, other: ApplicationLayer) -> bool:
        """
        Check if two application layer protocols are equivalent.
        This method uses a dummy comparison, and should be overridden by subclasses.

        Args:
            other (ApplicationLayer): other application layer protocol.
        Returns:
            bool: True if the two application layer protocols are equivalent.
        """
        if not isinstance(other, ApplicationLayer):
            return False
        
        return hash(self) == hash(other)

    
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


    def diff(self, other: ApplicationLayer) -> dict[str, tuple[Any, Any]]:
        """
        Dummy implementation for the diff() method.
        This method should be overridden by subclasses.

        Args:
            other (ApplicationLayer): other application layer protocol.
        Returns:
            dict[str, tuple[Any, Any]]: dictionary with the differences between
                the two application layer protocols.
        """
        return {}


    def compute_distance(self, other: ApplicationLayer) -> Fraction:
        """
        Compute the distance between two application layer protocols.
        This distance is generic and dummy, and should be overridden by subclasses.

        Args:
            other (ApplicationLayer): other application layer protocol.
        Returns:
            Fraction: distance between the two application layer protocols,
                i.e. 0 if the are equivalent, 1 if they are different.
        """
        if hash(self) == hash(other):
            return Fraction(0)
        else:
            return Fraction(1)
