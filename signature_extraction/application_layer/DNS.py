## Imports
# Libraries
from __future__ import annotations
from typing import Iterator
from scapy.all import Packet
from scapy.layers.dns import dnstypes
# Package
from signature_extraction.utils import compare_domain_names, get_wildcard_subdomain
from .ApplicationLayer import ApplicationLayer


class DNS(ApplicationLayer):
    """
    DNS Application Layer Protocol.
    """
    protocol_name = "DNS"

 
    def __init__(self, pkt: Packet) -> None:
        """
        Constructor of the DNS class.
        """
        application_layer = pkt.getlayer("DNS")
        self.response = application_layer.qr == 1 if application_layer.qr else False

        # Query type and name
        try:
            first_query = application_layer.qd[0]
        except IndexError:
            try:
                first_answer = application_layer.an[0]
            except IndexError:
                self.qtype = None
                self.qname = None
            else:
                self.qtype = dnstypes.get(first_answer.type, None)
                try:
                    self.qname = first_answer.rrname.decode()[:-1]
                except AttributeError:
                    self.qname = None
        else:
            self.qtype = dnstypes.get(first_query.qtype, None)
            try:
                self.qname = first_query.qname.decode()[:-1]
            except AttributeError:
                self.qname = None

    
    def update(self, other: DNS) -> None:
        """
        Update the current DNS object with another one.

        Args:
            other (DNS): other DNS object.
        """
        if not isinstance(other, DNS):
            raise ValueError("Cannot update DNS object with a non-DNS object.")
        
        if self.qname != other.qname and compare_domain_names(self.qname, other.qname):
            self.qname = get_wildcard_subdomain(self.qname, other.qname)

    
    def __iter__(self) -> Iterator:
        """
        Iterate over the class attributes.

        Returns:
            Iterator: iterator over the class attributes
        """
        for attr, value in self.__dict__.items():
            if value is None:
                continue
            
            if attr == "qname":
                attr = "domain-name"
            yield attr, value


    def __eq__(self, other: ApplicationLayer) -> bool:
        """
        Check if two DNS packet layers pertain to the same data transfer.

        Args:
            other (ApplicationLayer): Other ApplicationLayer object
        Returns:
            bool: True if the two DNS layers are equivalent
        """
        # Other object is not a DNS layer, return False
        if not isinstance(other, DNS):
            return False
        
        ## Other object is a DNS layer

        # Compare qtype
        if self.qtype != other.qtype:
            return False
        
        ## Compare qname
        # qnames are identical
        if self.qname == other.qname:
            return True
        
        # If qnames differ only by the first subdomain, consider them equal
        if self.qname is not None and other.qname is not None:
            return compare_domain_names(self.qname, other.qname)

        return False


    def __hash__(self) -> int:
        """
        Hash function for the DNS class.

        Returns:
            int: hash value of the DNS object.
        """
        attrs = tuple(attr for attr in dict(self).items() if attr[0] != "response")
        return hash((self.protocol_name, attrs))
