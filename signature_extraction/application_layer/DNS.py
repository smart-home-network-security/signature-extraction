## Imports
# Libraries
from __future__ import annotations
from typing import Iterator, Any
from enum import StrEnum
from scapy.all import Packet
from scapy.layers.dns import dnstypes
from fractions import Fraction
# Package
from signature_extraction.utils import compare_domain_names, get_wildcard_subdomain
from .ApplicationLayer import ApplicationLayer
from signature_extraction.utils.distance import discrete_distance, levenshtein_ratio


class DNS(ApplicationLayer):
    """
    DNS Application Layer Protocol.
    """
    protocol_name = "DNS"

    # Distance metric weights
    WEIGHT_QTYPE = Fraction(1, 3)
    WEIGHT_QNAME = Fraction(2, 3)

    class DnsFields(StrEnum):
        """
        DNS Fields.
        """
        QTYPE = "qtype"
        QNAME = "qname"


    def __init__(self, data: dict | Packet) -> None:
        """
        Constructor of the DNS class.

        Args:
            data (dict | Packet): DNS data, either from a policy's protocol dictionary or a scapy packet.
        """
        # Given data is the policy's protocol dictionary
        if isinstance(data, dict):
            self.set_attr_from_dict("qtype", data, "qtype")
            self.set_attr_from_dict("qname", data, "domain-name")
            self.response = data.get("response", False)

        # Given data is a scapy packet
        elif isinstance(data, Packet):
            application_layer = data.getlayer("DNS")
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
        if not self.compare_attrs(other, "qtype"):
            return False
        
        ## Compare qname
        # qnames are identical
        if self.compare_attrs(other, "qname"):
            return True
        
        # If qnames differ only by the first subdomain, consider them equal
        try:
            if self.qname is not None and other.qname is not None:
                return compare_domain_names(self.qname, other.qname)
        except AttributeError:
            # One of the qnames is not defined
            return False

        return False


    def __hash__(self) -> int:
        """
        Hash function for the DNS class.

        Returns:
            int: hash value of the DNS object.
        """
        attrs = tuple(attr for attr in dict(self).items() if attr[0] != "response")
        return hash((self.protocol_name, attrs))
    

    def diff(self, other: DNS) -> dict[str, tuple[Any, Any]]:
        """
        Compute the difference between this and another DNS layer object.
        The difference is defined as a dictionary,
        with keys being the protocol field names,
        and the values being a tuple of the two different values.

        Args:
            other (DNS): Other DNS object
        Returns:
            dict[str, tuple[Any, Any]]: difference between this and another DNS layer
        """
        # Initialize the difference dictionary
        diff = {}

        # If other is not a CoAP layer, return empty dictionary
        if not isinstance(other, DNS):
            return diff
        
        ## DNS attributes
        # qtype
        if self.qtype != other.qtype:
            diff[DNS.DnsFields.QTYPE.value] = (self.qtype, other.qtype)
        # qname
        are_domain_names_equal = (
            self.qname is not None and
            other.qname is not None and
            compare_domain_names(self.qname, other.qname)
        )
        if not are_domain_names_equal:
            diff[DNS.DnsFields.QNAME.value] = (self.qname, other.qname)
        
        return diff
    

    def compute_distance(self, other: DNS) -> Fraction:
        """
        Compute the distance between this and another DNS layer.

        Args:
            other (DNS): Other DNS object
        Returns:
            Fraction: distance between this and another DNS layer
        """
        # If other is not a DNS layer, distance is maximal (1)
        if not isinstance(other, DNS):
            return Fraction(1)

        
        # qtype distance
        # 0 if qtypes are identical, 1 if they differ
        distance_qtype = discrete_distance(self.qtype, other.qtype) if self.qtype is not None and other.qtype is not None else Fraction(1)

        # qname distance: Levenshtein distance
        distance_qname = levenshtein_ratio(self.qname, other.qname) if self.qname is not None and other.qname is not None else Fraction(1)

        # Return weighted distance
        return DNS.WEIGHT_QTYPE * distance_qtype + DNS.WEIGHT_QNAME * distance_qname 
