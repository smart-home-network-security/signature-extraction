## Imports
# Libraries
from __future__ import annotations
from typing import Iterator, Any
from enum import StrEnum
from scapy.all import Packet, Raw
import scapy.layers as scapy
from fractions import Fraction
# Package
from .ApplicationLayer import ApplicationLayer
from signature_extraction.utils import get_last_layer
from signature_extraction.utils.distance import discrete_distance, levenshtein_ratio


class HTTP(ApplicationLayer):
    """
    HTTP Application Layer Protocol.
    """
    protocol_name = "HTTP"

    # Distance metric weights
    WEIGHT_METHOD = Fraction(1, 2)
    WEIGHT_URI    = Fraction(1, 2)

    class HttpFields(StrEnum):
        """
        HTTP Fields.
        """
        METHOD = "method"
        URI    = "uri"


    @staticmethod
    def is_response(pkt: Packet) -> bool:
        """
        Check if the HTTP packet is a request.
        """
        return isinstance(get_last_layer(pkt), scapy.http.HTTPResponse)


    def __init__(self, data: dict | Packet) -> None:
        """
        Constructor of the HTTP class.

        Args:
            data (dict | Packet): HTTP data, either from a policy's protocol dictionary or a scapy packet.
        """
        # Given data is the policy's protocol dictionary
        if isinstance(data, dict):
            self.method = data.get("method", None)
            self.uri = data.get("uri", None)
            self.response = data.get("response", False)

        # Given data is a scapy packet
        elif isinstance(data, Packet):
            if data.haslayer(scapy.http.HTTP):
                application_layer = data.getlayer(scapy.http.HTTP)
            else:
                application_layer = scapy.http.HTTP(data.getlayer(Raw).getfieldval("load"))

            self.response = HTTP.is_response(application_layer)
            self.method = application_layer.Method.decode() if not self.response else None

            # URI
            uri = application_layer.Path.decode() if not self.response else None
            if uri is not None and "?" in uri:
                uri = uri.split("?")[0]
                uri += "*" if not uri.endswith("*") else ""
            self.uri = uri

    
    def __eq__(self, other: ApplicationLayer) -> bool:
        """
        Check if two HTTP packet layers pertain to the same data transfer.

        Args:
            other (ApplicationLayer): Other ApplicationLayer object
        Returns:
            bool: True if the two HTTP layers are equivalent
        """
        # Other object is not an HTTP layer, return False
        if not isinstance(other, HTTP):
            return False
        
        ## Other object is an HTTP layer

        if not self.response and not other.response:
            # Both objects are requests,
            # compare method & URI

            # Method
            is_same_method = self.compare_attrs(other, "method")

            # URI
            is_same_uri = False
            if not hasattr(self, "uri") and not hasattr(other, "uri"):
                is_same_uri = True
            else:
                try:
                    self_uri = self.uri[:-1] if self.uri and self.uri.endswith(("*", "?")) else self.uri
                    other_uri = other.uri[:-1] if other.uri and other.uri.endswith(("*", "?")) else other.uri
                except AttributeError:
                    # One of the two objects does not have a URI
                    is_same_uri = False
                else:
                    is_same_uri = self_uri == other_uri
            
            return is_same_method and is_same_uri
    
        # If one of the two objects is a response,
        # we cannot compare the fields.
        # ==> conservatively return True
        return True
    

    def __iter__(self) -> Iterator:
        """
        Iterate over the relevant class attributes.

        Returns:
            Iterator: iterator over the relevant class attributes
        """
        yield "response", self.response
        if self.method is not None:
            yield "method", self.method
        if self.uri is not None:
            yield "uri", self.uri
    

    def __hash__(self) -> int:
        """
        Hash function for the HTTP class.
        Conservatively returns the same value for all HTTP objects.

        Returns:
            int: hash value of the HTTP object
        """
        return hash(self.protocol_name)
    

    def diff(self, other: HTTP) -> dict[str, tuple[Any, Any]]:
        """
        Compute the difference between this and another HTTP layer object.
        The difference is defined as a dictionary,
        with keys being the protocol field names,
        and the values being a tuple of the two different values.

        Args:
            other (HTTP): Other HTTP object
        Returns:
            dict[str, tuple[Any, Any]]: difference between this and another HTTP layer
        """
        # Initialize the difference dictionary
        diff = {}

        # If other is not a HTTP layer, return empty dictionary
        if not isinstance(other, HTTP):
            return diff
        
        ## HTTP attributes
        # Method
        if self.method != other.method:
            diff[HTTP.HttpFields.METHOD.value] = (self.method, other.method)
        # URI
        if self.uri != other.uri:
            diff[HTTP.HttpFields.URI.value] = (self.uri, other.uri)
        
        return diff
    

    def compute_distance(self, other: HTTP) -> Fraction:
        """
        Compute the distance between this and another HTTP layer.

        Args:
            other (HTTP): Other HTTP object
        Returns:
            Fraction: distance between this and another HTTP layer
        """
        # If other is not a HTTP layer, distance is maximal (1)
        if not isinstance(other, HTTP):
            return Fraction(1)
        
        # If both objects are responses, distance is 0
        if self.response and other.response:
            return Fraction(0)

        # Method
        # 0 if identical, 1 if different
        distance_method = discrete_distance(self.method, other.method) if self.method is not None and other.method is not None else Fraction(1)

        # URI
        # Levenshtein distance
        distance_uri = levenshtein_ratio(self.uri, other.uri) if self.uri is not None and other.uri is not None else Fraction(1)

        return (
            HTTP.WEIGHT_METHOD * distance_method +
            HTTP.WEIGHT_URI    * distance_uri
        )
