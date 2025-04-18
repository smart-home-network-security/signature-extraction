from typing import Any
from fractions import Fraction
import Levenshtein
from .packet_utils import is_ip_address

# Default fractions
ZERO = Fraction(0)
ONE  = Fraction(1)


def discrete_distance(a: Any, b: Any) -> Fraction:
    """
    Compute the strict distance between two objects.
    If the two objects are identical, the distance is 0.
    If the two objects are different, the distance is 1.

    Args:
        a (Any): first object
        b (Any): second object
    Returns:
        Fraction: distance between the two objects (0 if identical, 1 if different)
    """
    if a == b:
        return Fraction(0)
    else:
        return Fraction(1)


def levenshtein_ratio(a: str, b: str) -> Fraction:
    """
    Compute the Levenshtein ratio between two strings.
    It is a normalized version of the Levenshtein distance in the range [0, 1].
    It is defined as:
        ratio = Levenshtein distance / (len(a) + len(b))
    
    Args:
        a (str): first string
        b (str): second string
    Returns:
        Fraction: Levenshtein ratio between the two strings
    """
    # Both strings are identical: distance is 0
    if a == b:
        return Fraction(0)
    
    # Both strings are empty: distance is 0
    if len(a) + len(b) == 0:
        return Fraction(0)
    
    # General case: compute Levenshtein ratio
    return Fraction(Levenshtein.distance(a, b), len(a) + len(b))


def distance_hosts(host_a: str, host_b: str) -> Fraction:
    """
    Compute a distance metric between two hosts (IP address or domain name).
    The distance metric is defined as follows:
        - If both hosts are identical, the distance is 0.
        - If both hosts are IP addresses, the distance is 0 if they are identical,
          1 if they are different.
        - If both hosts are domain names, the distance is defined as the
          Levenshtein distance between the two domain names.
        - If one host is an IP address and the other is a domain name,
          the distance is 1.
    
    Args:
        host_a (str): first host (IP address or domain name)
        host_b (str): second host (IP address or domain name)
    Returns:
        float: distance between the two hosts
    """
    # If both are identical, distance is 0
    if host_a == host_b:
        return 0.0

    # Try converting to IP address
    a_is_ip = is_ip_address(host_a)
    b_is_ip = is_ip_address(host_b)

    # Both are IP addressees:
    # distance = 0 if they are identical, 1 if they are different
    if a_is_ip and b_is_ip:
        return discrete_distance(host_a, host_b)
    
    # Both are domain names:
    # Compute Levenshtein distance
    if not a_is_ip and not b_is_ip:
        # Compute Levenshtein ratio
        return levenshtein_ratio(host_a, host_b)
    
    # One is an IP address, the other is a domain name
    # distance = 1
    return Fraction(1)
