from fractions import Fraction
import signature_extraction.utils.distance as distance


def test_discrete_distance() -> None:
    """
    Test the function which computes the discrete distance between two objects.
    """
    assert distance.discrete_distance("a", "a") == 0
    assert distance.discrete_distance("a", "b") == 1
    assert distance.discrete_distance(1, 1) == 0
    assert distance.discrete_distance(1, 2) == 1
    assert distance.discrete_distance([1], [1]) == 0
    assert distance.discrete_distance([1], [2]) == 1
    assert distance.discrete_distance({"a": 1}, {"a": 1}) == 0
    assert distance.discrete_distance({"a": 1}, {"b": 2}) == 1


def test_levenshtein_ratio() -> None:
    """
    Test the function which computes the Levenshtein ratio between two strings.
    """
    assert distance.levenshtein_ratio("", "") == 0
    assert distance.levenshtein_ratio("a", "a") == 0
    assert distance.levenshtein_ratio("a", "b") == Fraction(1, 2)
    assert distance.levenshtein_ratio("a", "") == 1
    assert distance.levenshtein_ratio("abc", "abc") == 0
    assert distance.levenshtein_ratio("abc", "def") == Fraction(1, 2)


def test_distance_hosts() -> None:
    """
    Test the function which computes the distance metric between two hosts.
    """
    ip_a = "192.168.1.1"
    ip_b = "192.168.1.2"
    domain_a = "example.com"
    domain_b = "example.org"

    assert distance.distance_hosts(ip_a, ip_a) == 0
    assert distance.distance_hosts(ip_a, ip_b) == 1
    assert distance.distance_hosts(domain_a, domain_a) == 0
    assert distance.distance_hosts(domain_a, domain_b) == distance.levenshtein_ratio(domain_a, domain_b)
    assert distance.distance_hosts(ip_a, domain_a) == 1
    assert distance.distance_hosts(ip_a, domain_b) == 1
    assert distance.distance_hosts(ip_b, domain_a) == 1
    assert distance.distance_hosts(ip_b, domain_b) == 1
