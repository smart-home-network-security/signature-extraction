## Imports
# Libraries
from scapy.all import IP, UDP
import scapy.layers.dns as dns
# Package
import signature_extraction.utils.distance as distance
from signature_extraction.application_layer import DNS


### VARIABLES ###

## DNS requests
dns_request_layer = (
    dns.DNS(
        rd=1,
        qd=dns.DNSQR(qtype="A", qname="www.example.com")
    ))
pkt_dns_request = (
    IP(dst="8.8.8.8") /
    UDP(dport=53) /
    dns_request_layer
)

dns_request_layer_aaaa = (
    dns.DNS(
        rd=1,
        qd=dns.DNSQR(qtype="AAAA", qname="www.example.com")
    ))
dns_request_layer_other = (
    dns.DNS(
        rd=1,
        qd=dns.DNSQR(qtype="A", qname="www.example.org")
    ))

## DNS response
dns_response_layer = (
    dns.DNS(id=0xAAAA, qr=1, aa=1, rd=1, ra=1,
            qd=dns.DNSQR(qtype="A", qname="www.example.com"),
            an=dns.DNSRR(rrname="www.example.com", ttl=60, rdata="93.184.216.34")
    ))
pkt_dns_response = (
    IP(src="8.8.8.8", dst="192.168.1.100") /
    UDP(sport=53, dport=12345) /
    dns_response_layer
)

# Concrete objects
dns_request = DNS(dns_request_layer)
dns_request_aaaa = DNS(dns_request_layer_aaaa)
dns_request_other = DNS(dns_request_layer_other)
dns_response = DNS(dns_response_layer)


## From policy's protocol dictionary

# DNS A request
dns_request_policy_dict = {
    "qtype": "A",
    "domain-name": "www.example.com"
}
dns_request_from_policy = DNS(dns_request_policy_dict)

# DNS A response
dns_response_policy_dict = {
    "response": True,
    "qtype": "A",
    "domain-name": "www.example.com"
}
dns_response_from_policy = DNS(dns_response_policy_dict)



### TEST FUNCTIONS ###


def test_dns_request() -> None:
    """
    Test the constructor with a DNS request.
    """
    dns = DNS(pkt_dns_request)
    assert dns.protocol_name == "DNS"
    assert dns.get_protocol_name() == "DNS"
    assert not dns.response
    assert dns.qtype == "A"
    assert dns.qname == "www.example.com"

    dns = dict(dns)
    assert isinstance(dns, dict)
    assert not dns["response"]
    assert dns["qtype"] == "A"
    assert dns["domain-name"] == "www.example.com"


def test_dns_response() -> None:
    """
    Test the constructor with a DNS response.
    """
    dns = DNS(pkt_dns_response)
    assert dns.protocol_name == "DNS"
    assert dns.get_protocol_name() == "DNS"
    assert dns.response
    assert dns.qtype == "A"
    assert dns.qname == "www.example.com"

    dns = dict(dns)
    assert isinstance(dns, dict)
    assert dns["response"]
    assert dns["qtype"] == "A"
    assert dns["domain-name"] == "www.example.com"


def test_dns_request_from_policy() -> None:
    """
    Test the constructor with a policy's protocol dictionary
    describing a DNS A request.
    """
    assert dns_request_from_policy.protocol_name == "DNS"
    assert not dns_request_from_policy.response
    assert dns_request_from_policy.qtype == "A"
    assert dns_request_from_policy.qname == "www.example.com"


def test_dns_response_from_policy() -> None:
    """
    Test the constructor with a policy's protocol dictionary
    describing a DNS A response.
    """
    assert dns_response_from_policy.protocol_name == "DNS"
    assert dns_response_from_policy.response
    assert dns_response_from_policy.qtype == "A"
    assert dns_response_from_policy.qname == "www.example.com"


def test_eq() -> None:
    """
    Test the equality operator.
    """
    assert dns_request == dns_request
    assert dns_request != dns_request_aaaa
    assert dns_request != dns_request_other
    assert dns_request == dns_response
    assert dns_request == dns_request_from_policy
    assert dns_response == dns_response_from_policy


def test_hash() -> None:
    """
    Test the hash function.
    """
    assert hash(dns_request) != hash(dns_request_aaaa)
    assert hash(dns_request) != hash(dns_request_other)
    assert hash(dns_request) == hash(dns_response)


def test_diff() -> None:
    """
    Test the diff function,
    which extracts the difference between two DNS objects.
    """
    assert dns_request.diff(dns_request) == {}
    assert dns_request.diff(dns_request_aaaa) == {
        "qtype": (dns_request.qtype, dns_request_aaaa.qtype)
    }
    assert dns_request.diff(dns_request_other) == {
        "qname": (dns_request.qname, dns_request_other.qname)
    }
    assert dns_request.diff(dns_response) == {}


def test_compute_distance() -> None:
    """
    Test the distance function.
    """
    assert dns_request.compute_distance(dns_request) == distance.ZERO
    assert dns_request.compute_distance(dns_request_aaaa) == DNS.WEIGHT_QTYPE * distance.ONE + DNS.WEIGHT_QNAME * distance.ZERO
    assert dns_request.compute_distance(dns_request_other) == DNS.WEIGHT_QTYPE * distance.ZERO + DNS.WEIGHT_QNAME * distance.levenshtein_ratio(dns_request.qname, dns_request_other.qname)
    assert dns_request.compute_distance(dns_response) == 0
