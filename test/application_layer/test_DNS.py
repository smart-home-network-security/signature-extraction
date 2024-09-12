## Imports
# Libraries
from scapy.all import IP, UDP
import scapy.layers.dns as dns
# Package
from signature_extraction.application_layer import DNS


### VARIABLES ###

# DNS request
pkt_dns_request = (
    IP(dst="8.8.8.8") /
    UDP(dport=53) /
    dns.DNS(
        rd=1,
        qd=dns.DNSQR(qname="www.example.com")
    )
)

# DNS response
pkt_dns_response = (
    IP(src="8.8.8.8", dst="192.168.1.100") /
    UDP(sport=53, dport=12345) /
    dns.DNS(id=0xAAAA, qr=1, aa=1, rd=1, ra=1,
            qd=dns.DNSQR(qname="www.example.com"),
            an=dns.DNSRR(rrname="www.example.com", ttl=60, rdata="93.184.216.34")
    )
)


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
