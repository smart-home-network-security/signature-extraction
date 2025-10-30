## Imports
# Libraries
import pytest
from scapy.all import Packet, Ether, ARP, IP, TCP, UDP, Padding, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLS_Ext_ServerName, ServerName
from scapy.layers.inet6 import IPv6, ICMPv6ND_RS, ICMPv6MLQuery, ICMPv6MLReport, ICMPv6ND_INDAdv, ICMPv6NDOptSrcLLAddr
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply
# Package
import signature_extraction.utils.packet_utils as packet_utils
from signature_extraction.utils import DnsRtype, DnsTableKeys


##### UTIL FUNCTIONS #####

def build_packet(pkt: Packet) -> Packet:
    """
    Fully build a Scapy packet,
    i.e. fill in all of its field with corresponding data.

    Args:
        pkt (scapy.Packet): Scapy packet to build.
    Returns:
        scapy.Packet: Fully built Scapy packet.
    """
    return pkt.__class__(bytes(pkt))


##### TEST VARIABLES #####

### Packets ###

## ARP
# ARP request
arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1")
# ARP reply
arp_reply = (
    Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb") /
    ARP(op=2, pdst="192.168.1.2", psrc="192.168.1.1", hwsrc="66:77:88:99:aa:bb", hwdst="00:11:22:33:44:55")
)

## Transport layer
# TCP
tcp = Ether() / IP() / TCP(flags="")
tcp_ack_raw = Ether() / IP() / TCP(flags="A")
tcp_ack_with_data = Ether() / IP() / TCP(flags="A") / Raw()
# UDP
udp = Ether() / IP() / UDP()
udp_padding = Ether() / IP() / UDP() / Padding()

## ICMPv6
# Neighbor Discovery - Router Solicitation
nd_rs = Ether() / IPv6() / ICMPv6ND_RS()
# Multicast Listener Query
ml_query = Ether() / IPv6() / ICMPv6MLQuery()
# Multicast Listener Report
ml_report = Ether() / IPv6() / ICMPv6MLReport()
# Neighbor Discovery - Interval Advertisement
nd_ind_adv = Ether() / IPv6() / ICMPv6ND_INDAdv()
# Neighbor Discovery - Source Link-Layer Address
nd_opt_src_ll_addr = Ether() / IPv6() / ICMPv6NDOptSrcLLAddr()

## Application layer
# TLS (raw)
tls_raw = Ether() / IP() / TCP(flags="") / TLS()
# TLS Client Hello with Server Name extension
server_name = ServerName(nametype=0, namelen=15, servername=b"www.example.com")
tls_server_name = (
    IP(dst="93.184.216.34") / TCP(flags="S") / TLS() /
    TLSClientHello(version=0x0303,
        ciphers=[0x0033, 0x0039, 0x002f],  # Sample cipher suites
        ext=[TLS_Ext_ServerName(servernames=[server_name])])
)
# TLS Server Hello
tls_server_hello = IP() / TCP(flags="") / TLS() / TLSServerHello()
# HTTP GET request
http_get = (
    IP(dst="www.example.com") /
    TCP(dport=80, flags="") /
    HTTP() /
    HTTPRequest(
        Method=b"GET",
        Path=b"/test/stuff",
        Http_Version=b"HTTP/1.1",
        Host=b"www.example.com",
        User_Agent=b"Scapy"
    )
)
# HTTP response
http_resp = (
    IP(src="www.example.com") /
    TCP(sport=80, flags="") /
    HTTP() /
    HTTPResponse(
        Http_Version=b"HTTP/1.1",
        Status_Code=b"200",
        Reason_Phrase=b"OK",
        Content_Type=b"text/html",
        Connection=b"close"
    )
)
# DNS A query
dns_query_A = (
    IP(dst="8.8.8.8") /
    UDP(dport=53) /
    DNS(
        rd=1,
        qd=DNSQR(qtype=DnsRtype.A.value, qname="www.example.com")
    )
)
dns_query_A = build_packet(dns_query_A)
# DNS A response
dns_response_A = (
    IP(src="8.8.8.8", dst="192.168.1.100") /
    UDP(sport=53, dport=12345) /
    DNS(id=0xAAAA, qr=1, aa=1, rd=1, ra=1,
        qd=DNSQR(qtype=DnsRtype.A.value, qname="www.example.com"),
        an=DNSRR(type=DnsRtype.A.value, rrname="www.example.com", ttl=60, rdata="93.184.216.34")
    )
)
dns_response_A = build_packet(dns_response_A)
# DNS PTR query
dns_query_PTR = (
    IP(dst="8.8.8.8") /
    UDP(dport=53) /
    DNS(
        rd=1,
        qd=DNSQR(qtype=DnsRtype.PTR.value, qname="34.216.184.93.in-addr.arpa")
    )
)
dns_query_PTR = build_packet(dns_query_PTR)
# DNS PTR response
dns_response_PTR = (
    IP(src="8.8.8.8", dst="192.168.1.100") /
    UDP(sport=53, dport=12345) /
    DNS(id=0xAAAA, qr=1, aa=1, rd=1, ra=1,
        qd=DNSQR(qtype=DnsRtype.PTR.value, qname="www.example2.com"),
        an=DNSRR(type=DnsRtype.PTR.value, rrname="34.216.184.93.in-addr.arpa", ttl=60, rdata="www.example2.com")
    )
)
dns_response_PTR = build_packet(dns_response_PTR)

# DHCPv6
dhcpv6_solicit = Ether() / IPv6() / DHCP6_Solicit()
dhcpv6_advertise = Ether() / IPv6() / DHCP6_Advertise()
dhcpv6_request = Ether() / IPv6() / DHCP6_Request()
dhcpv6_reply = Ether() / IPv6() / DHCP6_Reply()


### Mapping of equivalent hosts
hosts_equal = {
    "192.168.1.1": "device.local",
    "192.168.1.10": "192.168.1.20"
}


##### TEST FUNCTIONS #####

def test_is_ip_address() -> None:
    """
    Test the function `is_ip_address`.
    """
    # IPv4
    ipv4 = "192.168.1.1"
    assert packet_utils.is_ip_address(ipv4)

    # IPv6
    ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    assert packet_utils.is_ip_address(ipv6)
    ipv6 = "2001:db8::ff00:42:8329"
    assert packet_utils.is_ip_address(ipv6)
    ipv6 = "::1"
    assert packet_utils.is_ip_address(ipv6)

    # Invalid IP
    invalid_ip = "not_an_ip"
    assert not packet_utils.is_ip_address(invalid_ip)


def test_guess_network_protocol() -> None:
    """
    Test the function `guess_network_protocol`.
    """
    # IPv4
    ipv4 = "192.168.1.1"
    assert packet_utils.guess_network_protocol(ipv4) == "IPv4"

    # IPv6
    ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    assert packet_utils.guess_network_protocol(ipv6) == "IPv6"

    # Unknown
    with pytest.raises(ValueError):
        packet_utils.guess_network_protocol("not_an_ip")


def test_is_known_port() -> None:
    """
    Test the function `is_known_port`.
    """
    ## Known ports
    # TCP
    assert packet_utils.is_known_port(80, "tcp") == True
    assert packet_utils.is_known_port(443, "tcp") == True
    assert packet_utils.is_known_port(5000, "tcp") == True
    assert packet_utils.is_known_port(5683, "tcp") == True
    assert packet_utils.is_known_port(9999, "tcp") == True  # TP-Link Smart Home protocol port
    # UDP
    assert packet_utils.is_known_port(53, "udp") == True
    assert packet_utils.is_known_port(67, "udp") == True
    assert packet_utils.is_known_port(68, "udp") == True
    assert packet_utils.is_known_port(123, "udp") == True
    assert packet_utils.is_known_port(1900, "udp") == True
    assert packet_utils.is_known_port(5353, "udp") == True
    assert packet_utils.is_known_port(5683, "udp") == True

    ## Unknown ports
    assert packet_utils.is_known_port(5555, "tcp") == False
    assert packet_utils.is_known_port(89674, "tcp") == False

    ## Invalid ports
    assert packet_utils.is_known_port(-1, "tcp") == False
    assert packet_utils.is_known_port(65536, "tcp") == False


def test_is_domain_name() -> None:
    """
    Test the function `is_domain_name`,
    which checks if a given string is a valid domain name.
    """
    # Valid domain names
    assert packet_utils.is_domain_name("www.example.com")
    assert packet_utils.is_domain_name("subdomain.example.com")
    assert packet_utils.is_domain_name("example.co.uk")
    assert packet_utils.is_domain_name("euw1-device-telemetry-gw.iot.i.tplinknbu.com")

    # Invalid domain names
    assert not packet_utils.is_domain_name("192.168.1.1")
    assert not packet_utils.is_domain_name("1111:2222:3333:4444:5555:6666:7777:8888")
    assert not packet_utils.is_domain_name("fe80::1")
    assert not packet_utils.is_domain_name("not_a_domain")
    assert not packet_utils.is_domain_name("www..com")
    assert not packet_utils.is_domain_name("-invalid.com")
    assert not packet_utils.is_domain_name("invalid-.com")


def test_compare_domain_names() -> None:
    """
    Test the function `compare_domain_names`,
    which checks if two domain names are considered equivalent.
    """
    # Full-name comparison
    assert packet_utils.compare_domain_names("www.example.com", "www.example.com")
    assert not packet_utils.compare_domain_names("www.example.com", "www.example.org")

    # Subdomain comparison
    assert packet_utils.compare_domain_names("a.example.com", "example.com")
    assert not packet_utils.compare_domain_names("a.example.com", "example.org")
    assert packet_utils.compare_domain_names("a.example.com", "b.example.com")


def test_compare_hosts() -> None:
    """
    Test the function `compare_hosts`,
    which checks if two hosts are considered equivalent.
    """
    # Simple comparison
    assert packet_utils.compare_hosts("1.1.1.1", "1.1.1.1")
    assert not packet_utils.compare_hosts("1.1.1.1", "2.2.2.2")
    assert not packet_utils.compare_hosts("2.2.2.2", "1.1.1.1")
    assert packet_utils.compare_hosts("www.example.com", "www.example.com")
    assert not packet_utils.compare_hosts("www.example.com", "www.example.org")
    assert not packet_utils.compare_hosts("www.example.org", "www.example.com")

    # Comparison involving equivalent hosts
    assert packet_utils.compare_hosts("192.168.1.10", "192.168.1.20", hosts_equal)
    assert packet_utils.compare_hosts("192.168.1.20", "192.168.1.10", hosts_equal)
    assert packet_utils.compare_hosts("192.168.1.1", "device.local", hosts_equal)
    assert packet_utils.compare_hosts("device.local", "192.168.1.1", hosts_equal)


def test_should_skip_pkt() -> None:
    """
    Test the function `should_skip_pkt`.
    """
    ### Signalling packets ###

    ## TCP
    tcp_syn = Ether() / IP() / TCP(flags="S")
    assert packet_utils.should_skip_pkt(tcp_syn)
    tcp_fin = Ether() / IP() / TCP(flags="F")
    assert packet_utils.should_skip_pkt(tcp_fin)
    tcp_rst = Ether() / IP() / TCP(flags="R")
    assert packet_utils.should_skip_pkt(tcp_rst)
    assert packet_utils.should_skip_pkt(tcp_ack_raw)
    assert not packet_utils.should_skip_pkt(tcp_ack_with_data)

    ## ARP
    # ARP request
    assert packet_utils.should_skip_pkt(arp_request)
    # ARP reply
    assert packet_utils.should_skip_pkt(arp_reply)

    ## Padding
    padding = Padding()
    assert packet_utils.should_skip_pkt(padding)

    ## ICMPv6
    # Neighbor Discovery - Router Solicitation
    assert packet_utils.should_skip_pkt(nd_rs)
    # Multicast Listener Query
    assert packet_utils.should_skip_pkt(ml_query)
    # Multicast Listener Report
    assert packet_utils.should_skip_pkt(ml_report)
    # Neighbor Discovery - Interval Advertisement
    assert packet_utils.should_skip_pkt(nd_ind_adv)
    # Neighbor Discovery - Source Link-Layer Address
    assert packet_utils.should_skip_pkt(nd_opt_src_ll_addr)

    # TLS
    assert packet_utils.should_skip_pkt(tls_raw)
    assert packet_utils.should_skip_pkt(tls_server_hello)

    # DHCPv6
    assert packet_utils.should_skip_pkt(dhcpv6_solicit)
    assert packet_utils.should_skip_pkt(dhcpv6_advertise)
    assert packet_utils.should_skip_pkt(dhcpv6_request)
    assert packet_utils.should_skip_pkt(dhcpv6_reply)


    ### Non-signalling packets ###

    # Regular TCP packet
    assert not packet_utils.should_skip_pkt(tcp)
    # Regular UDP packet
    assert not packet_utils.should_skip_pkt(udp)
    # TLS Client Hello with Server Name extension
    assert not packet_utils.should_skip_pkt(tls_server_name)
    # HTTP
    assert not packet_utils.should_skip_pkt(http_get)
    assert not packet_utils.should_skip_pkt(http_resp)
    # DNS
    assert not packet_utils.should_skip_pkt(dns_query_A)
    assert not packet_utils.should_skip_pkt(dns_response_A)


def test_get_last_layer() -> None:
    """
    Test the function `get_last_layer`.
    """
    assert isinstance(packet_utils.get_last_layer(arp_request), ARP)
    assert isinstance(packet_utils.get_last_layer(tcp), TCP)
    assert isinstance(packet_utils.get_last_layer(tcp_ack_raw), TCP)
    assert isinstance(packet_utils.get_last_layer(tcp_ack_with_data), TCP)
    assert isinstance(packet_utils.get_last_layer(udp), UDP)
    assert isinstance(packet_utils.get_last_layer(udp_padding), UDP)
    assert isinstance(packet_utils.get_last_layer(nd_rs), ICMPv6ND_RS)
    assert isinstance(packet_utils.get_last_layer(ml_query), ICMPv6MLQuery)
    assert isinstance(packet_utils.get_last_layer(ml_report), ICMPv6MLReport)
    assert isinstance(packet_utils.get_last_layer(nd_ind_adv), ICMPv6ND_INDAdv)
    assert isinstance(packet_utils.get_last_layer(nd_opt_src_ll_addr), ICMPv6NDOptSrcLLAddr)
    assert isinstance(packet_utils.get_last_layer(tls_raw), TLS)
    assert isinstance(packet_utils.get_last_layer(tls_server_name), ServerName)
    assert isinstance(packet_utils.get_last_layer(tls_server_hello), TLSServerHello)
    assert isinstance(packet_utils.get_last_layer(http_get), HTTPRequest)
    assert isinstance(packet_utils.get_last_layer(http_resp), HTTPResponse)
    assert isinstance(packet_utils.get_last_layer(dns_query_A), DNSQR)
    assert isinstance(packet_utils.get_last_layer(dns_response_A), DNSRR)


def test_extract_domain_names() -> None:
    """
    Test the function `extract_domain_names`.
    """
    # TLS Client Hello with Server Name extension
    dns_table = {}
    packet_utils.extract_domain_names(tls_server_name, dns_table)
    assert "www.example.com" in dns_table[DnsTableKeys.IP.name]["93.184.216.34"]

    ## DNS
    dns_table = {}
    # DNS query
    packet_utils.extract_domain_names(dns_query_A, dns_table)
    assert not dns_table
    # DNS response
    packet_utils.extract_domain_names(dns_response_A, dns_table)
    assert "www.example.com" in dns_table[DnsTableKeys.IP.name]["93.184.216.34"]

    # DNS PTR response
    # DNS table has not been flushed, so the domain name should not be added
    packet_utils.extract_domain_names(dns_response_PTR, dns_table)
    assert "www.example.com" in dns_table[DnsTableKeys.IP.name]["93.184.216.34"]
    assert "www.example2.com" not in dns_table[DnsTableKeys.IP.name]["93.184.216.34"]

    # DNS PTR, with flushed DNS table
    dns_table = {}
    packet_utils.extract_domain_names(dns_query_PTR, dns_table)
    assert not dns_table
    packet_utils.extract_domain_names(dns_response_PTR, dns_table)
    assert "www.example2.com" in dns_table[DnsTableKeys.IP.name]["93.184.216.34"]


def test_get_domain_name_from_ip() -> None:
    """
    Test the function `get_domain_name_from_ip`.
    """
    # Build DNS table
    dns_table = {
        DnsTableKeys.IP.name: {
            "1.1.1.1": "www.example1.com",
            "2.2.2.2": "www.example2.com",
            "3.3.3.3": "server3.example.com"
        },
        DnsTableKeys.ALIAS.name: {
            "server3.example.com": "www.example3.com"
        }
    }

    # Known IP with direct domain name
    assert packet_utils.get_domain_name_from_ip("1.1.1.1", dns_table) == "www.example1.com"
    assert packet_utils.get_domain_name_from_ip("2.2.2.2", dns_table) == "www.example2.com"
    # Known IP with alias
    assert packet_utils.get_domain_name_from_ip("3.3.3.3", dns_table) == "www.example3.com"
    # Unknown IP
    with pytest.raises(KeyError):
        packet_utils.get_domain_name_from_ip("0.0.0.0", dns_table)
