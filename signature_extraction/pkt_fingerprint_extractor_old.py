import scapy.all as scapy
from scapy.all import IP, TCP, UDP, IPv6
from scapy.contrib.coap import CoAP, coap_codes
from scapy.layers.dhcp import DHCP, DHCPTypes
from scapy.layers.dns import DNS, DNSQR, DNSRR, dnstypes, dnsqtypes
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from packet_utils import get_last_layer, get_TCP_application_layer
from enum import Enum


class PacketFields(Enum):
    """
    Enum class for fields describing a packet fingerprint.
    """

    Index = 0
    Timestamp = 1
    DeviceHost = 2
    OtherHost = 3
    DevicePort = 4
    OtherPort = 5
    TransportProtocol = 6
    Protocol = 7
    Direction = 8
    Length = 9
    ApplicationSpecific = 10


packet_fields = [field.name for field in PacketFields]


def extract_pkt_fingerprint(pkt: scapy.Packet) -> dict:
    """
    Extract the relevant fields from the given packet.

    :param pkt: packet to extract the fingerprint from
    :return: packet fingerprint
    """
    # Resulting fingerprint dict
    pkt_fingerprint = {}

    pkt_fingerprint[PacketFields.Timestamp.name] = pkt.time

    # IP addresses
    if pkt.haslayer(IP):
        pkt_fingerprint[PacketFields.DeviceHost.name] = pkt.getlayer(IP).src
        pkt_fingerprint[PacketFields.OtherHost.name] = pkt.getlayer(IP).dst
    elif pkt.haslayer(IPv6):
        pkt_fingerprint[PacketFields.DeviceHost.name] = pkt.getlayer(IPv6).src
        pkt_fingerprint[PacketFields.OtherHost.name] = pkt.getlayer(IPv6).dst

    # Ports
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        protocol = pkt.getlayer(2).name
        pkt_fingerprint[PacketFields.TransportProtocol.name] = protocol
        pkt_fingerprint[PacketFields.DevicePort.name] = pkt.sport
        pkt_fingerprint[PacketFields.OtherPort.name] = pkt.dport

        # Application-specific layer
        # WARNING: Might be time-consuming for large packet traces
        pkt_fingerprint[PacketFields.ApplicationSpecific.name] = get_TCP_application_layer(pkt)

    # Highest-layer protocol
    pkt_fingerprint[PacketFields.Protocol.name] = get_last_layer(pkt).name

    # Packet length
    pkt_fingerprint[PacketFields.Length.name] = len(pkt)

    ## Protocol-specific fields

    # HTTP
    if pkt.haslayer(HTTP):
        pkt_fingerprint[PacketFields.Protocol.name] = "HTTP"
        pkt_fingerprint[PacketFields.ApplicationSpecific.name] = get_HTTP_data(pkt)
        return pkt_fingerprint

    # HTTPS
    if pkt_fingerprint[PacketFields.ApplicationSpecific.name] == "https":
        pkt_fingerprint[PacketFields.Protocol.name] = "HTTPS"
        return pkt_fingerprint

    # CoAP
    if pkt.haslayer(CoAP):
        pkt_fingerprint[PacketFields.Protocol.name] = "CoAP"
        pkt_fingerprint[PacketFields.ApplicationSpecific.name] = get_CoAP_data(pkt)
        return pkt_fingerprint

    # DHCP
    if pkt.haslayer(DHCP):
        pkt_fingerprint[PacketFields.Protocol.name] = "DHCP"
        dhcp = pkt.getlayer(DHCP)
        dhcp.show()
        pkt_fingerprint[PacketFields.ApplicationSpecific.name] = DHCPTypes[dhcp.options[0][1]]
        return pkt_fingerprint

    # DNS
    if pkt.haslayer(DNS):
        pkt_fingerprint[PacketFields.Protocol.name] = "DNS"
        pkt_fingerprint[PacketFields.ApplicationSpecific.name] = get_DNS_data(pkt)
        return pkt_fingerprint

    return pkt_fingerprint


def get_DNS_data(pkt: scapy.Packet) -> str:
    """
    Get the DNS data from a DNS packet.

    :param pkt: DNS packet
    :return: DNS data
    """
    dns = pkt.getlayer(DNS)

    if pkt.haslayer(DNSQR):
        dns = pkt.getlayer(DNSQR)
        return f"{dnsqtypes[dns.qtype]} {dns.qname.decode('utf-8')}"

    if pkt.haslayer(DNSRR):
        dns = pkt.getlayer(DNSRR)
        return (
            f"{dnstypes[dns.type]} {dns.rrname.decode('utf-8') if dns.rrname else ''}"
        )

    return ""


def get_CoAP_data(pkt: scapy.Packet) -> str:
    """
    Get the CoAP data from a CoAP packet.
    """
    coap_packet = pkt.getlayer(CoAP)
    type = coap_packet.type
    method = coap_codes[coap_packet.code]
    options = coap_packet.options

    # Initialize empty lists for Uri-Path and Uri-Query
    uri_path = []
    uri_query = []

    # Iterate over the list of options
    for opt in options:
        key, value = opt
        if key == "Uri-Path":
            uri_path.append(value.decode())
        elif key == "Uri-Query":
            uri_query.append(value.decode())

    # Construct the URI path and query string
    uri_path_str = "/" + "/".join(uri_path)
    uri_query_str = "&".join(uri_query)

    # Combine to form the final URI
    uri = f"{uri_path_str}?{uri_query_str}" if uri_query_str else uri_path_str

    return f"{type} {method} {uri}"


def get_HTTP_data(pkt: scapy.Packet) -> str:
    """
    Get the HTTP data from a HTTP packet.

    :param pkt: HTTP packet
    :return: HTTP data
    """
    data = ""
    if pkt.haslayer(HTTPRequest):
        http = pkt.getlayer(HTTPRequest)
        uri = (http.Host).decode("utf-8") + (http.Path).decode("utf-8")
        method = (http.Method).decode("utf-8")
        data = "{method} {uri}"
    elif pkt.haslayer(HTTPResponse):
        data = "{pkt.getlayer(HTTPResponse).Status_Code.decode('utf-8')} {pkt.getlayer(HTTPResponse).Reason_Phrase.decode('utf-8')}"

    return data
