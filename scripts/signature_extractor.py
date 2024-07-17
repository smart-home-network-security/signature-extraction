import scapy.all as scapy
from scapy.all import IP, TCP, UDP, IPv6
from scapy.contrib.coap import CoAP, coap_codes
from scapy.layers.dhcp import DHCP, DHCPTypes
from scapy.layers.dns import DNS, DNSQR, DNSRR, dnstypes, dnsqtypes
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from packet_utils import get_last_layer, is_known_port, get_TCP_application_layer
from enum import Enum


class PacketFields(Enum):
    """
    Enum class for fields describing a packet signature.
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


def extract_signature(pkt: scapy.Packet) -> dict:
    """
    Extract the relevant fields from the given packet.

    :param pkt: packet to extract the signature from
    :return: packet signature
    """
    # Resulting signature dict
    signature = {}

    signature[PacketFields.Timestamp.name] = pkt.time

    # IP addresses
    if pkt.haslayer(IP):
        signature[PacketFields.DeviceHost.name] = pkt.getlayer(IP).src
        signature[PacketFields.OtherHost.name] = pkt.getlayer(IP).dst
    elif pkt.haslayer(IPv6):
        signature[PacketFields.DeviceHost.name] = pkt.getlayer(IPv6).src
        signature[PacketFields.OtherHost.name] = pkt.getlayer(IPv6).dst

    # Ports
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        if is_known_port(pkt.sport):
            signature[PacketFields.DevicePort.name] = pkt.sport
        if is_known_port(pkt.dport):
            signature[PacketFields.OtherPort.name] = pkt.dport

        # Transport protocol
        if pkt.haslayer(TCP):
            signature[PacketFields.TransportProtocol.name] = "TCP"
        elif pkt.haslayer(UDP):
            signature[PacketFields.TransportProtocol.name] = "UDP"

        # Application-specific layer
        # WARNING: Might be time-consuming for large packet traces
        signature[PacketFields.ApplicationSpecific.name] = get_TCP_application_layer(
            pkt
        )

    # Highest-layer protocol
    signature[PacketFields.Protocol.name] = get_last_layer(pkt).name

    # Packet length
    signature[PacketFields.Length.name] = len(pkt)

    # Protocol-specific fields

    if pkt.haslayer(CoAP):
        signature[PacketFields.Protocol.name] = "CoAP"
        signature[PacketFields.ApplicationSpecific.name] = get_CoAP_data(pkt)
        return signature

    if pkt.haslayer(DHCP):
        signature[PacketFields.Protocol.name] = "DHCP"
        dhcp = pkt.getlayer(DHCP)
        dhcp.show()
        signature[PacketFields.ApplicationSpecific.name] = DHCPTypes[dhcp.options[0][1]]
        return signature

    if pkt.haslayer(DNS):
        signature[PacketFields.Protocol.name] = "DNS"
        signature[PacketFields.ApplicationSpecific.name] = get_DNS_data(pkt)
        return signature

    if pkt.haslayer(HTTP):
        signature[PacketFields.Protocol.name] = "HTTP"
        signature[PacketFields.ApplicationSpecific.name] = get_HTTP_data(pkt)
        return signature

    return signature


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
