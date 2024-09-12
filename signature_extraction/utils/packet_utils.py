from scapy.all import Packet, ARP, IP, IPv6, TCP, Padding
from scapy.layers.inet6 import IPv6, ICMPv6ND_RS, ICMPv6MLQuery, ICMPv6MLReport, ICMPv6ND_INDAdv, ICMPv6NDOptSrcLLAddr
from scapy.layers.tls.all import TLS, TLS_Ext_ServerName
from scapy.layers.dns import DNS
from socket import getservbyport


### GLOBAL VARIABLES ###

## KNOWN PORTS ##
# Well-known ports, outside the range 0-1023
# Typical application layer ports
application_protocols = {
    "tcp": {
        20:   "ftp",
        80:   "http",
        443:  "https",
        5000: "ssdp",
        5683: "coap"
    },
    "udp": {
        53:   "dns",
        67:   "dhcp",
        68:   "dhcp",
        123:  "ntp",
        1900: "ssdp",
        5353: "mdns",
        5683: "coap"
    }
}
# Well-known ports, outside the range 0-1023
known_ports = {
    "tcp": [
        9999  # TP-Link Smart Home protocol port
    ],
    "udp": []
}

## PACKETS TO SKIP ##
skip_tcp_flags = [
    "S",  # SYN
    "F",  # FIN
    "R"   # RST
]
# Packet layers to skip
skip_layers = [
    Padding,
    ARP,
    ICMPv6ND_RS,
    ICMPv6MLQuery,
    ICMPv6MLReport,
    ICMPv6ND_INDAdv,
    ICMPv6NDOptSrcLLAddr,
    "IP Option Router Alert",
]


### FUNCTIONS ###

def is_known_port(port: int, protocol: str = "tcp") -> bool:
    """
    Check if the given port is a well-known transport layer port.

    :param port: given port number
    :return: True if the given port number is well-known, False otherwise
    """
    protocol = protocol.lower()
    
    # Check in the known ports list, outside the range 0-1023
    if port in known_ports[protocol] or port in application_protocols[protocol]:
        return True
    
    # Check if port is well-known by the OS
    try:
        getservbyport(port, protocol)
        return True
    except:
        return False


def is_signalling_pkt(pkt: Packet) -> bool:
    """
    Check if the given packet is a signalling packet (e.g., TCP SYN or ACK).

    :param pkt: packet to check
    :return: True if packet is a signalling packet, False otherwise
    """
    # TCP packet
    if pkt.haslayer(TCP):
        flags = pkt.getlayer(TCP).flags
        return any(flag in flags for flag in skip_tcp_flags)
        # TODO: remove ACK packets only if raw TCP

    # TODO: other signalling packets, e.g. TLS (except the packet containing the SNI)

    # Any of the layers to skip
    return any(pkt.haslayer(layer) for layer in skip_layers)


def get_last_layer(packet: Packet) -> Packet:
    """
    Get the last layer of a Scapy packet.

    :param packet: Scapy Packet
    :return: last packet layer
    """
    i = 0
    layer = packet.getlayer(i)
    while layer is not None:
        i += 1
        layer = packet.getlayer(i)

    # if layer is raw, return the previous layer
    if packet.getlayer(i - 1).name == "Raw":
        return packet.getlayer(i - 2)

    return packet.getlayer(i - 1)


def extract_domain_names(packet: Packet, domain_names: dict) -> None:
    """
    Extract domain name from a scapy packet.

    Args:
        packet (Packet): Packet read from the PCAP file.
        domain_names (dict): Dictionary containing domain names and their associated IP addresses.
    """
    if packet.haslayer(TLS_Ext_ServerName) or packet.haslayer(DNS):

        # Extract domain names from TLS packets
        if (
            packet.haslayer(TLS_Ext_ServerName)
            and len(packet[TLS][TLS_Ext_ServerName].servernames) > 0
        ):
            ip = None
            if packet.haslayer(IPv6):
                ip = packet["IPv6"].dst
            elif packet.haslayer(IP):
                ip = packet["IP"].dst

            packet = packet.getlayer(TLS_Ext_ServerName)

            domain_name = packet.servernames[0].servername.decode("utf-8")
            if domain_name not in domain_names:
                domain_names[domain_name] = []
            if ip not in domain_names[domain_name]:
                domain_names[domain_name].append(ip)

        # Extract domain names from DNS packets
        if packet.haslayer(DNS):
            dns = packet.getlayer(DNS)
            
            # Query
            if dns.qr == 0:
                # Extract domain name
                domain_name = dns.qd.qname.decode("utf-8")[:-1]
                if domain_name not in domain_names:
                    domain_names[domain_name] = []
            
            # Response
            if dns.qr == 1:  # Response
                # Extract IP addresses
                for i in range(dns.ancount):
                    domain_name = dns.an[i].rrname.decode("utf-8")[:-1]
                    ip = dns.an[i].rdata

                    if domain_name not in domain_names:
                        domain_names[domain_name] = []

                    if ip not in domain_names[domain_name]:
                        domain_names[domain_name].append(ip)
