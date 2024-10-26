from enum import IntEnum, StrEnum
from scapy.all import Packet, ARP, IP, IPv6, TCP, UDP, Padding, Raw
from scapy.layers.inet6 import IPv6, ICMPv6ND_RS, ICMPv6MLQuery, ICMPv6MLReport, ICMPv6ND_INDAdv, ICMPv6NDOptSrcLLAddr
from scapy.layers.tls.all import TLS, TLSApplicationData, TLS_Ext_ServerName
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
        3478: "stun",
        5000: "ssdp",
        5683: "coap"
    },
    "udp": {
        53:   "dns",
        67:   "dhcp",
        68:   "dhcp",
        123:  "ntp",
        1900: "ssdp",
        3478: "stun",
        5353: "mdns",
        5683: "coap"
    }
}
# Well-known ports, outside the range 0-1023
known_ports = {
    "tcp": [
        8800,  # Tapo companion app TCP port
        9999   # TP-Link Smart Home protocol port
    ],
    "udp": [
        20002  # Tapo camera UDP port
    ]
}

## PACKETS TO SKIP ##
# TCP flags
skip_tcp_flags = [
    "S",  # SYN
    "F",  # FIN
    "R"   # RST
]
# Packet layers
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


### ENUM CLASSES ###

class DnsQtype(IntEnum):
    """
    Enum class for the DNS query types.
    """
    A    = 1
    PTR  = 12
    AAAA = 28
    SRV  = 33


class DnsTableKeys(StrEnum):
    """
    Enum class for the allowed dictionary keys.
    """
    IP      = "ip"
    SERVICE = "service"


### FUNCTIONS ###

def is_known_port(port: int, protocol: str = "tcp") -> bool:
    """
    Check if the given port is a well-known transport layer port.

    Args:
        port (int): given port number
        protocol (str): transport layer protocol (tcp or udp). Optional, default is "tcp"
    Returns:
        bool: True if the given port number is well-known, False otherwise
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


def should_skip_pkt(pkt: Packet) -> bool:
    """
    Check if the given packet should be skipped,
    i.e. if it is a control-plane packet,
    e.g. ARP, ICMP, TCP SYN/ACK, TLS Handshake.
    
    Args:
        pkt (scapy.Packet): packet to check
    Returns:
        bool: True if the packet should be skipped, False otherwise
    """
    # Packet does not have a transport layer, skip it
    if not pkt.haslayer(TCP) and not pkt.haslayer(UDP):
        return True

    # TLS packet
    if pkt.haslayer(TLS):
        # Do not skip TLS packets with application data or Server Name extension
        return not (pkt.haslayer(TLSApplicationData) or pkt.haslayer(TLS_Ext_ServerName))

    # TCP packet
    if pkt.haslayer(TCP):
        flags = pkt.getlayer(TCP).flags
        if "A" in flags:
            # Remove ACK packets only if raw TCP
            if isinstance(pkt.lastlayer(), TCP):
                return True

        # Skip TCP packets with SYN, FIN, or RST flags
        return any(flag in flags for flag in skip_tcp_flags)

    # Any of the layers to skip
    return any(pkt.haslayer(layer) for layer in skip_layers)


def get_last_layer(packet: Packet) -> Packet:
    """
    Get the last layer of a Scapy packet.

    Args:
        packet (scapy.Packet): full Scapy Packet
    Returns:
        scapy.Packet: last packet layer
    """
    i = 0
    layer = packet.getlayer(i)
    while layer is not None:
        i += 1
        layer = packet.getlayer(i)

    # If layer is Raw or Padding, return the previous layer
    if isinstance(packet.getlayer(i - 1), (Raw, Padding)):
        return packet.getlayer(i - 2)

    return packet.getlayer(i - 1)


def extract_domain_names(packet: Packet, dns_table: dict) -> None:
    """
    Extract domain name from a scapy packet.

    Args:
        packet (Packet): Packet read from the PCAP file.
        dns_table (dict): Dictionary containing domain names and their associated IP addresses.
    """
    # Only consider packets with TLS Server Name extension or DNS
    if packet.haslayer(TLS_Ext_ServerName) or packet.haslayer(DNS):

        # Extract domain names from TLS packets
        if packet.haslayer(TLS_Ext_ServerName):
            servernames = packet.getlayer(TLS_Ext_ServerName).servernames
            if len(servernames) <= 0:
                return
            
            ip = None
            if packet.haslayer(IPv6):
                ip = packet["IPv6"].dst
            elif packet.haslayer(IP):
                ip = packet["IP"].dst

            for domain_name in servernames:
                domain_name = domain_name
                if DnsTableKeys.IP in dns_table:
                    dns_table[DnsTableKeys.IP][ip] = domain_name
                else:
                    dns_table[DnsTableKeys.IP] = {ip: domain_name}

        # Extract domain names from DNS packets
        if packet.haslayer(DNS):

            # Do not consider mDNS packets
            if packet.getfieldval("sport") == 5353 or packet.getfieldval("dport") == 5353:
                return

            dns = packet.getlayer(DNS)
            
            # Response
            if dns.qr == 1:  # Response

                # Extract IP addresses
                for i in range(dns.ancount):
                    an_record = dns.an[i]
                    domain_name = an_record.rrname.decode("utf-8")[:-1]

                    # A or AAAA record
                    if an_record.type == DnsQtype.A or an_record.type == DnsQtype.AAAA:

                        # Check if given domain name is present in the services set
                        if domain_name in dns_table.get(DnsTableKeys.SERVICE, {}):
                            domain_name = dns_table[DnsTableKeys.SERVICE][domain_name]

                        ip = dns.an[i].rdata
                        if DnsTableKeys.IP in dns_table:
                            dns_table[DnsTableKeys.IP][ip] = domain_name
                        else:
                            dns_table[DnsTableKeys.IP] = {ip: domain_name}
                    
                    # PTR record
                    if an_record.type == DnsQtype.PTR:
                        rdata = an_record.rdata.decode("utf-8")[:-1]
                        if DnsTableKeys.SERVICE in dns_table:
                            dns_table[DnsTableKeys.SERVICE][domain_name] = rdata
                        else:
                            dns_table[DnsTableKeys.SERVICE] = {domain_name: rdata}

                    # SRV record
                    if an_record.type == DnsQtype.SRV:
                        service = an_record.target.decode("utf-8")[:-1]
                        if DnsTableKeys.SERVICE in dns_table:
                            dns_table[DnsTableKeys.SERVICE][service] = domain_name
                        else:
                            dns_table[DnsTableKeys.SERVICE] = {service: domain_name}
