from scapy.all import Packet, ARP, IP, IPv6, TCP, UDP, Padding, Raw
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


def should_skip_pkt(pkt: Packet) -> bool:
    """
    Check if the given packet is a signalling packet (e.g., TCP SYN or ACK).

    :param pkt: packet to check
    :return: True if the packet should be skipped, False otherwise
    """
    # Packet does not have a transport layer, skip it
    if not pkt.haslayer(TCP) and not pkt.haslayer(UDP):
        return True

    # TLS packet
    if pkt.haslayer(TLS):
        try:
            extensions = pkt[TLS].ext
        except AttributeError:
            # Other TLS packets are signalling packets
            return True
        else:
            if extensions is None:
                return True
            for extension in extensions:
                if isinstance(extension, TLS_Ext_ServerName):
                    # TLS Client Hello with Server Name extension, not a signalling packet
                    return False

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

    :param packet: Scapy Packet
    :return: last packet layer
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


def extract_domain_names(packet: Packet, domain_names: dict) -> None:
    """
    Extract domain name from a scapy packet.

    Args:
        packet (Packet): Packet read from the PCAP file.
        domain_names (dict): Dictionary containing domain names and their associated IP addresses.
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
                if domain_name not in domain_names:
                    domain_names[domain_name] = []
                if ip not in domain_names[domain_name]:
                    domain_names[domain_name].append(ip)

        # Extract domain names from DNS packets
        if packet.haslayer(DNS):
            dns = packet.getlayer(DNS)
            
            # Query
            if dns.qr == 0 and len(dns.qd) > 0:
                # Extract domain name
                domain_name = dns.qd[0].qname.decode("utf-8")[:-1]
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
