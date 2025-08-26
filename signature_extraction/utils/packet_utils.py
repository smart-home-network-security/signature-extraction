from typing import Any
import re
from ipaddress import ip_address, IPv4Address, IPv6Address
from scapy.all import Packet as ScapyPacket
from scapy.all import ARP, IP, IPv6, TCP, UDP, Padding, Raw
from scapy.layers.inet6 import IPv6, ICMPv6ND_RS, ICMPv6MLQuery, ICMPv6MLReport, ICMPv6ND_INDAdv, ICMPv6NDOptSrcLLAddr
from scapy.layers.tls.all import TLS, TLSApplicationData, TLS_Ext_ServerName
from scapy.layers.dns import DNS
from scapy.layers.dhcp import BOOTP, DHCP
from socket import getservbyport
from dns_unbound_cache_reader import DnsRtype, DnsTableKeys


### GLOBAL VARIABLES ###

## KNOWN PORTS ##
# Well-known ports, outside the range 0-1023
# Typical application layer ports
application_protocols = {
    "tcp": {
        20:   "ftp",
        53:   "dns",
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
        9999,  # TP-Link Smart Home protocol port
        20002  # Tapo UDP port
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
    BOOTP,
    DHCP,
    # ICMPv6
    ICMPv6ND_RS,
    ICMPv6MLQuery,
    ICMPv6MLReport,
    ICMPv6ND_INDAdv,
    ICMPv6NDOptSrcLLAddr,
    "IP Option Router Alert"
]
# DHCPv6
DHCP6 = "DHCP6"


### FUNCTIONS ###

def if_correct_type(value: Any, expected_type: type, default_value: Any = None) -> Any:
    """
    Check if the given value is of the expected type.
    Returns the value if it is;
    otherwise, returns the given default value, which defaults to None.

    Args:
        value (Any): given value
        expected_type (type): expected type
        default_value (Any): default value to return if the value is not of the expected type.
            Optional, default is None.
    Returns:
        Any: the given value if it is of the expected type, otherwise the default value
    """
    return value if isinstance(value, expected_type) else default_value


def policy_dict_to_other(policy_dict: dict, policy_field: str, other_dict: dict, flow_field: str) -> None:
    """
    Get a field from the policy dictionary and set it to another dictionary under a given field.

    Args:
        policy_dict (dict): Policy dictionary to get the field from.
        policy_field (str): Field name in the policy dictionary.
        flow_dict (dict): Other dictionary to set the field in.
        flow_field (str): Field name in the other dictionary.
    """
    try:
        other_dict[flow_field] = policy_dict[policy_field]
    except KeyError:
        pass


def is_ip_address(ip: str) -> bool:
    """
    Check if the given string is a valid IP (v4 or v6) address.

    Args:
        ip (str): given string
    Returns:
        bool: True if the string is a valid IP (v4 or v6) address, False otherwise
    """
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False
    

def guess_network_protocol(ip: str) -> str:
    """
    Guess the network-layer protocol (IPv4 or IPv6) of the given IP address.

    Args:
        ip (str): given IP address
    Returns:
        str: "IPv4" or "IPv6"
    Raises:
        ValueError: if the given IP address is not valid
    """
    try:
        ip = IPv4Address(ip)
        return "IPv4"
    except ValueError:
        try:
            ip = IPv6Address(ip)
            return "IPv6"
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")


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
    except (OSError, OverflowError):
        return False
    else:
        return True


def is_domain_name(name: str) -> bool:
    """
    Check whether a given name is a valid name.

    Args:
        name (str): given name
    Returns:
        bool: True if the name is a valid domain name, False otherwise
    """
    pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    return bool(re.match(pattern, name))


def compare_domain_names(domain_a: str, domain_b: str) -> bool:
    """
    Compare two domain names.

    Args:
        domain_a (str): first domain name
        domain_b (str): second domain name
    Returns:
        bool: True if the two domain names are (considered) equal, False otherwise
    """
    # If both are identical, return True
    if domain_a == domain_b:
        return True

    # If one domain name is a subdomain of the other, return True
    if domain_a.endswith(domain_b) or domain_b.endswith(domain_a):
        return True

    # If both domain names are subdomains of the same domain, return True
    if domain_a.split(".", 1)[1] == domain_b.split(".", 1)[1]:
        return True

    return False
    

def compare_hosts(host_a: str, host_b: str) -> bool:
    """
    Compare two hostnames or IP addresses.

    Args:
        host_a (str): first hostname or IP address
        host_b (str): second hostname or IP address
    Returns:
        bool: True if the two hosts are equal, False otherwise
    """
    # If both are identical, return True
    if host_a == host_b:
        return True

    # Try to convert to IP address
    a_is_ip = is_ip_address(host_a)
    b_is_ip = is_ip_address(host_b)

    if a_is_ip and b_is_ip:
        # If both are IP addresses, compare them
        # (should be False by now)
        return host_a == host_b
    
    # If one is an IP address and the other is a hostname, return False
    elif a_is_ip and not b_is_ip:
        return False
    elif not a_is_ip and b_is_ip:
        return False

    # Both are different hostnames
    # Check if they are valid domain names
    if not is_domain_name(host_a) or not is_domain_name(host_b):
        return False

    # Both are valid domain names
    # If they differ only by the first subdomain, consider them equal
    return compare_domain_names(host_a, host_b)


def get_wildcard_subdomain(domain_a: str, domain_b: str) -> str:
    """
    Get the wildcard subdomain matching the two given domain names.

    Args:
        domain_a (str): first domain name
        domain_b (str): second domain name
    Returns:
        str: wildcard subdomain matching the two domain names
    """
    if domain_a.endswith(domain_b):
        return f"*.{domain_b}"
    elif domain_b.endswith(domain_a):
        return f"*.{domain_a}"
    else:
        return f"*.{domain_a.split('.', 1)[1]}"


def should_skip_pkt(pkt: ScapyPacket) -> bool:
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
    
    # DHCPv6 packet
    if DHCP6 in pkt.summary():
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


def get_last_layer(packet: ScapyPacket) -> ScapyPacket:
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


def extract_domain_names(packet: ScapyPacket, dns_table: dict) -> None:
    """
    Extract domain name from a scapy packet,
    more precisely from TLS Server Name extension and DNS packets containing an answer section.
    The resulting dictionary takes the following format:
        {
            DnsTableKeys.IP: {
                ip_address: domain_name,
                ...
            },
            DnsTableKeys.ALIAS: {
                canonical_name: alias,
                ...
            }
        }

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
                domain_name = domain_name.getfieldval("servername").decode("utf-8")
                if DnsTableKeys.IP.name in dns_table:
                    dns_table[DnsTableKeys.IP.name][ip] = domain_name
                else:
                    dns_table[DnsTableKeys.IP.name] = {ip: domain_name}


        # Extract domain names from DNS packets
        if packet.haslayer(DNS):

            # Do not consider mDNS packets
            if packet.getfieldval("sport") == 5353 or packet.getfieldval("dport") == 5353:
                return

            dns = packet.getlayer(DNS)
            
            # Response
            if dns.qr == 1:  # Response

                # Extract IP addresses from DNS Answer and Additional sections
                for record in dns.an + dns.ar:
                    qname = record.rrname.decode("utf-8")
                    if qname.endswith("."):
                        qname = qname[:-1]

                    # A or AAAA record
                    if record.type == DnsRtype.A or record.type == DnsRtype.AAAA:
                        ip = record.rdata
                        if DnsTableKeys.IP.name in dns_table:
                            dns_table[DnsTableKeys.IP.name][ip] = qname
                        else:
                            dns_table[DnsTableKeys.IP.name] = {ip: qname}

                    # CNAME record
                    if record.type == DnsRtype.CNAME:
                        cname = record.rdata.decode("utf-8")
                        if cname.endswith("."):
                            cname = cname[:-1]
                        if DnsTableKeys.ALIAS.name in dns_table:
                            dns_table[DnsTableKeys.ALIAS.name][cname] = qname
                        else:
                            dns_table[DnsTableKeys.ALIAS.name] = {cname: qname}
                    
                    # SRV record
                    if record.type == DnsRtype.SRV:
                        service = record.target.decode("utf-8")
                        if service.endswith("."):
                            service = service[:-1]
                        if DnsTableKeys.ALIAS.name in dns_table:
                            dns_table[DnsTableKeys.ALIAS.name][service] = qname
                        else:
                            dns_table[DnsTableKeys.ALIAS.name] = {service: qname}
                    
                    # PTR record
                    if record.type == DnsRtype.PTR:
                        rdata = record.rdata.decode("utf-8")
                        if rdata.endswith("."):
                            rdata = rdata[:-1]
                        # Regex patterns
                        pattern_ipv4_byte = r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"                          # Single byte from an IPv4 address
                        pattern_ptr       = (pattern_ipv4_byte + r"\.") * 3 + pattern_ipv4_byte + r".in-addr.arpa"  # Reverse DNS lookup RDATA
                        match_ptr = re.match(pattern_ptr, qname)
                        if match_ptr:
                            # PTR record is a reverse DNS lookup
                            ip = ".".join(reversed(match_ptr.groups()))
                            if ip not in dns_table.get(DnsTableKeys.IP.name, {}):
                                if DnsTableKeys.IP.name in dns_table:
                                    dns_table[DnsTableKeys.IP.name][ip] = rdata
                                else:
                                    dns_table[DnsTableKeys.IP.name] = {ip: rdata}
                        else:
                            # PTR record contains generic RDATA
                            if DnsTableKeys.ALIAS.name in dns_table:
                                dns_table[DnsTableKeys.ALIAS.name][qname] = rdata
                            else:
                                dns_table[DnsTableKeys.ALIAS.name] = {qname: rdata}


def get_domain_name_from_ip(ip: str, dns_table: dict) -> str:
    """
    Get the domain name associated with the given IP address.

    Args:
        ip (str): IP address to look up.
        dns_table (dict): Dictionary mapping IP addresses and their associated domain names.
    Returns:
        str: Domain name associated with the given IP address.
    Raises:
        KeyError: if the IP address is not found in the DNS table.
    """
    if DnsTableKeys.IP.name in dns_table:
        dns_table_ip = dns_table[DnsTableKeys.IP.name]
        domain_name = dns_table_ip[ip]

        # Replace name with alias if available
        if DnsTableKeys.ALIAS.name in dns_table:
            dns_table_alias = dns_table[DnsTableKeys.ALIAS.name]
            domain_name = dns_table_alias.get(domain_name, domain_name)

        return domain_name
    else:
        raise KeyError(f"IP address {ip} not found in DNS table")
