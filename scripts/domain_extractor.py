import scapy.all as scapy
from scapy.layers.tls.all import TLS, TLS_Ext_ServerName
from scapy.all import IP, IPv6
from scapy.layers.dns import DNS
from signature_extractor import PacketFields


def extract_domain_names(packet_list: scapy.PacketList) -> dict:
    """
    Extract domain names from a list of packets.

    Args:
        packetList (scapy.PacketList): List of packets.

    Returns:
        dict: Dictionary containing domain names and their associated IP addresses.
    """

    domain_names = {}

    # Iterate on all packets
    for pkt in packet_list:
        # Check if packet may contain domain names
        if pkt.haslayer(TLS_Ext_ServerName) or pkt.haslayer(DNS):
            # Extract domain names from TLS packets
            if (
                pkt.haslayer(TLS_Ext_ServerName)
                and len(pkt[TLS][TLS_Ext_ServerName].servernames) > 0
            ):
                ip = None
                if pkt.haslayer(IPv6):
                    ip = pkt["IPv6"].dst
                elif pkt.haslayer(IP):
                    ip = pkt["IP"].dst

                pkt = pkt.getlayer(TLS_Ext_ServerName)

                domain_name = pkt.servernames[0].servername.decode("utf-8")
                if domain_name not in domain_names:
                    domain_names[domain_name] = []
                if ip not in domain_names[domain_name]:
                    domain_names[domain_name].append(ip)

            # Extract domain names from DNS packets
            if pkt.haslayer(DNS):
                dns = pkt.getlayer(DNS)
                
                # Query
                if dns.qr == 0:
                    # Extract domain name
                    domain_name = dns.qd.qname.decode("utf-8")[0:-1]
                    if domain_name not in domain_names:
                        domain_names[domain_name] = []
                
                # Response
                if dns.qr == 1:  # Response
                    # Extract IP addresses
                    for i in range(dns.ancount):
                        domain_name = dns.an[i].rrname.decode("utf-8")[0:-1]
                        ip = dns.an[i].rdata

                        if domain_name not in domain_names:
                            domain_names[domain_name] = []

                        if ip not in domain_names[domain_name]:
                            domain_names[domain_name].append(ip)

        else:
            continue

    return domain_names


def replace_ip_with_domain_name(domain_names: dict, signature: dict) -> dict:
    """
    Replace IP addresses with domain names in a packet signature.
    """

    for domain_name, ip_addresses in domain_names.items():
        for ip_address in ip_addresses:
            try:
                if signature[PacketFields.DeviceHost.name] == ip_address:
                    signature[PacketFields.DeviceHost.name] = domain_name
                if signature[PacketFields.OtherHost.name] == ip_address:
                    signature[PacketFields.OtherHost.name] = domain_name
            except KeyError:
                pass

    return signature
