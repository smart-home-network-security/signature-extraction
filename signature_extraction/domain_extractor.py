import scapy.all as scapy
from scapy.layers.tls.all import TLS, TLS_Ext_ServerName
from scapy.all import IP, IPv6
from scapy.layers.dns import DNS
from pkt_fingerprint_extractor_old import PacketFields


def extract_domain_names(packet: scapy.Packet, domain_names: dict) -> None:
    """
    Extract domain name from a scapy packet.

    Args:
        packet (scapy.Packet): Packet read from the PCAP file.
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
