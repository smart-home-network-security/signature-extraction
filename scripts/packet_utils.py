import scapy.all as scapy
from scapy.all import TCP
from socket import getservbyport


def is_known_port(port: int) -> bool:
    """
    Check if the given port is a well-known transport layer port.

    :param port: given port number
    :return: True if the given port number is well-known, False otherwise
    """
    # return port > 0 and port < 1024
    return True


def is_signalling_pkt(pkt: scapy.Packet) -> bool:
    """
    Check if the given packet is a signalling packet (e.g., TCP SYN or ACK).

    :param pkt: packet to check
    :return: True if packet is a signalling packet, False otherwise
    """

    # ARP packet
    if pkt.haslayer(scapy.ARP):
        return True

    # Padding packet
    if pkt.haslayer(scapy.Padding):
        return True

    # TCP packet
    if pkt.haslayer(TCP):
        signal_flags = [
            "S",  # SYN
            "F",  # FIN
            "R"   # RST
        ]
        flags = pkt.getlayer(TCP).flags
        return any(flag in flags for flag in signal_flags)
        # TODO: remove ACK packets only if raw TCP

    # TODO: other signalling packets, e.g. TLS (except the packet containing the SNI)

    if (
        pkt.haslayer("ICMPv6 Neighbor Discovery Option - Source Link-Layer Address")
        or pkt.haslayer("ICMPv6 Neighbor Discovery - Router Solicitation")
        or pkt.haslayer("ICMPv6 Neighbor Discovery - Interval Advertisement")
        or pkt.haslayer("MLD - Multicast Listener Query")
        or pkt.haslayer("IP Option Router Alert")
        or pkt.haslayer("MLD - Multicast Listener Report")
    ):
        return True

    return False


def get_last_layer(packet: scapy.Packet) -> scapy.Packet:
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


def get_TCP_application_layer(packet: scapy.Packet) -> str:
    """
    Get the application layer of a TCP packet by matching port numbers.

    :param packet: TCP packet
    :return: application layer
    """
    if packet.haslayer(TCP):
        sport = packet.getlayer(TCP).sport  # source port
        dport = packet.getlayer(TCP).dport  # destination port

        sd = ""  # source port description
        try:
            sd = getservbyport(sport)  # get service by port number
        except:
            pass
        fd = ""  # destination port description
        try:
            fd = getservbyport(dport)  # get service by port number
        except:
            pass

        return f"{sd}{fd}"  # return source and destination port descriptions
    return ""
