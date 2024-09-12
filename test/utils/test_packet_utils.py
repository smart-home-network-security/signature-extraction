## Imports
# Libraries
from scapy.all import Ether, ARP, IP, TCP, UDP, Padding
from scapy.layers.inet6 import IPv6, ICMPv6ND_RS, ICMPv6MLQuery, ICMPv6MLReport, ICMPv6ND_INDAdv, ICMPv6NDOptSrcLLAddr
# Package
import signature_extraction.utils.packet_utils as packet_utils


### TEST FUNCTIONS ###

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


def test_is_signalling_pkt() -> None:
    """
    Test the function `is_signalling_pkt`.
    """
    ### Signalling packets ###

    ## TCP
    tcp_syn = Ether() / IP() / TCP(flags="S")
    assert packet_utils.is_signalling_pkt(tcp_syn)
    tcp_fin = Ether() / IP() / TCP(flags="F")
    assert packet_utils.is_signalling_pkt(tcp_fin)
    tcp_rst = Ether() / IP() / TCP(flags="R")
    assert packet_utils.is_signalling_pkt(tcp_rst)

    ## ARP
    # ARP request
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1")
    assert packet_utils.is_signalling_pkt(arp_request)
    # ARP reply
    arp_reply = (
        Ether(dst="00:11:22:33:44:55", src="66:77:88:99:aa:bb") /
        ARP(op=2, pdst="192.168.1.2", psrc="192.168.1.1", hwsrc="66:77:88:99:aa:bb", hwdst="00:11:22:33:44:55")
    )
    assert packet_utils.is_signalling_pkt(arp_reply)

    ## Padding
    padding = Padding()
    assert packet_utils.is_signalling_pkt(padding)

    ## ICMPv6
    # Neighbor Discovery - Router Solicitation
    nd_rs = Ether() / IPv6() / ICMPv6ND_RS()
    assert packet_utils.is_signalling_pkt(nd_rs)
    # Multicast Listener Query
    ml_query = Ether() / IPv6() / ICMPv6MLQuery()
    assert packet_utils.is_signalling_pkt(ml_query)
    # Multicast Listener Report
    ml_report = Ether() / IPv6() / ICMPv6MLReport()
    assert packet_utils.is_signalling_pkt(ml_report)
    # Neighbor Discovery - Interval Advertisement
    nd_ind_adv = Ether() / IPv6() / ICMPv6ND_INDAdv()
    assert packet_utils.is_signalling_pkt(nd_ind_adv)
    # Neighbor Discovery - Source Link-Layer Address
    nd_opt_src_ll_addr = Ether() / IPv6() / ICMPv6NDOptSrcLLAddr()
    assert packet_utils.is_signalling_pkt(nd_opt_src_ll_addr)


    ### Non-signalling packets ###

    # Regular TCP packet
    tcp = Ether() / IP() / TCP(flags="")
    assert not packet_utils.is_signalling_pkt(tcp)
    # Regular UDP packet
    udp = Ether() / IP() / UDP()
    assert not packet_utils.is_signalling_pkt(udp)


def test_get_last_layer() -> None:
    """
    Test the function `get_last_layer`.
    """
    # TODO
    pass


def test_extract_domain_names() -> None:
    """
    Test the function `extract_domain_names`.
    """
    # TODO
    pass
