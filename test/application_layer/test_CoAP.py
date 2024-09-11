## Imports
# Libraries
from scapy.all import IP, UDP, Raw
import scapy.contrib.coap as coap
# Package
from signature_extraction.application_layer import CoAP


### VARIABLES ###

# HTTP GET request
options = [('Uri-Path', 'sensors'), ('Uri-Path', 'temperature')]
pkt_coap_get = (
    IP(src="192.168.1.100", dst="192.168.1.200") /
    UDP(sport=5683, dport=5683) /
    coap.CoAP(type=0, code=1, msg_id=0x1234, token=b"token", options=options)
)

# HTTP response
pkt_coap_resp = (
    IP(src="192.168.1.200", dst="192.168.1.100") /
    UDP(sport=5683, dport=5683) /
    coap.CoAP(type=2, code=69, msg_id=0x1234, token=b"token") /
    Raw(load=b"25.5 C")  # Sample temperature data in the response
)


### TEST FUNCTIONS ###

def test_coap_get() -> None:
    """
    Test the constructor with a CoAP GET request.
    """
    coap_pkt = CoAP(pkt_coap_get)
    assert coap_pkt.protocol_name == "CoAP"
    assert coap_pkt.get_protocol_name() == "CoAP"
    assert coap_pkt.type == CoAP.CoAPType.CON
    assert coap_pkt.code == coap.coap_codes[1]
    assert coap_pkt.uri_path == "/sensors/temperature"

    coap_dict = dict(coap_pkt)
    assert coap_dict["type"] == CoAP.CoAPType.CON
    assert coap_dict["code"] == coap.coap_codes[1]
    assert coap_dict["uri_path"] == "/sensors/temperature"


def test_coap_resp() -> None:
    """
    Test the constructor with a CoAP response.
    """
    coap_pkt = CoAP(pkt_coap_resp)
    assert coap_pkt.protocol_name == "CoAP"
    assert coap_pkt.get_protocol_name() == "CoAP"
    assert coap_pkt.type == CoAP.CoAPType.ACK
    assert coap_pkt.code == coap.coap_codes[69]
    assert coap_pkt.uri_path is None

    coap_dict = dict(coap_pkt)
    assert coap_dict["type"] == CoAP.CoAPType.ACK
    assert coap_dict["code"] == coap.coap_codes[69]
    assert coap_dict["uri_path"] is None
