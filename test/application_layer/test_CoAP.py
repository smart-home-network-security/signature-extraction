## Imports
# Libraries
from scapy.all import IP, UDP, Raw
import scapy.contrib.coap as coap
# Package
import signature_extraction.utils.distance as distance
from signature_extraction.application_layer import CoAP


### VARIABLES ###

## From scapy Packets

# CoAP GET requests
options = [('Uri-Path', 'sensors'), ('Uri-Path', 'temperature')]
layer_coap_get = coap.CoAP(type=0, code=1, msg_id=0x1234, token=b"token", options=options)
pkt_coap_get = (
    IP(src="192.168.1.100", dst="192.168.1.200") /
    UDP(sport=5683, dport=5683) /
    layer_coap_get
)

layer_coap_get_2 = coap.CoAP(type=1, code=1, msg_id=0x1234, token=b"token", options=options)
layer_coap_get_3 = coap.CoAP(type=0, code=2, msg_id=0x1234, token=b"token", options=options)
options_4 = [('Uri-Path', 'sensors'), ('Uri-Path', 'pressure')]
layer_coap_get_4 = coap.CoAP(type=0, code=1, msg_id=0x1234, token=b"token", options=options_4)

# CoAP responses
layer_coap_resp = coap.CoAP(type=2, code=69, msg_id=0x1234, token=b"token")
pkt_coap_resp = (
    IP(src="192.168.1.200", dst="192.168.1.100") /
    UDP(sport=5683, dport=5683) /
    layer_coap_resp /
    Raw(load=b"25.5 C")  # Sample temperature data in the response
)

layer_coap_resp_2 = coap.CoAP(type=3, code=69, msg_id=0x1234, token=b"token")
layer_coap_resp_3 = coap.CoAP(type=2, code=68, msg_id=0x1234, token=b"token")

# CoAP requests
coap_get  = CoAP(layer_coap_get)
coap_get2 = CoAP(layer_coap_get_2)
coap_get3 = CoAP(layer_coap_get_3)
coap_get4 = CoAP(layer_coap_get_4)
# CoAP responses
coap_resp  = CoAP(layer_coap_resp)
coap_resp2 = CoAP(layer_coap_resp_2)
coap_resp3 = CoAP(layer_coap_resp_3)


## From policy's protocol dictionary

# Protocol dictionary
dict_policy = {
    "type": CoAP.CoAPType.CON,     # CoAP Confirmable
    "method": coap.coap_codes[1],  # CoAP GET
    "uri": "/sensors/temperature"
}

# CoAP object
coap_from_policy = CoAP(dict_policy)


### TEST FUNCTIONS ###

def test_coap_get() -> None:
    """
    Test the constructor with a CoAP GET request.
    """
    coap_pkt = CoAP(pkt_coap_get)
    assert coap_pkt.protocol_name == "CoAP"
    assert coap_pkt.get_protocol_name() == "CoAP"
    assert coap_pkt.is_request
    assert coap_pkt.code == coap.coap_codes[1]
    assert coap_pkt.uri_path == "/sensors/temperature"

    coap_dict = dict(coap_pkt)
    assert not coap_dict["response"]
    assert coap_dict["code"] == coap.coap_codes[1]
    assert coap_dict["uri"] == "/sensors/temperature"


def test_coap_resp() -> None:
    """
    Test the constructor with a CoAP response.
    """
    coap_pkt = CoAP(pkt_coap_resp)
    assert coap_pkt.protocol_name == "CoAP"
    assert coap_pkt.get_protocol_name() == "CoAP"
    assert not coap_pkt.is_request

    coap_dict = dict(coap_pkt)
    assert coap_dict["response"]


def test_coap_from_policy() -> None:
    """
    Test the constructor with a policy's protocol dictionary.
    """
    assert coap_from_policy.protocol_name == "CoAP"
    assert coap_from_policy.get_protocol_name() == "CoAP"
    assert coap_from_policy.is_request
    assert coap_from_policy.type == CoAP.CoAPType.CON
    assert coap_from_policy.code == coap.coap_codes[1]
    assert coap_from_policy.uri_path == "/sensors/temperature"


def test_eq() -> None:
    """
    Test the equality operator.
    """
    assert coap_get  == coap_get2
    assert coap_get  != coap_get3
    assert coap_get  != coap_get4
    assert coap_get  == coap_resp
    assert coap_get  == coap_resp2
    assert coap_resp == coap_resp2


def test_hash() -> None:
    """
    Test the hash function.
    """
    assert hash(coap_get)   == hash(coap_get2)
    assert hash(coap_get)   == hash(coap_get3)
    assert hash(coap_get)   == hash(coap_get4)
    assert hash(coap_get)   == hash(coap_resp)
    assert hash(coap_resp)  == hash(coap_resp2)
    assert hash(coap_resp)  == hash(coap_resp3)
    assert hash(coap_resp2) == hash(coap_resp3)


def test_diff() -> None:
    """
    Test the diff function,
    which extracts the difference between two CoAP objects.
    """
    # CoAP requests
    assert coap_get.diff(coap_get)  == {}
    assert coap_get.diff(coap_get2) == {}
    assert coap_get.diff(coap_get3) == {
        CoAP.CoAPFields.CODE.value: (coap_get.code, coap_get3.code)
    }
    assert coap_get.diff(coap_get4) == {
        CoAP.CoAPFields.URI.value: (coap_get.uri_path, coap_get4.uri_path)
    }

    # CoAP responses
    diff_response = {
        CoAP.CoAPFields.CODE.value: (coap_get.code, None),
        CoAP.CoAPFields.URI.value:  (coap_get.uri_path, None)
    }
    assert coap_get.diff(coap_resp)  == diff_response
    assert coap_get.diff(coap_resp2) == diff_response


def test_compute_distance() -> None:
    """
    Test the distance function.
    """
    # CoAP requests
    coap_get  = CoAP(layer_coap_get)
    coap_get2 = CoAP(layer_coap_get_2)
    coap_get3 = CoAP(layer_coap_get_3)
    coap_get4 = CoAP(layer_coap_get_4)
    # CoAP responses
    coap_resp = CoAP(layer_coap_resp)
    coap_resp2 = CoAP(layer_coap_resp_2)
    coap_resp3 = CoAP(layer_coap_resp_3)

    # Assertions
    assert coap_get.compute_distance(coap_get) == 0
    assert coap_get.compute_distance(coap_get2) == CoAP.WEIGHT_CODE * distance.ZERO + CoAP.WEIGHT_URI * distance.ZERO
    assert coap_get.compute_distance(coap_get3) == CoAP.WEIGHT_CODE * distance.ONE + CoAP.WEIGHT_URI * distance.ZERO
    assert coap_get.compute_distance(coap_get4) == CoAP.WEIGHT_CODE * distance.ZERO + CoAP.WEIGHT_URI * distance.levenshtein_ratio(coap_get.uri_path, coap_get4.uri_path)
    assert coap_get.compute_distance(coap_resp) == CoAP.WEIGHT_CODE * distance.ONE + CoAP.WEIGHT_URI * distance.ONE
    assert coap_get.compute_distance(coap_resp2) == CoAP.WEIGHT_CODE * distance.ONE + CoAP.WEIGHT_URI * distance.ONE
    assert coap_get.compute_distance(coap_resp3) == CoAP.WEIGHT_CODE * distance.ONE + CoAP.WEIGHT_URI * distance.ONE
    assert coap_resp.compute_distance(coap_resp) == 0
    assert coap_resp.compute_distance(coap_resp2) == 0
    assert coap_resp.compute_distance(coap_resp3) == 0
