## Imports
# Libraries
import pytest
from scapy.all import IP, TCP
import scapy.layers.http as http
# Package
import signature_extraction.utils.distance as distance
from signature_extraction.application_layer import HTTP


### VARIABLES ###

## From scapy Packets

## HTTP GET requests
http_get_layer = (
    http.HTTP() /
    http.HTTPRequest(
        Method=b"GET",
        Path=b"/test/stuff",
        Http_Version=b"HTTP/1.1",
        Host=b"www.example.com",
        User_Agent=b"Scapy"
    ))
pkt_http_get = (
    IP(dst="www.example.com") /
    TCP(dport=80) /
    http_get_layer
)

http_get_layer_2 = (
    http.HTTP() /
    http.HTTPRequest(
        Method=b"GET",
        Path=b"/test/stuff",
        Http_Version=b"HTTP/1.1",
        Host=b"www.example.com"
    ))
http_get_layer_3 = (
    http.HTTP() /
    http.HTTPRequest(
        Method=b"GET",
        Path=b"/test/thing",
        Http_Version=b"HTTP/1.1",
        Host=b"www.example.com",
        User_Agent=b"Scapy"
    ))

## HTTP POST requests
http_post_layer = (
    http.HTTP() /
    http.HTTPRequest(
        Method=b"POST",
        Path=b"/test/stuff",
        Http_Version=b"HTTP/1.1",
        Host=b"www.example.com",
        User_Agent=b"Scapy"
    )
)
pkt_http_post = (
    IP(dst="www.example.com") /
    TCP(dport=80) /
    http_post_layer
)

## HTTP responses
http_resp_layer = (
    http.HTTP() /
    http.HTTPResponse(
        Http_Version=b"HTTP/1.1",
        Status_Code=b"200",
        Reason_Phrase=b"OK",
        Content_Type=b"text/html",
        Connection=b"close"
    )
)
pkt_http_resp = (
    IP(src="www.example.com") /
    TCP(sport=80) /
    http_resp_layer
)

http_resp_layer_error = (
    http.HTTP() /
    http.HTTPResponse(
        Http_Version=b"HTTP/1.1",
        Status_Code=b"404"
    )
)

# HTTP requests
http_get   = HTTP(http_get_layer)
http_get_2 = HTTP(http_get_layer_2)
http_get_3 = HTTP(http_get_layer_3)
http_post  = HTTP(http_post_layer)
# HTTP responses
http_resp = HTTP(http_resp_layer)
http_resp_error = HTTP(http_resp_layer_error)


## From policy's protocol dictionary

# GET request
dict_get = {
    "method": "GET",
    "uri": "/test/stuff"
}
http_get_from_policy = HTTP(dict_get)

# Response
dict_resp = {
    "response": True
}
http_resp_from_policy = HTTP(dict_resp)


### TEST FUNCTIONS ###

def test_http_get() -> None:
    """
    Test the constructor with an HTTP GET request.
    """
    http_pkt = HTTP(pkt_http_get)
    assert http_pkt.protocol_name == "HTTP"
    assert not HTTP.is_response(pkt_http_get)
    assert not http_pkt.response
    assert http_pkt.method == "GET"
    assert http_pkt.uri == "/test/stuff"

    http_dict = dict(http_pkt)
    assert not http_dict["response"]
    assert http_dict["method"] == "GET"
    assert http_dict["uri"] == "/test/stuff"


def test_http_post() -> None:
    """
    Test the constructor with an HTTP POST request.
    """
    http_pkt = HTTP(pkt_http_post)
    assert http_pkt.protocol_name == "HTTP"
    assert not HTTP.is_response(pkt_http_post)
    assert not http_pkt.response
    assert http_pkt.method == "POST"
    assert http_pkt.uri == "/test/stuff"

    http_dict = dict(http_pkt)
    assert not http_dict["response"]
    assert http_dict["method"] == "POST"
    assert http_dict["uri"] == "/test/stuff"


def test_http_resp() -> None:
    """
    Test the constructor with an HTTP response.
    """
    http_pkt = HTTP(pkt_http_resp)
    assert http_pkt.protocol_name == "HTTP"
    assert HTTP.is_response(pkt_http_resp)
    assert http_pkt.response
    assert http_pkt.method is None
    assert http_pkt.uri is None

    http_dict = dict(http_pkt)
    assert http_dict["response"]
    with pytest.raises(KeyError):
        assert http_dict["method"] is None
    with pytest.raises(KeyError):
        assert http_dict["uri"] is None


def test_http_get_from_policy() -> None:
    """
    Test the constructor with a policy's protocol dictionary
    describing an HTTP GET request.
    """
    assert http_get_from_policy.protocol_name == "HTTP"
    assert not http_get_from_policy.response
    assert http_get_from_policy.method == "GET"
    assert http_get_from_policy.uri == "/test/stuff"


def test_http_response_from_policy() -> None:
    """
    Test the constructor with a policy's protocol dictionary
    describing an HTTP response.
    """
    assert http_resp_from_policy.protocol_name == "HTTP"
    assert http_resp_from_policy.response
    assert http_resp_from_policy.method is None
    assert http_resp_from_policy.uri is None


def test_hash() -> None:
    """
    Test the hash function.
    """
    assert hash(http_get)  == hash(http_get_2)
    assert hash(http_get)  == hash(http_get_3)
    assert hash(http_get)  == hash(http_post)
    assert hash(http_post) == hash(http_resp)
    assert hash(http_get)  == hash(http_resp)
    assert hash(http_resp) == hash(http_resp_error)


def test_diff() -> None:
    """
    Test the diff function,
    which extracts the difference between two HTTP objects.
    """
    assert http_get.diff(http_get)   == {}
    assert http_get.diff(http_get_2) == {}
    assert http_get.diff(http_get_3) == {
        "uri": (http_get.uri, http_get_3.uri)
    }
    assert http_get.diff(http_post)  == {
        "method": (http_get.method, http_post.method)
    }
    assert http_get.diff(http_resp) == {
        "method": (http_get.method, None),
        "uri": (http_get.uri, None)
    }


def test_compute_distance() -> None:
    """
    Test the distance function.
    """
    assert http_get.compute_distance(http_get_2) == distance.ZERO
    assert http_get.compute_distance(http_get_3) == HTTP.WEIGHT_METHOD * distance.ZERO + HTTP.WEIGHT_URI * distance.levenshtein_ratio(http_get.uri, http_get_3.uri)
    assert http_get.compute_distance(http_post) == HTTP.WEIGHT_METHOD * distance.ONE + HTTP.WEIGHT_URI * distance.ZERO
    assert http_get.compute_distance(http_resp) == distance.ONE
    assert http_get.compute_distance(http_resp_error) == distance.ONE
    assert http_resp.compute_distance(http_resp_error) == distance.ZERO
