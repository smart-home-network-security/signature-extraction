## Imports
# Libraries
from scapy.all import IP, TCP
import scapy.layers.http as http
# Package
from signature_extraction.application_layer import HTTP


### VARIABLES ###

# HTTP GET request
pkt_http_get = (
    IP(dst="www.example.com") /
    TCP(dport=80) /
    http.HTTP() /
    http.HTTPRequest(
        Method=b"GET",
        Path=b"/test/stuff",
        Http_Version=b"HTTP/1.1",
        Host=b"www.example.com",
        User_Agent=b"Scapy"
    )
)

# HTTP POST request
pkt_http_post = (
    IP(dst="www.example.com") /
    TCP(dport=80) /
    http.HTTP() /
    http.HTTPRequest(
        Method=b"POST",
        Path=b"/test/stuff",
        Http_Version=b"HTTP/1.1",
        Host=b"www.example.com",
        User_Agent=b"Scapy"
    )
)

# HTTP response
pkt_http_resp = (
    IP(src="www.example.com") /
    TCP(sport=80) /
    http.HTTP() /
    http.HTTPResponse(
        Http_Version=b"HTTP/1.1",
        Status_Code=b"200",
        Reason_Phrase=b"OK",
        Content_Type=b"text/html",
        Connection=b"close"
    )
)


### TEST FUNCTIONS ###

def test_http_get() -> None:
    """
    Test the constructor with an HTTP GET request.
    """
    http = HTTP(pkt_http_get)
    assert http.protocol_name == "HTTP"
    assert not HTTP.is_response(pkt_http_get)
    assert not http.response
    assert http.method == "GET"
    assert http.path == "/test/stuff"

    http = dict(http)
    assert isinstance(http, dict)
    assert not http["response"]
    assert http["method"] == "GET"
    assert http["path"] == "/test/stuff"


def test_http_post() -> None:
    """
    Test the constructor with an HTTP POST request.
    """
    http = HTTP(pkt_http_post)
    assert http.protocol_name == "HTTP"
    assert not HTTP.is_response(pkt_http_post)
    assert not http.response
    assert http.method == "POST"
    assert http.path == "/test/stuff"

    http = dict(http)
    assert isinstance(http, dict)
    assert not http["response"]
    assert http["method"] == "POST"
    assert http["path"] == "/test/stuff"


def test_http_resp() -> None:
    """
    Test the constructor with an HTTP response.
    """
    http = HTTP(pkt_http_resp)
    assert http.protocol_name == "HTTP"
    assert HTTP.is_response(pkt_http_resp)
    assert http.response
    assert http.method is None
    assert http.path is None

    http = dict(http)
    assert isinstance(http, dict)
    assert http["response"]
    assert http["method"] is None
    assert http["path"] is None
