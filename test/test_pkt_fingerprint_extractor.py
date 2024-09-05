## Import
# Libraries
import pytest
# Package
import signature_extraction.pkt_fingerprint_extractor as pkt_fingerprint_extractor


def test_pcap_to_pkts():
    """
    Test the function `pcap_to_pkts`.
    """
    # Variables
    pcap_file = "demo/1724059939.pcap"

    # Execution
    pkts = pkt_fingerprint_extractor.pcap_to_pkts(pcap_file)

    # Validation
    assert all([type(pkt) == pkt_fingerprint_extractor.PacketFingerprint for pkt in pkts])


def test_pcaps_to_pkts():
    """
    Test the function `pcaps_to_pkts`.
    """
    # Variables
    pcap_files = [
        "demo/1724059939.pcap",
        "demo/1724060053.pcap",
        "demo/1724060140.pcap"
    ]

    # Execution
    pkts = pkt_fingerprint_extractor.pcaps_to_pkts(pcap_files)

    # Validation
    assert all([type(pkt) == pkt_fingerprint_extractor.PacketFingerprint for pkt in pkts])


def test_pcaps_to_csv():
    """
    Test the function `pcaps_to_csv`.
    """
    # Variables
    pcap_files = [
        "demo/1724059939.pcap",
        "demo/1724060053.pcap",
        "demo/1724060140.pcap"
    ]
    output_file = "demo/pkts.csv"

    # Execution
    pkt_fingerprint_extractor.pcaps_to_csv(pcap_files, output_file)

    # Validation
    pass
