## Imports
# Package
from signature_extraction.classes import Packet
import signature_extraction.pkt_extraction as pkt_extraction


### Variables
pcap_file = "demo/1724059939.pcap"


def test_pcap_to_pkts():
    """
    Test the function `pcap_to_pkts`.
    """
    # Variables
    pcap_file = "demo/1724059939.pcap"

    # Execution
    pkts = pkt_extraction.pcap_to_pkts(pcap_file)

    # Validation
    assert all([type(pkt) == Packet for pkt in pkts])


def test_pkts_to_df():
    """
    Test the function `pkts_to_df`.
    """
    # Execution
    pkts = pkt_extraction.pcap_to_pkts(pcap_file)
    df = pkt_extraction.pkts_to_df(pkts)

    # Validation
    assert df.shape[0] == len(pkts)


def test_pcap_to_csv():
    """
    Test the function `pcap_to_csv`.
    """
    # Variables
    output_file = "demo/pkts.csv"

    # Execution
    pkt_extraction.pcap_to_csv(pcap_file, output_file)

    # Validation
    pass
