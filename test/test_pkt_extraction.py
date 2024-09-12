## Imports
# Libraries
import os
from pathlib import Path
# Package
from signature_extraction.network import Packet
import signature_extraction.pkt_extraction as pkt_extraction


### VARIABLES ###
self_path = os.path.abspath(__file__)
self_dir = os.path.dirname(self_path)
pcap_file_path = os.path.join(self_dir, "traces", "1724059939.pcap")


### TEST FUNCTIONS ###

def test_pcap_to_pkts():
    """
    Test the function `pcap_to_pkts`.
    """
    # Execution
    pkts = pkt_extraction.pcap_to_pkts(pcap_file_path)

    # Validation
    assert all([isinstance(pkt, Packet) for pkt in pkts])


def test_pkts_to_df():
    """
    Test the function `pkts_to_df`.
    """
    # Execution
    pkts = pkt_extraction.pcap_to_pkts(pcap_file_path)
    df = pkt_extraction.pkts_to_df(pkts)

    # Validation
    assert df.shape[0] == len(pkts)


def test_pcap_to_csv(tmp_path: Path) -> None:
    """
    Test the function `pcap_to_csv`.

    Args:
        tmp_path (Path): Path to the temporary directory.
    """
    # Variables
    output_file = os.path.join(tmp_path, "pkts.csv")

    # Execution
    pkt_extraction.pcap_to_csv(pcap_file_path, output_file)

    # Validation
    assert os.path.isfile(output_file)
