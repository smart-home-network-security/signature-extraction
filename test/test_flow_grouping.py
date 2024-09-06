## Imports
# Libraries
import os
# Package
from signature_extraction.network import Flow
import signature_extraction.pkt_extraction as pkt_extraction
import signature_extraction.flow_grouping as flow_grouping


def test_group_pkts_per_flow():
    """
    Test the function `group_pkts_per_flow`.
    """
    # Variables
    pcap_file = "demo/1724059939.pcap"
    pkts = pkt_extraction.pcap_to_pkts(pcap_file)

    # Execution
    pattern = flow_grouping.group_pkts_per_flow(pkts)

    # Validation
    pass


def test_pkts_csv_to_flows_csv(tmp_path):
    """
    Test the functions `pkts_csv_to_flows_csv`.
    """
    # Variables
    pcap_file = "demo/1724059939.pcap"
    pkts_csv_path = os.path.join(tmp_path, "pkts.csv")
    pkt_extraction.pcap_to_csv(pcap_file, pkts_csv_path)
    pattern_csv_path = os.path.join(tmp_path, "pattern.csv")

    # Execution
    flow_grouping.pkts_csv_to_pattern_csv(pkts_csv_path, pattern_csv_path)

    # Validation
    assert os.path.exists(pattern_csv_path)
