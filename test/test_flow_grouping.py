## Imports
# Libraries
import os
from pathlib import Path
# Package
import signature_extraction.pkt_extraction as pkt_extraction
import signature_extraction.flow_grouping as flow_grouping


### VARIABLES ###

self_path = os.path.abspath(__file__)
self_dir = os.path.dirname(self_path)
pcap_file_path = os.path.join(self_dir, "traces", "1724059939.pcap")


### TEST FUNCTIONS ###

def test_group_pkts_per_flow() -> None:
    """
    Test the function `group_pkts_per_flow`.
    """
    # Variables
    pkts = pkt_extraction.pcap_to_pkts(pcap_file_path)

    # Execution
    pattern = flow_grouping.group_pkts_per_flow(pkts)

    # Validation
    assert len(pattern.flows) > 0


def test_pkts_csv_to_flows_csv(tmp_path: Path) -> None:
    """
    Test the functions `pkts_csv_to_flows_csv`.

    Args:
        tmp_path (Path): Path to the temporary directory.
    """
    # Variables
    pkts_csv_path = os.path.join(tmp_path, "pkts.csv")
    pkt_extraction.pcap_to_csv(pcap_file_path, pkts_csv_path)
    pattern_csv_path = os.path.join(tmp_path, "pattern.csv")

    # Execution
    flow_grouping.pkts_csv_to_pattern_csv(pkts_csv_path, pattern_csv_path)

    # Validation
    assert os.path.isfile(pattern_csv_path)
