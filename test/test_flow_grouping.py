## Imports
# Libraries
import os
# Package
import signature_extraction.pkt_fingerprint_extractor as pkt_fingerprint_extractor
import signature_extraction.flow_grouping as flow_grouping


def test_group_pkts_per_flow():
    """
    Test the function `group_pkts_per_flow`.
    """
    # Variables
    pcap_file = "demo/1724059939.pcap"
    pkts = pkt_fingerprint_extractor.pcap_to_pkts(pcap_file)

    # Execution
    flows = flow_grouping.group_pkts_per_flow(pkts)

    # Validation
    assert all([type(flow) == flow_grouping.FlowFingerprint for flow in flows])


def test_pkts_csv_to_flows_csv(tmp_path):
    """
    Test the functions `pkts_csv_to_flows_csv`.
    """
    # Variables
    pcap_file = "demo/1724059939.pcap"
    pkts_csv_path = os.path.join(tmp_path, "pkts.csv")
    pkt_fingerprint_extractor.pcaps_to_csv(pcap_file, pkts_csv_path)
    flows_csv_path = os.path.join(tmp_path, "flows.csv")

    # Execution
    flow_grouping.pkts_csv_to_flows_csv(pkts_csv_path, flows_csv_path)

    # Validation
    assert os.path.exists(flows_csv_path)
