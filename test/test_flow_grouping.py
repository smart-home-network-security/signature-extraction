## Imports
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
