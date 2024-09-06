from typing import List, Union
import pandas as pd
from .classes import FlowFingerprint, NetworkPattern
from .pkt_extraction import pcap_to_pkts
from .flow_grouping import group_pkts_per_flow


def pcaps_to_event(pcap_files: Union[str, List[str]]) -> NetworkPattern:
    """
    Extract an event signature from a list of network traces.

    Args:
        pcap_files (Union[str, List[str]]): Path to the PCAP file(s).
    Returns:
        NetworkPattern: Event signature extracted from the flows.
    """
    # Convert input PCAP file(s) to list if necessary
    if isinstance(pcap_files, str):
        pcap_files = [pcap_files]

    # Extract flows from PCAP files
    patterns = []
    for pcap in pcap_files:

        pkts = pcap_to_pkts(pcap)
        pattern = group_pkts_per_flow(pkts)
        patterns.append(pattern)


    ### Extract event signature from the flows

    already_parsed_flow_indices = set()
    already_matched_ports = set()
    signature = NetworkPattern()
    patterns.sort(key=len)
    reference_pattern = patterns[0]

    # Iterate over flows in the reference pattern
    for i, flow in enumerate(reference_pattern.get_flows()):

        # Flow already parsed, skip
        if i in already_parsed_flow_indices:
            continue


        ## Parse flow
        result_flow = FlowFingerprint(flow)
        already_parsed_flow_indices.add(i)

        # Iterate over NetworkPatterns (i.e., lists of FlowFingerprints),
        # to find flows matching the one currently being processed
        for pattern in patterns:
            matched_flow = pattern.match_flow_basic(flow)
            result_flow.add_flow(matched_flow)

        # Remove port if already matched
        for already_matched_port in already_matched_ports:
            if already_matched_port in result_flow.ports:
                del result_flow.ports[already_matched_port]

        fixed_port = result_flow.get_fixed_port()[0]
        already_matched_ports.add(fixed_port)

        signature.add_flow(result_flow)

    return signature
