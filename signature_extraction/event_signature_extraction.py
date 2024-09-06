from typing import List, Union
import pandas as pd
from .classes import FlowFingerprint, NetworkPattern
from .pkt_extraction import pcap_to_pkts
from .flow_grouping import group_pkts_per_flow


def pcaps_to_event(pcap_files: Union[str, List[str]]) -> NetworkPattern:
    """
    Extract an event signature from a list of flow fingerprints.

    Args:
        flows (List[FlowFingerprint]): List of flow fingerprints.
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
        flows = group_pkts_per_flow(pkts)
        pattern = NetworkPattern(flows)
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

        already_parsed_flow_indices.add(i)

        # Iterate over NetworkPatterns (i.e., lists of FlowFingerprints),
        # to find flows matching the one currently being processed
        for j, pattern in enumerate(patterns):
            matched_flow = pattern.match_flow_basic(flow)
            if j == 0:  # Reference record
                #index = matched_record.index[0]
                #already_parsed_flow_indices.add(index)
                pass
            result_pattern.
            result = pd.concat([result, matched_record])

        for record in result.iterrows():
            fingerprint.addPorts(record[1])

        for already_matched_port in already_matched_ports:
            if already_matched_port in list(fingerprint.ports):
                fingerprint.ports.pop(already_matched_port)

        base_port = fingerprint.get_fixed_port()[0]
        already_matched_ports.add(base_port)

        result = result[
            (result["DevicePort"] == base_port) | (result["OtherPort"] == base_port)
        ]

        fingerprint.clearPorts()

        for frame in result.iterrows():
            fingerprint.addPorts(frame[1])
            fingerprint.getApplicationData(frame[1], "Length")
            fingerprint.getApplicationData(frame[1], "ApplicationSpecific")
            fingerprint.getApplicationData(frame[1], "nbPacket")

        result_flows.append(fingerprint)

    return signature
