## Imports
# Libraries
from typing import List, Union
# Package
from .network import FlowFingerprint, NetworkPattern
from .pkt_extraction import pcap_to_pkts
from .flow_grouping import group_pkts_per_flow


def patterns_to_signature(patterns: List[NetworkPattern]) -> NetworkPattern:
    """
    Extract an event signature from a list of NetworkPatterns.

    Args:
        patterns (List[NetworkPattern]): List of NetworkPatterns.
    Returns:
        NetworkPattern: Event signature extracted from the flows.
    Raises:
        ValueError: If no valid NetworkPatterns are provided.
    """
    patterns_filtered = [p for p in patterns if p and len(p) > 0]
    if len(patterns_filtered) == 0:
        raise ValueError("No valid NetworkPatterns provided.")

    patterns_sorted = sorted(patterns_filtered, key=len)
    reference_pattern = patterns_sorted[0]
    already_parsed_reference_flow_indices = set()
    signature = NetworkPattern()

    # Iterate over flows in the reference pattern
    for i, reference_flow in enumerate(reference_pattern.get_flows()):

        # Flow already parsed, skip
        if i in already_parsed_reference_flow_indices:
            continue


        ## Parse flow
        potential_flow = FlowFingerprint.build_from_flow(reference_flow)
        already_parsed_reference_flow_indices.add(i)

        # Iterate over NetworkPatterns (i.e., lists of FlowFingerprints),
        # to find flows matching the one currently being processed
        skip = False  # Skip current reference flow if True
        for j, pattern in enumerate(patterns_sorted):
            try:
                index, matched_flow = pattern.find_matching_flow(potential_flow)
            except ValueError:
                # No matching flow found for the current reference flow
                # ==> Reference flow is not part of signature
                # ==> Skip it
                skip = True
                break
            else:
                # Matching flow found
                if j == 0:  # Reference record
                    if index in already_parsed_reference_flow_indices:
                        # Already parsed, skip
                        continue
                    already_parsed_reference_flow_indices.add(index)
                # Add matching flow to the current potential flow
                potential_flow.add_flow(matched_flow)

        if skip:
            continue

        signature.add_flow(potential_flow)

    return signature


def pcaps_to_signature_pattern(pcap_files: Union[str, List[str]], timeout: int = 5) -> NetworkPattern:
    """
    Extract an event signature from a list of network traces.

    Args:
        pcap_files (Union[str, List[str]]): Path to the PCAP file(s).
        timeout (int): Iteration is stopped if current packet's timestamp exceeds the previous one by this value [seconds].
                       Optional, default is 5 seconds.
    Returns:
        NetworkPattern: Event signature extracted from the flows.
    """
    # Convert input PCAP file(s) to list if necessary
    if isinstance(pcap_files, str):
        pcap_files = [pcap_files]

    # Extract flows from PCAP files
    patterns = []
    for pcap in pcap_files:
        pkts = pcap_to_pkts(pcap, timeout)
        if len(pkts) > 0:
            pattern = group_pkts_per_flow(pkts)
            patterns.append(pattern)

    # Extract event signature from the flows
    return patterns_to_signature(patterns)


def pcaps_to_signature_csv(pcap_files: Union[str, List[str]], output_file: str) -> None:
    """
    Extract an event signature from a list of network traces,
    and save it to a CSV file.

    Args:
        pcap_files (Union[str, List[str]]): Path to the PCAP file(s).
        output_file (str): Output CSV file.
    """
    # Extract event signature from the flows
    signature = pcaps_to_signature_pattern(pcap_files)

    # Save event signature to CSV
    signature.to_csv(output_file)
