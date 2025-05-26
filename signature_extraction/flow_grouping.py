## Imports
# Libraries
from typing import List
import pandas as pd
# Package
from .network import Packet, FlowFingerprint, NetworkPattern
from .pkt_extraction import pkts_to_df


def group_pkts_per_flow(pkts: List[Packet], match_random_ports: bool = False) -> NetworkPattern:
    """
    Group packets per flow, along the following attributes:
        - IP addresses
        - Transport protocol
        - Ports
    Grouping is bidirectional, i.e., (src, dst) and (dst, src) are considered the same flow.

    Args:
        pkts (List[Packet]): List of packets.
        match_random_ports (bool): Whether to consider random ports in flow matching.
                                   Optional, default is False.
    Returns:
        NetworkPattern: pattern composed of the list of Flows.
    """
    # If no packet, return empty NetworkPattern object
    if len(pkts) < 1:
        return NetworkPattern()

    # Initialize resulting list of flow fingerprints
    list_flows: List[FlowFingerprint] = []

    # Convert packets to DataFrame for easy grouping
    df = pkts_to_df(pkts)

    # Group packets per flow
    df["flow"] = df.apply(
        lambda row: tuple(
            sorted(
                [
                    (row["src"], row["sport"]),
                    (row["dst"], row["dport"])
                ]
            ) + [row["transport_protocol"], row["application_layer"]]
        ),
        axis="columns",
    )
    grouped = df.groupby("flow", sort=False)

    # Extract flows
    for key, _ in grouped:
        group = grouped.get_group(key)
        pkts = group.to_dict(orient="records")
        new_flow = FlowFingerprint(pkts)
        
        # Check if an equivalent flow is already in the list
        found_matching_flow = False
        for flow in list_flows:
            if flow.match_flow(new_flow, match_random_ports):
                flow.add_flow(new_flow)
                found_matching_flow = True

        if not found_matching_flow:
            list_flows.append(new_flow)
    
    return NetworkPattern(list_flows)


def pkts_csv_to_pattern_csv(pkts_file: str, pattern_file: str, match_random_ports: bool = False) -> None:
    """
    Read a CSV file containing packet fingerprints,
    group packets per flow,
    and save the resulting flow fingerprints to a CSV file.

    Args:
        pkts_file (str): CSV file containing packet fingerprints.
        flows_file (str): Output CSV file containing flow fingerprints.
        match_random_ports (bool): Whether to consider random ports in flow matching.
                                   Optional, default is False.
    """
    # Read packet fingerprints
    df_pkts = pd.read_csv(pkts_file)
    df_pkts.where(df_pkts.notnull(), None, inplace=True)  # Replace NaN with None
    pkts = [Packet(dict(row)) for _, row in df_pkts.iterrows()]
    # Convert packet fingerprints to flow fingerprints
    pattern = group_pkts_per_flow(pkts, match_random_ports)
    # Save flow fingerprints to CSV
    pattern.to_csv(pattern_file)
