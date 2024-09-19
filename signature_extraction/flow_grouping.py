## Imports
# Libraries
from typing import List
import pandas as pd
# Package
from .network import Packet, Flow, NetworkPattern
from .pkt_extraction import pkts_to_df


def group_pkts_per_flow(pkts: List[Packet]) -> NetworkPattern:
    """
    Group packets per flow, along the following attributes:
        - IP addresses
        - Transport protocol
        - Ports
    Grouping is bidirectional, i.e., (src, dst) and (dst, src) are considered the same flow.

    Args:
        pkts (List[Packet]): List of packets.
    Returns:
        NetworkPattern: pattern composed of the list of Flows.
    """
    # Initialize resulting list of flow fingerprints
    flows = []

    # Convert packets to DataFrame for easy grouping
    df = pkts_to_df(pkts)

    # Group packets per flow
    df["flow"] = df.apply(
        lambda row: tuple(
            sorted(
                [
                    (row["src"], row["sport"], row["transport_protocol"]),
                    (row["dst"], row["dport"], row["transport_protocol"])
                ]
            )
        ),
        axis="columns",
    )
    grouped = df.groupby("flow")

    # Extract flow fingerprints
    for key, _ in grouped:
        group = grouped.get_group(key)
        pkts = group.to_dict(orient="records")
        flow = Flow(pkts)
        flows.append(flow)
    
    return NetworkPattern(flows)


def pkts_csv_to_pattern_csv(pkts_file: str, pattern_file: str) -> None:
    """
    Read a CSV file containing packet fingerprints,
    group packets per flow,
    and save the resulting flow fingerprints to a CSV file.

    Args:
        pkts_file (str): CSV file containing packet fingerprints.
        flows_file (str): Output CSV file containing flow fingerprints.
    """
    # Read packet fingerprints
    pkts_df = pd.read_csv(pkts_file)
    pkts = [Packet(dict(row)) for _, row in pkts_df.iterrows()]
    # Convert packet fingerprints to flow fingerprints
    pattern = group_pkts_per_flow(pkts)
    # Save flow fingerprints to CSV
    pattern.to_csv(pattern_file)
