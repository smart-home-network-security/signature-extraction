## Imports
# Libraries
from typing import List
import pandas as pd
# Package
from .classes import PacketFingerprint, FlowFingerprint
from .pkt_fingerprint_extractor import pkts_to_df


def group_pkts_per_flow(pkts: List[PacketFingerprint]) -> List[FlowFingerprint]:
    """
    Group packets per flow, along the following attributes:
        - IP addresses
        - Transport protocol
        - Ports
    Grouping is bidirectional, i.e., (src, dst) and (dst, src) are considered the same flow.

    Args:
        pkts (List[PacketFingerprint]): List of packet fingerprints.
    Returns:
        List[FlowFingerprint]: List of flow fingerprints.
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
        flow = FlowFingerprint(pkts)
        flows.append(flow)
    
    return flows


def flows_to_df(flows: List[FlowFingerprint]) -> pd.DataFrame:
    """
    Convert a list of FlowFingerprint objects to a DataFrame.

    Args:
        flows (List[FlowFingerprint]): List of flow fingerprints.
    Returns:
        pd.DataFrame: DataFrame containing the flow fingerprints.
    """
    return pd.DataFrame([dict(flow) for flow in flows])


def flows_to_csv(flows: List[FlowFingerprint], output_file: str) -> None:
    """
    Save a list of flow fingerprints to a CSV file.

    Args:
        flows (List[FlowFingerprint]): List of flow fingerprints.
        output_file (str): Output file.
    """
    df = flows_to_df(flows)
    df.to_csv(output_file, index=False)


def pkts_csv_to_flows_csv(pkts_file: str, flows_file: str) -> None:
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
    pkts = [PacketFingerprint(dict(row)) for _, row in pkts_df.iterrows()]
    # Convert packet fingerprints to flow fingerprints
    flows = group_pkts_per_flow(pkts)
    # Save flow fingerprints to CSV
    flows_to_csv(flows, flows_file)
