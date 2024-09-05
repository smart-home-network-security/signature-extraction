## Imports
# Libraries
from typing import List
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
