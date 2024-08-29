#!/usr/bin/python3

import pandas as pd
import argparse


def transform_to_dataframe(pkt_repr: dict) -> pd.DataFrame:
    """
    Transform the given packet representation into a DataFrame.
    Use the packet_fields as columns.
    """
    return pd.DataFrame(pkt_repr, index=[0])


def merge_pkt_reprs(pkt_reprs: list) -> pd.DataFrame:
    """
    Merge all packet representations into a single DataFrame.
    """
    return pd.concat(pkt_reprs, ignore_index=True)


def group_by_stream(df: pd.DataFrame) -> pd.DataFrame:
    """
    Group the packets by stream.

    Args:
        df (pandas.DataFrame): the packets

    Returns:
        pandas.DataFrame: the grouped packets
    """
    # Create a new column that contains a tuple of the source and destination IP addresses and ports
    df["stream"] = df.apply(
        lambda row: tuple(
            sorted(
                [
                    (row["DeviceHost"], row["DevicePort"]),
                    (row["OtherHost"], row["OtherPort"]),
                ]
            )
        ),
        axis=1,
    )

    # Group the packets by the stream column
    grouped = df.groupby("stream")

    return grouped


def compress_packets(grouped: pd.DataFrame) -> pd.DataFrame:
    """Compress the packets in each stream.

    Args:
        grouped (pandas.DataFrame): the grouped packets

    Returns:
        pandas.DataFrame: the compressed packets
    """

    # Initialize an empty list to store the compressed packets
    compressed_packets = []

    # Iterate over the groups
    for _, group in grouped:
        # Calculate the total length of the packets in the group
        total_length = group["Length"].sum()

        # Add a new row to the list of compressed packets
        compressed_packets.append(
            {
                "Index": group["Index"].min(),
                "Timestamp": group["Timestamp"].min(),
                "DeviceHost": group["DeviceHost"].iloc[0],
                "DevicePort": group["DevicePort"].iloc[0],
                "OtherHost": group["OtherHost"].iloc[0],
                "OtherPort": group["OtherPort"].iloc[0],
                "TransportProtocol": group["TransportProtocol"].iloc[0],
                "Protocol": group["Protocol"].iloc[0],
                "Length": total_length,
                "ApplicationSpecific": group["ApplicationSpecific"].iloc[0],
                "nbPacket": len(group),
            }
        )

    # Convert the list of compressed packets into a DataFrame
    compressed_df = pd.DataFrame(compressed_packets).sort_values("Index").reset_index(drop=True)

    return compressed_df


def write_to_csv(df: pd.DataFrame, filename: str) -> None:
    """Write the DataFrame to a CSV file.

    Args:
        df (DataFrame): the DataFrame to write
        filename (str): the name of the CSV file
    """
    df.to_csv(filename, index=False)


if __name__ == "__main__":
    ## COMMAND LINE ARGUMENTS ##
    parser = argparse.ArgumentParser(
        prog="Stream Identifier",
        description="Extract the network pattern relative to a specific event.",
    )
    # Positional argument: Network trace to search the pattern in
    parser.add_argument("csv", type=str, help="CSV file you want me to identify stream")

    # Parse arguments
    args = parser.parse_args()
    # Load the CSV file into a DataFrame
    df = pd.read_csv(args.csv)

    grouped = group_by_stream(df)  # Group the packets by stream
    compressed_df = compress_packets(grouped)  # Compress the packets in each stream
    compressed_df.to_csv(
        args.csv, index=False
    )  # Save the compressed packets to a new CSV file
