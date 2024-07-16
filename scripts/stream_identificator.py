#!/usr/bin/python3

import pandas as pd
import os
import argparse

if __name__ == "__main__":
    ## COMMAND LINE ARGUMENTS ##
    parser = argparse.ArgumentParser(
        prog="Stream Identificator",
        description="Extract the network pattern relative to a specific event.",
    )
    # Positional argument: Network trace to search the pattern in
    parser.add_argument("csv", type=str, help="CSV file you want me to identify stream")

    # Parse arguments
    args = parser.parse_args()
    # Load the CSV file into a DataFrame
    df = pd.read_csv(args.csv)

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

    # Initialize an empty list to store the compressed packets
    compressed_packets = []

    # Iterate over the groups
    for name, group in grouped:
        # Calculate the total length of the packets in the group
        total_length = group["Length"].sum()

        # Add a new row to the list of compressed packets
        compressed_packets.append(
            {
                "Index": group["Index"].min(),
                "Timestamp": group["Timestamp"].min(),
                "DeviceHost": group["DeviceHost"].iloc[0],
                "OtherHost": group["OtherHost"].iloc[0],
                "DevicePort": group["DevicePort"].iloc[0],
                "OtherPort": group["OtherPort"].iloc[0],
                "TransportProtocol": group["TransportProtocol"].iloc[0],
                "Protocol": group["Protocol"].iloc[0],
                "Direction": group["Direction"].iloc[0],
                "Length": total_length,
                "ApplicationSpecific": group["ApplicationSpecific"].iloc[0],
                "nbPacket": len(group),
            }
        )

    # Convert the list of compressed packets into a DataFrame
    compressed_df = pd.DataFrame(compressed_packets).sort_values("Index")

    # Save the compressed DataFrame to a new CSV file
    compressed_df.to_csv(args.csv, index=False)
