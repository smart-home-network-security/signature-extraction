#!/usr/bin/python3

# Libraries
import os
from pathlib import Path
from ipaddress import IPv4Address
# Custom
from domain_extractor import extract_domain_names, replace_ip_with_domain_name
from packet_translator import translate
from pattern_detection import find_patterns, generate_policies, write_profile

# from arg_types import PathType
import scapy.all as scapy
from stream_identifier import (
    transform_to_dataframe,
    merge_signatures,
    group_by_stream,
    compress_packets,
    write_to_csv,
)
import argparse
from arg_types import file, directory


### GLOBAL VARIABLES ###
script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
timestamps = []


if __name__ == "__main__":
    
    ##### ARGUMENT PARSING #####
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Extract signatures from a pcap file.",
        epilog="Enjoy the program! :)"
    )

    ### Positional arguments ###

    ## Input files
    # PCAP file
    parser.add_argument(
        "pcap",
        type=file,
        help="PCAP file containing the device's network traffic."
    )
    # Timestamps file
    parser.add_argument(
        "timestamp_file",
        type=file,
        help="File containing the timestamps of the device events."
    )

    ## Device metadata
    # Device name
    parser.add_argument(
        "device",
        type=str,
        help="Name of the device."
    )
    # Device IPv4 address
    parser.add_argument(
        "ipv4",
        type=IPv4Address,
        help="IPv4 address of the device."
    )

    ### Optional arguments ###

    # Output directory
    parser.add_argument(
        "-o",
        "--output",
        type=directory,
        default=script_path,
        help="Directory where the output files will be saved."
    )

    args = parser.parse_args()


    # read the timestamps from the act.txt file
    with open(args.timestamp_file) as file:
        timestamps = [line.rstrip() for line in file]

    # read the packets from the file.pcap file
    packets = scapy.rdpcap(args.pcap)

    # extract the domain names from the packets
    domain_names = extract_domain_names(packets)

    flows = []

    # -------------------- simplification and flow compression ------------------- #

    for timestamp in timestamps:
        # translate the packets to signatures
        signatures = translate(5, int(timestamp), packets)
        # replace the IP addresses with domain names
        signatures = [
            replace_ip_with_domain_name(domain_names, signature)
            for signature in signatures
        ]
        # transform all signatures to a data frame
        signatures = merge_signatures(
            [transform_to_dataframe(signature) for signature in signatures]
        )
        # group the signatures by stream
        signatures = group_by_stream(signatures)
        # compress the packets in the stream
        signatures = compress_packets(signatures)

        flows.append(signatures)

        # write the signatures to a CSV file
        output_signature_file = os.path.join(args.output, f"{timestamp}.csv")
        write_to_csv(signatures, output_signature_file)

    print("Flows extracted")

    # ---------------------------- pattern extraction ---------------------------- #

    patterns = find_patterns(flows)  # find the patterns in the flows

    print(f"{len(patterns)} pattern(s) found")

    for i, pattern in enumerate(patterns):
        print(f"Pattern {i+1}: {pattern}\n")

    print("Patterns found!")

    # output the patterns to a file
    patterns_output_file = os.path.join(args.output, "patterns.txt")
    with open(patterns_output_file, "w") as file:
        for i, pattern in enumerate(patterns):
            file.write("Pattern " + str(i + 1) + ":\n")
            file.write(repr(pattern))
            file.write("\n\n")
            

    policies = generate_policies(args.ipv4, patterns)  # generate the policy from the patterns

    output_profile_file = os.path.join(args.output, "profile.yaml")
    write_profile(args.device, args.ipv4, policies, output_profile_file)  # write the profile to a file

    print("Policies generated")
