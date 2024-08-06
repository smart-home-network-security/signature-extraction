#!/usr/bin/python3

from domain_extractor import extract_domain_names, replace_ip_with_domain_name
from packet_translator import translate
from pattern_detection import find_patterns, generate_policies, write_profile

# from arg_types import PathType
import scapy.all as scapy
from stream_identificator import (
    transform_to_dataframe,
    merge_signatures,
    group_by_stream,
    compress_packets,
    write_to_csv,
)
import argparse
from arg_types import directory

timestamps = []


if __name__ == "__main__":
    # parse the arguments
    parser = argparse.ArgumentParser(
        prog="Signature Extractor",
        description="Extract signatures from a pcap file.",
        epilog="Enjoy the program! :)",
    )
    parser.add_argument(
        "folder",
        type=directory,
        help="The folder containing the pcap file and the act.txt file.",
    )
    args = parser.parse_args()
    folder = str(args.folder) + "/"

    # read the timestamps from the act.txt file
    with open(folder + "act.txt") as file:
        timestamps = [line.rstrip() for line in file]

    # read the packets from the file.pcap file
    packets = scapy.rdpcap(folder + "file.pcap")

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
        signatures = compress_packets(signatures)

        flows.append(signatures)

        # write the signatures to a CSV file
        write_to_csv(signatures, folder + f"{timestamp}.csv")

    print("Flows extracted")

    # ---------------------------- pattern extraction ---------------------------- #

    patterns = find_patterns(flows)  # find the patterns in the flows
    
    print(f"{len(patterns)} pattern(s) found")
    
    for i, pattern in enumerate(patterns):
        print(f"Pattern {i+1}: {pattern}\n")

    policies = generate_policies(patterns)  # generate the policy from the patterns

    policies = write_profile(policies, folder)

    print("Policies generated")

    exit(0)
