#!/usr/bin/python3

### Imports
# Libraries
import os
from pathlib import Path
import argparse
from ipaddress import IPv4Address
from scapy.all import Packet, sniff
# Custom
from arg_types import file, directory
from packet_utils import is_signalling_pkt
from domain_extractor import extract_domain_names, replace_ip_with_domain_name
from signature_extractor import extract_signature, PacketFields
from pattern_detection import find_patterns, generate_policies, write_profile
from stream_identifier import (
    transform_to_dataframe,
    merge_signatures,
    group_by_stream,
    compress_packets,
    write_to_csv,
)


### GLOBAL VARIABLES ###
# Paths
script_name = os.path.basename(__file__)
script_path = Path(os.path.abspath(__file__))
# Config variables
timeout = 5  # seconds
# Packet loop accumulators
timestamp     = 0
pkt_id        = 0
previous_time = 0
domain_names  = {}
signatures    = []  # Simpler representations of packets
flows         = []  


### FUNCTIONS ###

def handle_packet(packet: Packet) -> None:
    """
    Callback function which handle one packet read from a PCAP file.

    Args:
        packet (scapy.Packet): Packet read from the PCAP file.
    """
    ### Preliminary checks
    global timestamp, pkt_id, previous_time, domain_names, signatures

    # If timestamp is not set, set it with the first packet
    if pkt_id == 0 and timestamp == 0:
        timestamp = packet.time

    # If first packet, set timestamp
    if previous_time == 0:
        previous_time = packet.time

    # Skip signalling packets (e.g., TCP SYN)
    if is_signalling_pkt(packet):
        return
    
    # Stop iteration if timeout exceeded w.r.t. previous packet
    if packet.time > previous_time + timeout:
        return

    
    ### Domain name extraction
    extract_domain_names(packet, domain_names)


    ### Packet signature extraction
    
    # Extract packet signature
    signature = extract_signature(packet)
    signature[PacketFields.Index.name] = pkt_id

    # Replace IP addresses with domain names
    signature = replace_ip_with_domain_name(domain_names, signature)
    signatures.append(signature)

    # Update loop variables
    previous_time = packet.time
    pkt_id += 1



### MAIN ###

if __name__ == "__main__":
    
    ##### ARGUMENT PARSING #####
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Extract signatures from a pcap file.",
        epilog="Enjoy the program! :)"
    )

    ### Positional arguments ###

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

    # Input PCAP files
    parser.add_argument(
        "pcap",
        type=file,
        nargs="+",
        action="store",
        help="PCAP files containing the device's network traffic, split per event."
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


    ##### MAIN SCRIPT #####

    # Iterate over input PCAP files
    for pcap in args.pcap:

        # Event timestamp
        try:
            timestamp = int(os.path.basename(pcap).split(".")[0])
        except ValueError:
            timestamp = 0

        # Read packets from the PCAP file
        sniff(offline=pcap, prn=handle_packet, store=False)


        # -------------------- Simplification and flow compression ------------------- #
            
        # Transform all signatures to a data frame
        signatures = merge_signatures(
            [transform_to_dataframe(signature) for signature in signatures]
        )
        # Group the signatures by stream
        signatures = group_by_stream(signatures)
        # Compress the packets in the stream
        signatures = compress_packets(signatures)

        flows.append(signatures)

        # write the signatures to a CSV file
        output_signature_file = os.path.join(args.output, f"{timestamp}.csv")
        write_to_csv(signatures, output_signature_file)

        # Reset accumulators
        pkt_id = 0
        previous_time = 0
        domain_names = {}
        signatures = []

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
            file.write(f"Pattern {i+1}:\n")
            file.write(repr(pattern))
            file.write("\n\n")
            

    policies = generate_policies(args.ipv4, patterns)  # generate the policy from the patterns

    # Generate device profile from the policies
    output_profile_file = os.path.join(args.output, "profile.yaml")
    write_profile(args.device, args.ipv4, policies, output_profile_file)

    print("Policies generated")
