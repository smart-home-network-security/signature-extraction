#!/usr/bin/python3

### Imports
# Libraries
import os
from pathlib import Path
import argparse
from ipaddress import IPv4Address
import scapy.all as scapy
# Custom
from arg_types import file, directory
from packet_utils import is_signalling_pkt
from signature_extraction.utils.domain_extraction import extract_domain_names
from pkt_fingerprint_extractor_old import extract_pkt_fingerprint, PacketFields
from signature_extractor_old import extract_signature, generate_policies, write_profile
from stream_identifier import (
    transform_to_dataframe,
    merge_pkt_fingerprints,
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
timestamp        = 0
pkt_id           = 0
previous_time    = 0
domain_names     = {}
pkt_fingerprints = []  # Simpler representations of packets
flows            = []  # Network flows (sequences of packets)


### FUNCTIONS ###

def handle_packet(packet: scapy.Packet) -> None:
    """
    Callback function which handle one packet read from a PCAP file.

    Args:
        packet (scapy.Packet): Packet read from the PCAP file.
    """
    ### Preliminary checks
    global timestamp, pkt_id, previous_time, domain_names, pkt_fingerprints

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


    ### Packet fingerprint extraction
    
    # Extract packet fingerprint
    pkt_fingerprint = extract_pkt_fingerprint(packet)
    pkt_fingerprint[PacketFields.Index.name] = pkt_id

    # Replace IP addresses with domain names
    pkt_fingerprints.append(pkt_fingerprint)

    # Update loop variables
    previous_time = packet.time
    pkt_id += 1



### MAIN ###

if __name__ == "__main__":
    
    ##### ARGUMENT PARSING #####
    parser = argparse.ArgumentParser(
        prog=script_name,
        description="Extract event signatures from PCAP files.",
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
        scapy.sniff(offline=pcap, prn=handle_packet, store=False)


        # -------------------- Simplification and flow compression ------------------- #
            
        # Transform all packet fingerprints to a data frame
        pkt_fingerprints = merge_pkt_fingerprints(
            [transform_to_dataframe(pkt_fingerprint) for pkt_fingerprint in pkt_fingerprints]
        )
        # Group the fingerprints by stream
        pkt_fingerprints = group_by_stream(pkt_fingerprints)
        # Compress the packets in the stream
        pkt_fingerprints = compress_packets(pkt_fingerprints)

        flows.append(pkt_fingerprints)

        # Write the packet fingerprints to a CSV file
        output_fingerprint_file = os.path.join(args.output, f"{timestamp}.csv")
        write_to_csv(pkt_fingerprints, output_fingerprint_file)

        # Reset accumulators
        pkt_id = 0
        previous_time = 0
        domain_names = {}
        pkt_fingerprints = []

        #print("Flows extracted")


    # ---------------------------- Pattern extraction ---------------------------- #

    # Extract event signature from the flows
    signature = extract_signature(flows)

    print(f"Signature composed of {len(signature)} packet flows found\n")

    # for i, flow in enumerate(signature):
    #     print(f"Flow {i+1}:")
    #     print(f"{str(flow)}\n")

    # Write the signature to a file
    signature_output_file = os.path.join(args.output, "signature.txt")
    with open(signature_output_file, "w") as file:
        for i, fingerprint in enumerate(signature):
            file.write(f"Flow {i+1}:\n")
            file.write(str(fingerprint))
            file.write("\n\n")
            

    # Generate policies from the signature
    policies = generate_policies(args.ipv4, signature)

    # Generate device profile from the policies
    output_profile_file = os.path.join(args.output, "profile.yaml")
    write_profile(args.device, args.ipv4, policies, output_profile_file)

    #print("Policies generated")
