#!/usr/bin/python3

import os
from pathlib import Path
import argparse
import csv
from constants import flow_timeout
from arg_types import timestamp
from packet_utils import is_signalling_pkt
from domain_extractor import extract_domain_names, replace_ip_with_domain_name
from signature_extractor import (
    extract_signature,
    PacketFields,
    packet_fields,
)
import scapy.all as scapy


def simplify_pkt(packet: scapy.Packet, timeout: int, previous_time: int) -> None:
    # Skip packet if it is a signalling packet (e.g., TCP SYN)
    if is_signalling_pkt(packet):
        return
    
    # Stop iteration if timeout exceeded w.r.t. previous packet
    if packet.time > previous_time + timeout:
        return
    
    # Extract packet signature
    signature = extract_signature(packet)
    return signature


def write(file, signatures, packet_fields) -> None:
    csv_rows = [signature for signature in signatures]
    with open(file, "w") as f:
        writer = csv.DictWriter(f, fieldnames=packet_fields)
        writer.writeheader()
        writer.writerows(csv_rows)

    return


if __name__ == "__main__":
    ## COMMAND LINE ARGUMENTS ##
    parser = argparse.ArgumentParser(
        prog="packet_translator.py",
        description='Translate `.pcap` file into "simplified" CSV packet format',
        epilog="See https://github.com/smart-home-network-security/iot-dynamic-fingerprinting for more details",
    )
    # Positional argument: Network trace to search the pattern in
    parser.add_argument(
        "pcap",
        type=str,
        help="network trace to extract packets in",
    )
    # Optional argument: Timestamp to start searching from
    parser.add_argument(
        "-t",
        "--time",
        type=timestamp,
        default=0,
        help="timestamp to start extracting packet from",
    )

    parser.add_argument(
        "-w",
        "--window",
        type=int,
        default=flow_timeout,
        help="window time to extract after timestamp",
    )

    # Parse arguments
    args = parser.parse_args()

    # Get PCAP trace's parent directory
    pcap_dir = Path(os.path.abspath(args.pcap)).parents[0]

    flow_timeout = args.window

    # Get domain names from the given PCAP trace

    packets = scapy.rdpcap(args.pcap)

    domain_names = extract_domain_names(packets)

    # Initialize CSV result file
    signature_file_path = os.path.join(pcap_dir, "signature.csv")

    signatures = simplify_pkt(flow_timeout, args.time, packets)
    for signature in signatures:
        replace_ip_with_domain_name(domain_names, signature)
    write(signature_file_path, signatures, packet_fields)

    print(f"Result file written to {signature_file_path}")
