## Imports
# Libraries
from typing import Tuple
import os
from pathlib import Path
import pandas as pd
from datetime import datetime
import yaml
from ipaddress import IPv4Address
import scapy.all as scapy
from scapy.all import Packet, sniff
# Custom
from arg_types import file, directory
from packet_utils import is_signalling_pkt
from domain_extractor import extract_domain_names, replace_ip_with_domain_name
from fingerprint import Fingerprint
from pkt_fingerprint_extractor_old import extract_pkt_fingerprint, PacketFields
from stream_identifier import (
    transform_to_dataframe,
    merge_pkt_fingerprints,
    group_by_stream,
    compress_packets,
    write_to_csv,
)


### VARIABLES ###
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


def load_csv_files(path: str) -> list:
    """Load all the csv files in a directory

    Args:
        path (str): path to the directory

    Returns:
        list: list of dataframes
    """
    network_records = []
    dirs = os.listdir(path)
    for file in dirs:
        if file.endswith(".csv"):
            network_records.append(pd.read_csv(os.path.join(path, file)))
    return network_records


def extract_signature(network_records: list) -> list:
    """
    Find signatures in the network records

    :param: network_records (list): list of dataframes
    :raises Exception: No matching frame has been found
    :return: list: event signature, i.e. list of network flows
    """
    already_parsed_flows_indices = set()
    already_matched_ports = set()
    identified_flows = []
    network_recording = sorted(network_records, key=len)
    reference_record = network_recording[0]

    for i, flow in reference_record.iterrows():

        # Flow already parsed, skip
        if i in already_parsed_flows_indices:
            continue

        ## Parse flow

        result = pd.DataFrame()
        fingerprint = Fingerprint(flow)
        already_parsed_flows_indices.add(i)

        for j, record in enumerate(network_recording):
            # Find matching flow in given network record
            matched_record = fingerprint.matchBasicSignature(record)
            if j == 0:  # Reference record
                index = matched_record.index[0]
                # print(matched_record)
                # print(index)
                already_parsed_flows_indices.add(index)
            result = pd.concat([result, matched_record])

        if result.empty:
            raise Exception("No matching frame has been found")

        for record in result.iterrows():
            fingerprint.addPorts(record[1])

        for already_matched_port in already_matched_ports:
            if already_matched_port in list(fingerprint.ports):
                fingerprint.ports.pop(already_matched_port)

        base_port = fingerprint.get_fixed_port()[0]
        already_matched_ports.add(base_port)

        result = result[
            (result["DevicePort"] == base_port) | (result["OtherPort"] == base_port)
        ]

        fingerprint.clearPorts()

        for frame in result.iterrows():
            fingerprint.addPorts(frame[1])
            fingerprint.getApplicationData(frame[1], "Length")
            fingerprint.getApplicationData(frame[1], "ApplicationSpecific")
            fingerprint.getApplicationData(frame[1], "nbPacket")

        identified_flows.append(fingerprint)

    return identified_flows


def get_policy_id(policy: dict) -> str:
    """
    Generate an identifier for a given policy.

    :param: policy (dict): Policy to generate an identifier for.
    :return: str: Identifier for the given policy.
    """
    highest_protocol = list(dict.keys(policy["protocols"]))[-1]
    id = highest_protocol
    for _, value in dict.items(policy["protocols"][highest_protocol]):
        id += f"_{value}"
    return id


def generate_policies(ipv4:IPv4Address, identified_flows: list) -> dict:
    policies = {}

    for fingerprint in identified_flows:
        policy = fingerprint.extract_policy(ipv4)
        id = get_policy_id(policy)
        policies[id] = policy

    return policies


def write_profile(device_name: str, ipv4: IPv4Address, policies: dict, output: str) -> None:
    deviceinfo = {
        "name": device_name,
        "ipv4": str(ipv4),
        "last-update": datetime.today().strftime("%a %d %b %Y, %I:%M%p")
    }
    profile = {"device-info": deviceinfo, "single-policies": policies}

    with open(output, "w") as f:
        yaml.dump(profile, f)


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
    pkt_fingerprint = replace_ip_with_domain_name(domain_names, pkt_fingerprint)
    pkt_fingerprints.append(pkt_fingerprint)

    # Update loop variables
    previous_time = packet.time
    pkt_id += 1


def extract_event_signature(pcap_files: list, device: Tuple[str, str], output_dir: str = os.getcwd()) -> None:
    ## Variables
    # Global accumulators
    global timestamp, pkt_id, previous_time, domain_names, pkt_fingerprints
    # Arguments
    device_name = device[0]
    device_ipv4 = device[1]

    # Iterate over input PCAP files
    for pcap in pcap_files:

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
        output_fingerprint_file = os.path.join(output_dir, f"{timestamp}.csv")
        write_to_csv(pkt_fingerprints, output_fingerprint_file)

        # Reset accumulators
        pkt_id = 0
        previous_time = 0
        domain_names = {}
        pkt_fingerprints = []

        print("Flows extracted")


    # ---------------------------- Pattern extraction ---------------------------- #

    # Extract event signature from the flows
    signature = extract_signature(flows)

    print(f"Signature composed of {len(signature)} packet flows found\n")

    for i, flow in enumerate(signature):
        print(f"Flow {i+1}:")
        print(f"{str(flow)}\n")

    # Write the signature to a file
    signature_output_file = os.path.join(output_dir, "signature.txt")
    with open(signature_output_file, "w") as file:
        for i, fingerprint in enumerate(signature):
            file.write(f"Flow {i+1}:\n")
            file.write(str(fingerprint))
            file.write("\n\n")
            

    # Generate policies from the signature
    policies = generate_policies(device_ipv4, signature)

    # Generate device profile from the policies
    output_profile_file = os.path.join(output_dir, "profile.yaml")
    write_profile(device_name, device_ipv4, policies, output_profile_file)

    print("Policies generated")
