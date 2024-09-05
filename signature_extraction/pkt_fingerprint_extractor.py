## Imports
# Libraries
from typing import List
from scapy.all import Packet, sniff
import pandas as pd
# Package
from .utils.packet_utils import is_signalling_pkt
from .classes import PacketFingerprint


### Variables
# Config variables
timeout = 5  # seconds
# Packet loop accumulators
i = 0
timestamp        = 0
previous_time    = 0
domain_names     = {}
pkts = []  # Simpler representations of packets


def handle_packet(packet: Packet) -> None:
    global i, timestamp, previous_time, domain_names, pkts

    ## Packet validation

    # If timestamp is not set, set it with the first packet
    if i == 0 and timestamp == 0:
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
    

    ## Packet fingerprint extraction
    pkt_fingerprint = PacketFingerprint(packet)
    pkts.append(pkt_fingerprint)

    # Update loop variables
    previous_time = packet.time


def pcap_to_pkts(pcap_file: str) -> List[Packet]:
    """
    Convert a PCAP file to a list of packets.

    Args:
        pcap_file (str): PCAP file.
    Returns:
        List[Packet]: List of packet fingerprints.
    """
    global pkts
    sniff(offline=pcap_file, prn=handle_packet, store=False)
    return pkts


def pcaps_to_pkts(pcap_files: List[str]) -> List[Packet]:
    """
    Convert multiple PCAP files to a list of packets.

    Args:
        pcap_files (List[str]): List of PCAP files.
    Returns:
        List[Packet]: List of packet fingerprints.
    """
    global pkts
    for pcap in pcap_files:
        pcap_to_pkts(pcap)
    return pkts


def pkts_to_df(pkts: List[Packet]) -> pd.DataFrame:
    """
    Convert a list of packets to a DataFrame.

    Args:
        pkts (List[Packet]): List of packet fingerprints.
    Returns:
        pd.DataFrame: DataFrame of packet fingerprints.
    """
    return pd.DataFrame([dict(pkt) for pkt in pkts])


def save_pkts_to_csv(pkts: List[Packet], output_file: str) -> None:
    """
    Save a list of packets to a CSV file.

    Args:
        pkts (List[Packet]): List of packet fingerprints.
        output_file (str): Output file.
    """
    df = pkts_to_df(pkts)
    df.to_csv(output_file, index=False)


def pcaps_to_csv(pcap_files: List[str], output_file: str) -> None:
    """
    Convert multiple PCAP files to a list of PacketSignatures,
    and save it to a CSV file.

    Args:
        pcap_files (List[str]): List of PCAP files.
        output_file (str): Output file.
    """
    pkts = pcaps_to_pkts(pcap_files)
    save_pkts_to_csv(pkts, output_file)
