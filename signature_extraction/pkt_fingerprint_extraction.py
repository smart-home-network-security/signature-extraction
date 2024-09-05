## Imports
# Libraries
from typing import List, Union
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
    pkt_fingerprint = PacketFingerprint.build_from_packet(packet)
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


def pcaps_to_pkts(pcap_files: Union[str, List[str]]) -> List[PacketFingerprint]:
    """
    Convert one or multiple PCAP file(s) to a list of PacketFingerprint objects.

    Args:
        pcap_files (str | List[str]): (list of) PCAP file(s).
    Returns:
        List[PacketFingerprint]: List of packet fingerprints.
    """
    global pkts
    
    if isinstance(pcap_files, list):
        for pcap in pcap_files:
            pcap_to_pkts(pcap)
    else:
        pcap_to_pkts(pcap_files)
    
    return pkts


def pkts_to_df(pkts: List[PacketFingerprint]) -> pd.DataFrame:
    """
    Convert a list of packets to a DataFrame.

    Args:
        pkts (List[Packet]): List of packet fingerprints.
    Returns:
        pd.DataFrame: DataFrame of packet fingerprints.
    """
    return pd.DataFrame([dict(pkt) for pkt in pkts])


def save_pkts_to_csv(pkts: List[PacketFingerprint], output_file: str) -> None:
    """
    Save a list of packets to a CSV file.

    Args:
        pkts (List[Packet]): List of packet fingerprints.
        output_file (str): Output file.
    """
    df = pkts_to_df(pkts)
    df.to_csv(output_file, index=False)


def pcaps_to_csv(pcap_files: Union[str, List[str]], output_file: str) -> None:
    """
    Convert one or multiple PCAP file(s) to a list of PacketSignatures,
    and save it to a CSV file.

    Args:
        pcap_files (Union[str, List[str]]): (list of) PCAP file(s).
        output_file (str): Output file.
    """
    pkts = pcaps_to_pkts(pcap_files)
    save_pkts_to_csv(pkts, output_file)
