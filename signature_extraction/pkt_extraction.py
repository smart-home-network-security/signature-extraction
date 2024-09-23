## Imports
# Libraries
from typing import List
import scapy.all as scapy
import pandas as pd
# Package
from .utils.packet_utils import should_skip_pkt, extract_domain_names
from .network import Packet


### Variables
# Config variables
timeout = 5  # seconds
# Packet loop accumulators
i = 0
timestamp     = 0
previous_time = 0
domain_names  = {}
pkts          = []


def reset_vars() -> None:
    """
    Reset global variables.
    """
    global i, timestamp, previous_time, domain_names, pkts
    i = 0
    timestamp     = 0
    previous_time = 0
    domain_names  = {}
    pkts          = []


def handle_packet(packet: scapy.Packet) -> None:
    """
    Callback function which handles one packet read from a PCAP file.

    Args:
        packet (scapy.Packet): Packet read from the PCAP file.
    """
    global i, timestamp, previous_time, domain_names, pkts

    ## Packet validation

    # If timestamp is not set, set it with the first packet
    if i == 0 and timestamp == 0:
        timestamp = packet.time

    # If first packet, set timestamp
    if previous_time == 0:
        previous_time = packet.time

    # Skip signalling packets (e.g., TCP SYN)
    if should_skip_pkt(packet):
        return
    
    # Stop iteration if timeout exceeded w.r.t. previous packet
    if packet.time > previous_time + timeout:
        return
    
    # Domain name extraction
    extract_domain_names(packet, domain_names)

    ## Packet fingerprint extraction
    pkt = Packet.build_from_pkt(packet)
    pkt.set_domain_names(domain_names)
    pkts.append(pkt)

    # Update loop variables
    previous_time = packet.time
    i += 1


def pcap_to_pkts(pcap_file: str) -> List[Packet]:
    """
    Convert a PCAP file to a list of packets.

    Args:
        pcap_file (str): PCAP file.
    Returns:
        List[Packet]: List of packet fingerprints.
    """
    global pkts
    scapy.sniff(offline=pcap_file, prn=handle_packet, store=False)
    packets = pkts
    reset_vars()
    return packets


def df_to_pkts(df: pd.DataFrame) -> List[Packet]:
    """
    Convert a DataFrame to a list of packets.

    Args:
        df (pd.DataFrame): DataFrame of packet fingerprints.
    Returns:
        List[Packet]: List of packet fingerprints.
    """
    return [Packet(row) for _, row in df.iterrows()]


def pkts_to_df(pkts: List[Packet]) -> pd.DataFrame:
    """
    Convert a list of packets to a DataFrame.

    Args:
        pkts (List[Packet]): List of packet fingerprints.
    Returns:
        pd.DataFrame: DataFrame of packet fingerprints.
    """
    return pd.DataFrame([dict(pkt) for pkt in pkts])


def pcap_to_df(pcap_file: str) -> pd.DataFrame:
    """
    Convert a PCAP file to a DataFrame.

    Args:
        pcap_file (str): PCAP file.
    Returns:
        pd.DataFrame: DataFrame of packet fingerprints.
    """
    pkts = pcap_to_pkts(pcap_file)
    return pkts_to_df(pkts)


def pkts_to_csv(pkts: List[Packet], output_file: str) -> None:
    """
    Save a list of packets to a CSV file.

    Args:
        pkts (List[Packet]): List of packet fingerprints.
        output_file (str): Output file.
    """
    df = pkts_to_df(pkts)
    df.to_csv(output_file, index=False)


def pcap_to_csv(pcap_file: str, output_file: str) -> None:
    """
    Convert a PCAP file to a list of PacketSignatures,
    and save it to a CSV file.

    Args:
        pcap_file (str): PCAP file.
        output_file (str): Output file.
    """
    pkts = pcap_to_pkts(pcap_file)
    pkts_to_csv(pkts, output_file)
