## Imports
# Libraries
from typing import List
import scapy.all as scapy
import pandas as pd
# Package
from .utils import should_skip_pkt, extract_domain_names
from .network import Packet


### Variables
# Config variables
timeout = 20  # seconds
# Packet loop accumulators
i = 0
previous_time = 0
dns_table     = {}
pkts          = []


def reset_vars() -> None:
    """
    Reset global variables.
    """
    global i, previous_time, dns_table, pkts
    i = 0
    previous_time = 0
    dns_table     = {}
    pkts          = []


def handle_packet(packet: scapy.Packet) -> None:
    """
    Callback function which handles one packet read from a PCAP file.

    Args:
        packet (scapy.Packet): Packet read from the PCAP file.
    """
    global i, previous_time, dns_table, pkts, timeout

    ## Packet validation

    # If first packet, set timestamp
    if previous_time == 0:
        previous_time = packet.time
    
    # Stop iteration if timeout exceeded w.r.t. previous packet
    if packet.time > previous_time + timeout:
        return
    
    previous_time = packet.time

    # Skip signalling packets (e.g., TCP SYN)
    if should_skip_pkt(packet):
        return
    
    # Domain name extraction
    extract_domain_names(packet, dns_table)

    ## Packet fingerprint extraction
    pkt = Packet.build_from_pkt(packet)
    pkts.append(pkt)

    i += 1


def pcap_to_pkts(pcap_file: str, dns_table_arg: dict = {}, timeout_arg: int = 20) -> List[Packet]:
    """
    Convert a PCAP file to a list of packets.

    Args:
        pcap_file (str): PCAP file.
        dns_table_arg (dict): Dictionary mapping IP addresses to domain names. Optional, default is empty.
        timeout_arg (int): Iteration is stopped if current packet's timestamp exceeds the previous one by this value [seconds].
                           Optional, default is 20 seconds.
    Returns:
        List[Packet]: List of packet fingerprints.
    """
    # Set global variables
    global pkts, dns_table, timeout
    dns_table = dns_table_arg
    timeout = timeout_arg

    # Read PCAP file
    scapy.sniff(offline=pcap_file, prn=handle_packet, store=False)
    packets = Packet.replace_ips_with_domains(pkts, dns_table)

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


def pcap_to_df(pcap_file: str, dns_table_arg: dict = {}, timeout_arg: int = 20) -> pd.DataFrame:
    """
    Convert a PCAP file to a DataFrame.

    Args:
        pcap_file (str): PCAP file.
        dns_table_arg (dict): Dictionary mapping IP addresses to domain names. Optional, default is empty.
        timeout_arg (int): Iteration is stopped if current packet's timestamp exceeds the previous one by this value [seconds].
                           Optional, default is 20 seconds.
    Returns:
        pd.DataFrame: DataFrame of packet fingerprints.
    """
    pkts = pcap_to_pkts(pcap_file, dns_table_arg, timeout_arg)
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


def pcap_to_csv(pcap_file: str, output_file: str, dns_table_arg: dict = {}, timeout_arg: int = 20) -> None:
    """
    Convert a PCAP file to a list of PacketSignatures,
    and save it to a CSV file.

    Args:
        pcap_file (str): PCAP file.
        output_file (str): Output file.
        dns_table_arg (dict): Dictionary mapping IP addresses to domain names. Optional, default is empty.
        timeout_arg (int): Iteration is stopped if current packet's timestamp exceeds the previous one by this value [seconds].
            Optional, default is 20 seconds.
    """
    pkts = pcap_to_pkts(pcap_file, dns_table_arg, timeout_arg)
    pkts_to_csv(pkts, output_file)
