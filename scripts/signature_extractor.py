import os
import pandas as pd
from fingerprint import Fingerprint
from datetime import datetime
import yaml
from ipaddress import IPv4Address


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
            network_records.append(pd.read_csv(path + "/" + file))
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
            matched_record = fingerprint.matchBasicSignature(record)
            if j == 0:  # Reference record
                index = matched_record.index[0]
                already_parsed_flows_indices.add(index)
            result = pd.concat([result, matched_record])

        if result.empty:
            raise Exception("No matching frame has been found")

        for record in result.iterrows():
            fingerprint.addPorts(record[1])

        for already_matched_port in already_matched_ports:
            if already_matched_port in list(fingerprint.ports):
                fingerprint.ports.pop(already_matched_port)

        base_port = fingerprint.getFixedPort()
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
            fingerprint.raw = result

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
