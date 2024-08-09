import os
import pandas as pd
from pattern import Pattern
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


def find_patterns(network_records: list) -> list:
    """
    Find patterns in the network records

    :param: network_records (list): list of dataframes
    :raises Exception: No matching frame has been found
    :return: list: list of patterns
    """
    already_parsed_pattern_indices = set()
    already_matched_ports = []
    identified_patterns = []
    network_recording = sorted(network_records, key=len)
    reference_record = network_recording[0]

    for i, flow in reference_record.iterrows():

        # Pattern already parsed, skip
        if i in already_parsed_pattern_indices:
            continue

        ## Parse pattern

        result = pd.DataFrame()
        pattern = Pattern(flow)
        already_parsed_pattern_indices.add(i)

        for j, record in enumerate(network_recording):
            matched_record = pattern.matchBasicSignature(record)
            if j == 0:  # Reference record
                already_parsed_pattern_indices.update(matched_record.index)
            result = pd.concat([result, matched_record])

        if result.empty:
            raise Exception("No matching frame has been found")

        for record in result.iterrows():
            pattern.addPorts(record[1])

        for already_matched_port in already_matched_ports:
            if already_matched_port in list(pattern.ports):
                pattern.ports.pop(already_matched_port)

        base_port = pattern.mostUsedPort()
        already_matched_ports.append(base_port)

        result = result[
            (result["DevicePort"] == base_port) | (result["OtherPort"] == base_port)
        ]

        pattern.clearPorts()

        for frame in result.iterrows():
            pattern.addPorts(frame[1])
            pattern.getApplicationData(frame[1], "Length")
            pattern.getApplicationData(frame[1], "ApplicationSpecific")
            pattern.getApplicationData(frame[1], "nbPacket")
            pattern.raw = result

        identified_patterns.append(pattern)

    return identified_patterns


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


def generate_policies(ipv4:IPv4Address, identified_patterns: list) -> dict:
    policies = {}

    for pattern in identified_patterns:
        policy = pattern.profile_extractor(ipv4)
        policy["bidirectional"] = True
        id = get_policy_id(policy)
        policies[id] = policy

    return policies


def write_profile(device_name: str, ipv4: IPv4Address, policies: dict, path: str) -> None:
    deviceinfo = {
        "name": device_name,
        "ipv4": str(ipv4),
        "last-update": datetime.today().strftime("%a %d %b %Y, %I:%M%p")
    }
    profile = {"device-info": deviceinfo, "single-policies": policies}

    with open(path + "profile.yaml", "w") as f:
        yaml.dump(profile, f)


def main():
    path = "demo/"
    network_records = load_csv_files(path)
    identified_patterns = find_patterns(network_records)
    policies = generate_policies(identified_patterns)

    write_profile(policies, path)


if __name__ == "__main__":
    main()
