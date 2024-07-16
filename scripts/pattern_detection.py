#!/usr/bin/python3

# Library
import os  # import all CSV from a folder
import pandas as pd  # operations on CSV
from pattern import Pattern
from uuid import uuid1 as uuid
from datetime import datetime
import yaml

# Global variables
already_matched_ports = []
identified_patterns = []  # list of patterns
network_records = []  # list of records, imported from CSVs files

# Edit this to the relative path where CSVs are stored
path = "/home/remi/Documents/Repos/iot-dynamic-fingerprinting/android/tplink-kasa/activities/EXP2/"
dirs = os.listdir(path)

# Import CSV files
for file in dirs:
    if file.endswith(".csv"):
        network_records.append(pd.read_csv(path + "/" + file))

record_number = len(network_records)

# Sort the list of recording of their number of rows
network_recording = sorted(network_records, key=len)

# set the reference packet to the smallest one
# WARNING: suppose every recording has the event
reference_record = network_recording[0]

# iterate through all the line inside the recording
for line in reference_record.iterrows():
    result = pd.DataFrame()
    pattern = Pattern(line[1])

    # iterate through all record and filter only the line
    # that match IPs and transport protocol
    for record in network_recording:
        result = pd.concat(
            [
                result,
                pattern.matchBasicSignature(record),
            ]
        )

    if result.empty:
        raise Exception("No matching frame has been find")

    # Add Ports to the Pattern
    for record in result.iterrows():
        pattern.addPorts(record[1])

    for already_matched_port in already_matched_ports:
        if already_matched_port in list(pattern.ports):
            pattern.ports.pop(already_matched_port)

    base_port = pattern.mostUsedPort()  # get most frequent port
    already_matched_ports.append(base_port)

    result = result[
        (result["DevicePort"] == base_port) | (result["OtherPort"] == base_port)
    ]

    pattern.clearPorts()

    # display(result)

    for frame in result.iterrows():
        # print(frame)
        pattern.addPorts(frame[1])
        pattern.getApplicationData(frame[1], "Length")
        pattern.getApplicationData(frame[1], "ApplicationSpecific")
        pattern.getApplicationData(frame[1], "nbPacket")
        pattern.raw = result

    identified_patterns.append(pattern)


print(f"I found {len(identified_patterns)} pattern.")

policies = {}

for pattern in identified_patterns:
    print(pattern)
    print("\n")
    toadd = pattern.profile_extractor()
    unique = str(uuid())
    policies[unique] = toadd
    pattern.raw.to_csv(path + "/signature_end.txt")

deviceinfo = {"last-update": datetime.today().strftime("%a %d %b %Y, %I:%M%p")}

profile = {}
profile["device-info"] = deviceinfo
profile["single-policies"] = policies
print(profile)
with open('output.yaml', 'w') as f:
    yaml.dump(profile, f)