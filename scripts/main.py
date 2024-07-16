#!/usr/bin/python3

from domain_extractor import extract_domain_names, replace_ip_with_domain_name
from signature_extractor import packet_fields
from packet_translator import write, translate
import scapy.all as scapy

folder = "/home/remi/Documents/Repos/iot-dynamic-fingerprinting (old)/android/tplink-kasa/activities/EXP1/"

timestamps = []

with open(folder + "act.txt") as file:
    timestamps = [line.rstrip() for line in file]

packets = scapy.rdpcap(folder + "file.pcap")

domain_names = extract_domain_names(packets)

print(domain_names)

for timestamp in timestamps:
    signatures = translate(5, int(timestamp), packets)
    signatures = [
        replace_ip_with_domain_name(domain_names, signature) for signature in signatures
    ]
    write(folder + "signature_" + timestamp + ".csv", signatures, packet_fields)
