from typing import List
import pandas as pd
from .classes import FlowFingerprint, EventSignature


# def flows_to_event(flows: List[FlowFingerprint]) -> EventSignature:
#     """
#     Extract an event signature from a list of flow fingerprints.

#     Args:
#         flows (List[FlowFingerprint]): List of flow fingerprints.
#     Returns:
#         EventSignature: Event signature extracted from the flows.
#     """
#     already_parsed_flows_indices = set()
#     already_matched_ports = set()
#     identified_flows = []
#     flows = sorted(flows, key=len)
#     reference_record = network_recording[0]

#     for i, flow in reference_record.iterrows():

#         # Flow already parsed, skip
#         if i in already_parsed_flows_indices:
#             continue

#         ## Parse flow

#         result = pd.DataFrame()
#         fingerprint = Fingerprint(flow)
#         already_parsed_flows_indices.add(i)

#         for j, record in enumerate(network_recording):
#             matched_record = fingerprint.matchBasicSignature(record)
#             if j == 0:  # Reference record
#                 index = matched_record.index[0]
#                 already_parsed_flows_indices.add(index)
#             result = pd.concat([result, matched_record])

#         if result.empty:
#             raise Exception("No matching frame has been found")

#         for record in result.iterrows():
#             fingerprint.addPorts(record[1])

#         for already_matched_port in already_matched_ports:
#             if already_matched_port in list(fingerprint.ports):
#                 fingerprint.ports.pop(already_matched_port)

#         base_port = fingerprint.get_fixed_port()[0]
#         already_matched_ports.add(base_port)

#         result = result[
#             (result["DevicePort"] == base_port) | (result["OtherPort"] == base_port)
#         ]

#         fingerprint.clearPorts()

#         for frame in result.iterrows():
#             fingerprint.addPorts(frame[1])
#             fingerprint.getApplicationData(frame[1], "Length")
#             fingerprint.getApplicationData(frame[1], "ApplicationSpecific")
#             fingerprint.getApplicationData(frame[1], "nbPacket")

#         identified_flows.append(fingerprint)

#     return identified_flows
