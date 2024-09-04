## Imports
# Libraries
from __future__ import annotations
from typing import Tuple
import os
from pathlib import Path
from ipaddress import IPv4Address
import pandas as pd
# Custom
from packet_utils import application_protocols, is_known_port
from profile_translator_blocklist import translate_policy


# Paths
this_path = Path(os.path.abspath(__file__))
this_dir = this_path.parents[0]
base_dir = this_path.parents[1]


class Fingerprint:

    def __init__(self, frame: pd.DataFrame) -> None:
        """Packet fingerprint constructor

        Args:
            frame (pd.DataFrame): Data frame to init with
        """
        self.ip_addresses = (frame["DeviceHost"], frame["OtherHost"])
        self.protocol = frame["TransportProtocol"]
        self.ports = {}
        self.addPorts(frame)
        self.fixed_port = self.get_fixed_port()
        self.application_data = {}
        self.bidirectional = True

    
    def __str__(self):
        output = ""
        output += f"IP Addresses: {self.ip_addresses}"
        output += f"\nProtocol: {self.protocol}"
        sorted_ports = sorted(
            self.ports.items(), key=lambda item: item[1]["number"], reverse=True
        )
        output += f"\nPorts: {sorted_ports}"
        output += f"\nFixed port: {self.fixed_port}"
        output += f"\nApplication Data: {self.application_data}"

        return output


    def __repr__(self):
        # Device host and port
        device = self.get_device_host()
        device_port = self.get_device_port()
        if device_port is not None:
            device += f":{device_port}"
        
        # Other host and port
        other = self.get_other_host()
        other_port = self.get_other_port()
        if other_port is not None:
            other += f":{other_port}"

        # Add protocol and application data
        return f"{device} -> {other} [{self.protocol}]: {self.application_data}"
    

    def __eq__(self, other: Fingerprint) -> bool:
        """
        Compare two Fingerprint objects for equality.

        Args:
            other (Fingerprint): Fingerprint to compare with.
        Returns:
            bool: True if the Fingerprint objects are equal, False otherwise.
        """
        if not isinstance(other, Fingerprint):
            return False
        
        return (
            self.ip_addresses == other.ip_addresses and
            self.protocol == other.protocol and
            self.fixed_port == other.fixed_port
        )


    def clearPorts(self) -> None:
        """Clear ports and application data"""
        self.ports = {}
        self.application_data = {}


    def addPorts(self, frame: pd.DataFrame) -> None:
        """Add ports from data frame

        Args:
            frame (pd.DataFrame): _description_
        """
        DevicePort = int(frame["DevicePort"])
        DeviceHost = frame["DeviceHost"]

        OtherPort = int(frame["OtherPort"])
        OtherHost = frame["OtherHost"]

        if DevicePort and (DevicePort not in self.ports):
            self.ports[DevicePort] = {"number": 1, "host": DeviceHost}
        else:
            self.ports[DevicePort]["number"] += 1

        if OtherPort and (OtherPort not in self.ports):
            self.ports[OtherPort] = {"number": 1, "host": OtherHost}
        else:
            self.ports[OtherPort]["number"] += 1

        return self.ports


    def matchBasicSignature(self, record: pd.DataFrame) -> pd.DataFrame:
        return record[
            (record["DeviceHost"].isin(self.ip_addresses))
            & (record["OtherHost"].isin(self.ip_addresses))
            & (record["TransportProtocol"] == self.protocol)
        ]


    def get_fixed_port(self) -> Tuple[int, str]:
        # Sort port numbers by number of occurences
        ports_sorted = sorted(self.ports.items(), key=lambda item: item[1]["number"], reverse=True)

        # If one of the port numbers is well-known, return it
        for port, data in ports_sorted:
            if is_known_port(port, self.protocol):
                return port, data["host"]

        # Else, return the most used port
        return ports_sorted[0][0], ports_sorted[0][1]["host"]


    def getApplicationData(
        self,
        frame: pd.DataFrame,
        data: str,
    ):
        if data not in self.application_data:
            self.application_data[data] = {}

        value = frame[data]

        if value and (value not in self.application_data[data]):
            self.application_data[data][value] = 1
        else:
            try:
                self.application_data[data][value] += 1
            except KeyError:
                pass
        
        return self.application_data
    

    def get_device_host(self) -> str:
        """Get device host ip or domain name

        Returns:
            str: ip address or domain name
        """
        return self.ip_addresses[0]


    def get_other_host(self) -> str:
        """Get other host ip or domain name

        Returns:
            str: ip address or domain name
        """
        return self.ip_addresses[1]


    def get_device_port(self) -> int:
        """Get device Port

        Returns:
            int: device port
        """
        device_host = self.get_device_host()
        if self.fixed_port[1] == device_host:
            return self.fixed_port[0]
        else:
            return None


    def get_other_port(self) -> int:
        """Get other Port

        Returns:
            int: device port
        """
        other_host = self.get_other_host()
        if self.fixed_port[1] == other_host:
            return self.fixed_port[0]
        else:
            return None
    

    def get_application_protocol(self) -> str:
        """
        Retrieve the application layer protocol from the packet fingerprint.

        Returns:
            str: Application layer protocol.
        """
        protocol = self.protocol.lower()
        src_port = self.get_device_port()
        dst_port = self.get_other_port()
        if src_port:
            return application_protocols[protocol].get(src_port, None)
        elif dst_port:
            return application_protocols[protocol].get(dst_port, None)


    def extract_policy(self, ipv4: IPv4Address) -> dict:
        """
        Extract a profile-compliant policy from this packet fingerprint.
        
        Args:
            ipv4 (IPv4Address): IP address of the device.
        Returns:
            dict: Policy extracted from the packet fingerprint.
        """
        # IP addresses
        src_ip = self.get_device_host()
        src_ip = "self" if src_ip == str(ipv4) else src_ip
        dst_ip = self.get_other_host()
        dst_ip = "self" if dst_ip == str(ipv4) else dst_ip
        policy = {
            "protocols": {
                "ipv4": {"src": src_ip, "dst": dst_ip},
            }
        }

        # Protocols
        src_port = self.get_device_port()
        dst_port = self.get_other_port()
        protocol = self.protocol.lower()
        if src_port:
            policy["protocols"][protocol] = {"src-port": src_port}
            protocol_port = src_port
        if dst_port:
            policy["protocols"][protocol] = {"dst-port": dst_port}
            protocol_port = dst_port

        # Application layer protocol
        application_protocol = self.get_application_protocol()
        if application_protocol == "dns":
            query = list(self.application_data["ApplicationSpecific"])[0]
            # query format = "type domainname"
            # split query by space
            query = query.split(" ")

            policy["protocols"]["dns"] = {
                "qtype": query[0],
                "domain-name": query[1][:-1],
            }
        
        policy["bidirectional"] = self.bidirectional

        return policy
    

    def translate_to_firewall(self, device_name: str, ipv4: IPv4Address, output_dir: str = os.getcwd()) -> None:
        """
        Translate this fingerprint to NFTables/NFQueue firewall files.

        Args:
            device_name (str): Name of the device.
            ipv4 (IPv4Address): IP address of the device.
            output_dir (str): Output directory. Optional, defaults to the current working directory.
        """
        # Validate output directory
        if not os.path.isdir(output_dir):
            print(f"Output directory {output_dir} does not exist. Using current directory.")
            output_dir = os.getcwd()

        # Device metadata
        device = {
            "device-name": device_name,
            "ipv4": str(ipv4)
        }

        # Extract policy
        policy_dict = self.extract_policy(ipv4)
        translate_policy(device, policy_dict, output_dir=output_dir)
