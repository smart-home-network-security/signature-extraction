from ipaddress import IPv4Address
import pandas as pd
from packet_utils import is_known_port


class Fingerprint:

    def __init__(self, frame: pd.DataFrame) -> None:
        """Packet fingerprint constructor

        Args:
            frame (pd.DataFrame): Data frame to init with
        """
        self.ip_addresses = (frame["DeviceHost"], frame["OtherHost"])
        self.protocol = frame["TransportProtocol"]
        self.ports = {}
        self.ports = self.addPorts(frame)
        self.application_data = {}


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
            self.ports[DevicePort] = {"number": 1, "host": [DeviceHost]}
        else:
            self.ports[DevicePort]["number"] += 1

        if OtherPort and (OtherPort not in self.ports):
            self.ports[OtherPort] = {"number": 1, "host": [OtherHost]}
        else:
            self.ports[OtherPort]["number"] += 1

        return self.ports


    def matchBasicSignature(self, record: pd.DataFrame) -> pd.DataFrame:
        return record[
            (record["DeviceHost"].isin(self.ip_addresses))
            & (record["OtherHost"].isin(self.ip_addresses))
            & (record["TransportProtocol"] == self.protocol)
        ]


    def getFixedPort(self) -> int:
        # Sort port numbers by number of occurences
        ports_sorted = list(
            dict(
                sorted(
                    self.ports.items(), key=lambda item: item[1]["number"], reverse=True
                )
            )
        )

        # If one of the port numbers is well-known, return it
        for port in ports_sorted:
            if is_known_port(port, self.protocol):
                return port

        # Else, return the most used port
        return ports_sorted[0]


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

    # from tabulate import tabulate

    def __str__(self):
        output = ""
        output += f"IP Addresses: {self.ip_addresses}"
        output += f"\nProtocol: {self.protocol}"
        sorted_ports = sorted(
            self.ports.items(), key=lambda item: item[1]["number"], reverse=True
        )
        output += f"\nPorts: {sorted_ports}"
        output += f"\nFixed port: {self.getFixedPort()} -> {self.ports[self.getFixedPort()]['host']}"
        output += f"\nApplication Data: {self.application_data}"

        return output
    
    def __repr__(self):
        return self.__str__()

    def getDeviceHost(self) -> str:
        """Get device host ip or domain name

        Returns:
            str: ip address or domain name
        """
        ref = self.raw

        return list(set(self.ip_addresses) & set(ref["DeviceHost"]))

    def getOtherHost(self) -> str:
        """Get device host ip or domain name

        Returns:
            str: ip address or domain name
        """
        ref = self.raw

        return list(set(self.ip_addresses) & set(ref["OtherHost"]))

    def getDevicePort(self) -> int:
        """Get device Port

        Returns:
            int: device port
        """
        ref = self.raw
        fixed_port = self.getFixedPort()
        return list(set([fixed_port]) & set(ref["DevicePort"]))


    def getOtherPort(self) -> int:
        """Get other Port

        Returns:
            int: device port
        """
        ref = self.raw
        fixed_port = self.getFixedPort()
        return list(set([fixed_port]) & set(ref["OtherPort"]))


    def policy_extractor(self, ipv4: IPv4Address) -> dict:
        """
        Extract a profile-compliant policy from this packet fingerprint.
        
        Args:
            ipv4 (IPv4Address): IP address of the device.
        Returns:
            dict: Policy extracted from the packet fingerprint.
        """

        # IP addresses
        src_ip = self.getDeviceHost()[0]
        src_ip = "self" if src_ip == str(ipv4) else src_ip
        dst_ip = self.getOtherHost()[0]
        dst_ip = "self" if dst_ip == str(ipv4) else dst_ip
        profile = {
            "protocols": {
                "ipv4": {"src": src_ip, "dst": dst_ip},
            }
        }

        # Protocols
        if self.protocol == "TCP":
            src = self.getDevicePort()
            dst = self.getOtherPort()

            if src:
                profile["protocols"]["tcp"] = {"src-port": src[0]}
            if dst:
                profile["protocols"]["tcp"] = {"dst-port": dst[0]}

        elif self.protocol == "UDP":
            src = self.getDevicePort()
            dst = self.getOtherPort()
            protoport = 0

            if src:
                profile["protocols"]["udp"] = {"src-port": src[0]}
                protoport = src[0]
            if dst:
                profile["protocols"]["udp"] = {"dst-port": dst[0]}
                protoport = dst[0]

            if protoport == 53:
                query = list(self.application_data["ApplicationSpecific"])[0]
                # query format = "type domainname"
                # split query by space
                query = query.split(" ")

                profile["protocols"]["dns"] = {
                    "qtype": query[0],
                    "domain-name": query[1][:-1],
                }

        return profile
