import pandas as pd


class Pattern:
    ip_adresses = ()
    ports = {}
    protocol = ""
    application_data = {}

    def __init__(self, frame: pd.DataFrame) -> None:
        """Pattern constructor

        Args:
            frame (pd.DataFrame): Data frame to init with
        """
        self.ip_adresses = (frame["DeviceHost"], frame["OtherHost"])
        self.protocol = frame["TransportProtocol"]
        self.ports = self.addPorts(frame)

    def clearPorts(self) -> None:
        """Clear ports and application data"""
        self.ports = {}
        self.application_data = {}

    def addPorts(self, frame: pd.DataFrame) -> None:
        """Add ports from data frame

        Args:
            frame (pd.DataFrame): _description_

        Returns:
            _type_: _description_
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
            (record["DeviceHost"].isin(self.ip_adresses))
            & (record["OtherHost"].isin(self.ip_adresses))
            & (record["TransportProtocol"] == self.protocol)
        ]

    def mostUsedPort(self) -> int:
        return list(
            dict(
                sorted(
                    self.ports.items(), key=lambda item: item[1]["number"], reverse=True
                )
            )
        )[0]

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
        output += f"IP Addresses: {self.ip_adresses}"
        output += f"\nProtocol: {self.protocol}"
        sorted_ports = sorted(
            self.ports.items(), key=lambda item: item[1]["number"], reverse=True
        )
        output += f"\nPorts: {sorted_ports[:3]}"
        output += f"\nMost Used Port: {self.mostUsedPort()} -> {self.ports[self.mostUsedPort()]['host']}"
        output += f"\nApplication Data: {self.application_data}"

        return output
    
    def __repr__(self):
        output = ""
        output += f"IP Addresses: {self.ip_adresses}"
        output += f"\nProtocol: {self.protocol}"
        sorted_ports = sorted(
            self.ports.items(), key=lambda item: item[1]["number"], reverse=True
        )
        output += f"\nPorts: {sorted_ports[:3]}"
        output += f"\nMost Used Port: {self.mostUsedPort()} -> {self.ports[self.mostUsedPort()]['host']}"
        output += f"\nApplication Data: {self.application_data}"

        return output

    def getDeviceHost(self) -> str:
        """Get device host ip or domain name

        Returns:
            str: ip address or domain name
        """
        ref = self.raw

        return list(set(self.ip_adresses) & set(ref["DeviceHost"]))

    def getOtherHost(self) -> str:
        """Get device host ip or domain name

        Returns:
            str: ip address or domain name
        """
        ref = self.raw

        return list(set(self.ip_adresses) & set(ref["OtherHost"]))

    def getDevicePort(self) -> int:
        """Get device Port

        Returns:
            int: device port
        """
        ref = self.raw
        mostUsedPort = self.mostUsedPort()
        return list(set([mostUsedPort]) & set(ref["DevicePort"]))


    def getOtherPort(self) -> int:
        """Get other Port

        Returns:
            int: device port
        """
        ref = self.raw
        mostUsedPort = self.mostUsedPort()
        return list(set([mostUsedPort]) & set(ref["OtherPort"]))


    def profile_extractor(self):
        profile = {
            "protocols": {
                "ipv4": {"src": self.getDeviceHost()[0], "dst": self.getOtherHost()[0]},
            }
        }

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
