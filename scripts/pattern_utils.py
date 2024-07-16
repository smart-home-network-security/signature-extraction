from pandas import DataFrame

class Pattern:
    ip_adresses = ()
    ports = {}
    protocol = ""
    application_data = {}

    def __init__(self, frame: DataFrame) -> None :
        self.ip_adresses = (frame["DeviceHost"], frame["OtherHost"])
        self.protocol = frame["TransportProtocol"]
        self.ports = self.addPorts(frame)

    def addPorts(self, frame: DataFrame) -> None:
        DevicePort = int(frame["DevicePort"])
        if DevicePort not in self.ports:
            self.ports[DevicePort] = 1
        else:
            self.ports[DevicePort] += 1

        OtherPort = int(frame["OtherPort"])
        if OtherPort not in self.ports:
            self.ports[OtherPort] = 1
        else:
            self.ports[OtherPort] += 1

    def matchBasicSignature(self, record: DataFrame) -> DataFrame:
        return record[
            (record["DeviceHost"] == self.ip_adresses)
            & (record["OtherHost"] == self.OtherHost)
            & (record["TransportProtocol"] == self.TransportProtocol)
        ]
