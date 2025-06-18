from __future__ import annotations
from typing import List, Tuple
import pandas as pd
from .FlowFingerprint import FlowFingerprint


class NetworkPattern:
    """
    List of network flows occurring subsequently.
    """

    def __init__(self, flows: list[FlowFingerprint] = []) -> None:
        """
        NetworkPattern constructor.

        Args:
            flows (List[FlowFingerprint]): List of flow fingerprints.
        """
        self.flows = flows if flows else []

    
    @classmethod
    def load_from_csv(cls, csv_file: str) -> NetworkPattern:
        """
        Instantiate a NetworkPattern object from a CSV file.

        Args:
            csv_file (str): CSV file containing the network pattern.
        Returns:
            NetworkPattern: Network pattern.
        """
        df = pd.read_csv(csv_file, na_filter=False)
        return cls([FlowFingerprint(row) for _, row in df.iterrows()])
    

    def __repr__(self) -> str:
        """
        String representation of an NetworkPattern object.

        Returns:
            str: String representation of an NetworkPattern object.
        """
        return ", ".join([f"<{flow}>" for flow in self.flows])
    

    def __str__(self) -> str:
        """
        "Printable" string representation of an NetworkPattern object.

        Returns:
            str: String representation of an NetworkPattern object.
        """
        return "\n".join([f"<{flow}>" for flow in self.flows])
    

    def __len__(self) -> int:
        """
        Get the number of FlowFingerprints in the NetworkPattern.

        Returns:
            int: Number of FlowFingerprints.
        """
        return len(self.flows)
    

    def get_flows(self) -> list[FlowFingerprint]:
        """
        Get the list of FlowFingerprints.

        Returns:
            List[FlowFingerprint]: list of FlowFingerprints.
        """
        return self.flows
    

    def set_flows(self, flows: list[FlowFingerprint]) -> None:
        """
        Set the list of flow fingerprints.

        Args:
            flows (List[FlowFingerprint]): List of flow fingerprints.
        """
        self.flows = flows


    def add_flow(self, flow: FlowFingerprint) -> None:
        """
        Add a FlowFingerprint to this NetworkPattern.

        Args:
            flow (FlowFingerprint): FlowFingerprint fingerprint to add.
        """
        self.flows.append(flow)

    
    def find_matching_flow(self, reference_flow: FlowFingerprint, match_random_ports: bool = False) -> Tuple[int, FlowFingerprint]:
        """
        Find a flow in the list which matches the basic attributes,
        i.e. the hosts, fixed port and transport protocol,
        of the given flow.

        Args:
            reference_flow (FlowFingerprint): flow to search for.
            match_random_ports (bool): Whether to consider random ports in flow matching.
                                       Optional, default is False.
        Returns:
            Tuple[int, FlowFingerprint]: associated index, and matching flow
        Raises:
            ValueError: If no matching flow has been found in the pattern.
        """
        for i, flow in enumerate(self.flows):
            if reference_flow.match_flow(flow, match_random_ports):
                return i, flow
        
        raise ValueError("No matching flow found in the pattern.")
    

    def to_df(self) -> pd.DataFrame:
        """
        Convert the network pattern to a DataFrame.

        Returns:
            pd.DataFrame: DataFrame of flow fingerprints.
        """
        return pd.DataFrame([dict(flow) for flow in self.flows])
    

    def to_csv(self, output_file: str) -> None:
        """
        Save the network pattern to a CSV file.

        Args:
            output_file (str): Output file.
        """
        self.to_df().to_csv(output_file, index=False)
