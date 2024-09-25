from __future__ import annotations
from typing import List, Tuple
import pandas as pd
from .BaseFlow import BaseFlow
from .FlowFingerprint import FlowFingerprint


class NetworkPattern:
    """
    List of network flows occurring subsequently.
    """

    def __init__(self, flows: List[BaseFlow] = []) -> None:
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
        Get the number of flow fingerprints in the list.

        Returns:
            int: Number of flow fingerprints.
        """
        return len(self.flows)
    

    def get_flows(self) -> List[BaseFlow]:
        """
        Get the list of flow fingerprints.

        Returns:
            List[FlowFingerprint]: List of flow fingerprints.
        """
        return self.flows
    

    def set_flows(self, flows: List[BaseFlow]) -> None:
        """
        Set the list of flow fingerprints.

        Args:
            flows (List[FlowFingerprint]): List of flow fingerprints.
        """
        self.flows = flows


    def add_flow(self, flow: BaseFlow) -> None:
        """
        Add a flow fingerprint to the list.

        Args:
            flow (FlowFingerprint): BaseFlow fingerprint to add.
        """
        self.flows.append(flow)

    
    def find_matching_flow(self, flow: BaseFlow) -> Tuple[int, BaseFlow]:
        """
        Find a flow in the list which matches the basic attributes,
        i.e. the hosts and transport protocol,
        of the given flow.

        Args:
            flow (BaseFlow): flow to search for.
        Returns:
            Tuple[int, BaseFlow]: associated index, and matching flow
        Raises:
            ValueError: If no matching flow has been found in the pattern.
        """
        i = self.flows.index(flow)
        return i, self.flows[i]
    

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
