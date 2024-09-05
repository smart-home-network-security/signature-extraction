from typing import List
import pandas as pd
from .FlowFingerprint import FlowFingerprint


class NetworkPattern:
    """
    List of network flows occurring subsequently.
    """

    def __init__(self, flows: List[FlowFingerprint] = []) -> None:
        """
        NetworkPattern constructor.

        Args:
            flows (List[FlowFingerprint]): List of flow fingerprints.
        """
        self.flows = flows if flows else []
    

    def __repr__(self) -> str:
        """
        String representation of an NetworkPattern object.

        Returns:
            str: String representation of an NetworkPattern object.
        """
        return ", ".join([f"<{flow.str_base()}>" for flow in self.flows])
    

    def __len__(self) -> int:
        """
        Get the number of flow fingerprints in the list.

        Returns:
            int: Number of flow fingerprints.
        """
        return len(self.flows)
    

    def get_flows(self) -> List[FlowFingerprint]:
        """
        Get the list of flow fingerprints.

        Returns:
            List[FlowFingerprint]: List of flow fingerprints.
        """
        return self.flows
    

    def set_flows(self, flows: List[FlowFingerprint]) -> None:
        """
        Set the list of flow fingerprints.

        Args:
            flows (List[FlowFingerprint]): List of flow fingerprints.
        """
        self.flows = flows


    def add_flow(self, flow: FlowFingerprint) -> None:
        """
        Add a flow fingerprint to the list.

        Args:
            flow (FlowFingerprint): Flow fingerprint to add.
        """
        self.flows.append(flow)

    
    def find_flow(self, flow: FlowFingerprint) -> FlowFingerprint:
        """
        Find a flow fingerprint in the list.

        Args:
            flow (FlowFingerprint): Flow fingerprint to find.
        Returns:
            FlowFingerprint: Found flow fingerprint, or None if not found.
        Raises:
            ValueError: If no matching flow is found in the pattern.
        """
        i = self.flows.index(flow)
        if i != -1:
            return self.flows[i]
        else:
            raise ValueError("No matching flow found in the pattern")


    def match_flow_basic(self, flow: FlowFingerprint) -> FlowFingerprint:
        """
        Find a flow fingerprint in the list which matches the basic attributes,
        i.e. the hosts and transport protocol,
        of the given flow fingerprint.

        Args:
            flow (FlowFingerprint): Flow fingerprint to find.
        Returns:
            FlowFingerprint: Found flow fingerprint, or None if not found.
        Raises:
            ValueError: If no matching flow is found in the pattern.
        """
        for f in self.flows:
            if f.match_basic(flow):
                return f
        raise ValueError("No matching flow found in the pattern")
    

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
