from typing import List
from .FlowFingerprint import FlowFingerprint


class EventSignature:
    """
    Network signature of a user event,
    i.e. list of network flows descrbing the event.
    """

    def __init__(self, flows: List[FlowFingerprint]) -> None:
        """
        Event signature constructor.

        Args:
            flows (List[FlowFingerprint]): List of flow fingerprints.
        """
        self.flows = flows
    

    def __repr__(self) -> str:
        """
        String representation of an EventSignature object.

        Returns:
            str: String representation of an EventSignature object.
        """
        return ", ".join([f"<{flow.str_base()}>" for flow in self.flows])
