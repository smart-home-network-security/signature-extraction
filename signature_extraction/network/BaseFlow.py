from __future__ import annotations


class BaseFlow:
    """
    Reduced representation of a network flow, containing the following attributes:
        - Source & destination hosts
        - Transport protocol
    """

    def __init__(self) -> None:
        """
        Abstract flow constructor.
        Initialize attributes.
        """
        self.src                  = None
        self.dst                  = None
        self.transport_protocol   = None
        self.bidirectional        = True

    
    def match_host(self, other: BaseFlow) -> bool:
        """
        Match AbstractFlows based on source and destination hosts,
        regardless of the direction.

        Args:
            other (BaseFlow): BaseFlow to match with.
        Returns:
            bool: True if the AbstractFlows' hosts match, False otherwise.
        """
        # If other object is not an BaseFlow, return False
        if not isinstance(other, BaseFlow):
            return False
        
        return (
            (self.src == other.src and self.dst == other.dst) or
            (self.src == other.dst and self.dst == other.src)
        )


    def __eq__(self, other: BaseFlow) -> bool:
        """
        Compare two BaseFlow objects.

        Args:
            other (BaseFlow): Abstract flow to compare with.
        Returns:
            bool: True if the flow fingerprints are equal, False otherwise.
        """
        # If other object is not an BaseFlow, return False
        if not isinstance(other, BaseFlow):
            return False
        
        # If other object is an BaseFlow, compare attributes
        return (
            self.match_host(other)
            and self.transport_protocol == other.transport_protocol
        )
