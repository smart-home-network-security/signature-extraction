"""
Translate a NetworkPattern object to NFTables / NFQueue configuration files.
"""
from .network.NetworkPattern import NetworkPattern


def pattern_to_firewall(pattern: NetworkPattern) -> None:
    """
    Translate a NetworkPattern object to NFTables / NFQueue configuration files.
    
    Args:
        pattern_file (str): file containing the NetworkPattern object.
    """
    # TODO
    pass


def pattern_csv_to_firewall(pattern_csv_path: str) -> None:
    """
    Translate a CSV file containing a NetworkPattern object to NFTables / NFQueue configuration files.

    Args:
        pattern_csv_path (str): CSV file containing the NetworkPattern object.
    """
    pattern = NetworkPattern.load_from_csv(pattern_csv_path)
    pattern_to_firewall(pattern)
