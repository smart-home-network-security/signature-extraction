from constants import epoch_max
import argparse


def timestamp(arg: str) -> int:
    """
    Argparse type for a Unix epoch timestamp,
    i.e. an integer between 0 and 2,147,483,647.

    :param arg: given argument
    :return: Unix timestamp, as an integer
    :raises argparse.ArgumentTypeError: if the given argument is not a valid Unix timestamp
    """
    timestamp = int(arg)
    if timestamp < 0 or timestamp > epoch_max:
        raise argparse.ArgumentTypeError(f"{timestamp} is not a valid Unix timestamp")
    return timestamp
