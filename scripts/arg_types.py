from constants import epoch_max
import argparse
import os


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


def directory(raw_path: str) -> str:
    """
    Argparse type for an existing directory path.

    :param arg: given argument
    :return: absolute path to an existing directory
    :raises argparse.ArgumentTypeError: if the given argument is not an existing directory
    """
    if not os.path.isdir(raw_path):
        raise argparse.ArgumentTypeError(f'"{raw_path}" is not an existing directory')
    return os.path.abspath(raw_path)
