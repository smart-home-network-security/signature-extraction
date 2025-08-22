## Imports
# Libraries
from __future__ import annotations
from typing import Union, Iterator
import os
import time
from ipaddress import IPv4Address
from fractions import Fraction
from json import JSONEncoder
# Package
from .Packet import Packet
from signature_extraction.application_layer import ApplicationLayer
from signature_extraction.utils import if_correct_type, policy_dict_to_other, guess_network_protocol, is_known_port, compare_hosts
from signature_extraction.utils.distance import discrete_distance, distance_hosts
from profile_translator_blocklist import translate_policy
# Logging
import importlib
import logging
module_relative_path = importlib.import_module(__name__).__name__
logger = logging.getLogger(module_relative_path)


class FlowFingerprint:
    """
    Fingerprint of a network flow,
    matching only the following attributes:
        - Source & destination hosts
        - Transport protocol
        - Fixed port (to be computed)
        - Application protocol
    """

    ## Distance metrics weights
    # Layers
    WEIGHT_NETWORK     = Fraction(1, 3)
    WEIGHT_TRANSPORT   = Fraction(1, 3)
    WEIGHT_APPLICATION = Fraction(1, 3)
    # Network layer
    WEIGHT_NETWORK_PROTOCOL = Fraction(1, 3)
    WEIGHT_HOSTS            = Fraction(2, 3)
    WEIGHT_SINGLE_HOST      = Fraction(1, 2)
    # Transport layer
    WEIGHT_TRANSPORT_PROTOCOL = Fraction(1, 3)
    WEIGHT_PORTS              = Fraction(2, 3)

    ## Policy protocols

    # Protocol names with specific cases
    PROTOCOL_NAMES = {
        "ipv4":   "IPv4",
        "ipv6":   "IPv6",
        "icmpv6": "ICMPv6",
        "coap":   "CoAP"
    }

    # Protocols grouped by layer
    PROTOCOL_LAYERS = {
        "datalink":    ["ARP"],
        "network":     ["IPv4", "IPv6"],
        "transport":   ["TCP", "UDP", "ICMP", "ICMPv6"],
        "application": ["DNS", "HTTP", "DHCP", "SSDP", "CoAP"]
    }


    @staticmethod
    def from_policy(policy: dict) -> FlowFingerprint:
        """
        Create a FlowFingerprint object from a policy dictionary.

        Args:
            policy (dict): Policy dictionary to create the FlowFingerprint from.
        Returns:
            FlowFingerprint: FlowFingerprint object created from the policy.
        """
        dict_data = {}

        # Iterate over the policy's protocols
        data_protocols = policy["protocols"]
        for protocol, attrs in data_protocols.items():

            # Convert protocol name case
            protocol = FlowFingerprint.PROTOCOL_NAMES.get(protocol.lower(), protocol.upper())

            ## Network-layer protocol
            if protocol in FlowFingerprint.PROTOCOL_LAYERS["network"]:
                # Network protocol
                dict_data["network_protocol"] = protocol
                # Source host
                policy_dict_to_other(attrs, "src", dict_data, "src")
                # Destination host
                policy_dict_to_other(attrs, "dst", dict_data, "dst")

            ## Transport-layer protocol
            elif protocol in FlowFingerprint.PROTOCOL_LAYERS["transport"]:
                # Transport protocol
                dict_data["transport_protocol"] = protocol
                # Source port
                policy_dict_to_other(attrs, "src-port", dict_data, "sport")
                # Destination port
                policy_dict_to_other(attrs, "dst-port", dict_data, "dport")

            ## Application-layer protocol
            elif protocol in FlowFingerprint.PROTOCOL_LAYERS["application"]:
                dict_data["application_layer"] = ApplicationLayer.init_protocol(attrs, protocol)

        return FlowFingerprint(dict_data)


    def __init__(self, flow_data: Union[dict, Packet, list]) -> None:
        """
        FlowFingerprint constructor.

        Args:
            flow_data (dict | Packet | list): flow fingerprint data.
        """
        # Set FlowFingerprint as bidirectional by default
        self.bidirectional = True

        self.count = 1  # Number of flows added to this FlowFingerprint

        # If given data is not a dictionary, convert it
        if isinstance(flow_data, Packet):
            flow_data = dict(flow_data)
        elif isinstance(flow_data, list):
            first_item = flow_data[0]
            if isinstance(first_item, Packet):
                flow_data = dict(first_item)
            else:
                flow_data = first_item

        ## Set attributes
        self.src = if_correct_type(flow_data["src"], str)
        self.dst = if_correct_type(flow_data["dst"], str)

        # Set network-layer protocol
        self.network_protocol = "IPv4"  # Default: IPv4
        if "network_protocol" in flow_data:
            self.network_protocol = if_correct_type(flow_data["network_protocol"], str, "IPv4")
        else:
            # Guess network protocol from hosts
            for host in (self.src, self.dst):
                try:
                    self.network_protocol = guess_network_protocol(host)
                    break
                except ValueError:
                    pass

        self.transport_protocol = if_correct_type(flow_data["transport_protocol"], str)
        self.application_layer  = flow_data.get("application_layer", None)
        if not self.application_layer:
            self.application_layer = None
 
        # Initialize ports (to be computed)
        self.ports = {}
        self._add_ports_from_dict(flow_data)
    

    def get_fixed_ports(self, match_random_ports: bool = False) -> set[(str, int)]:
        """
        Compute the fixed ports of the FlowFingerprint.

        Args:
            match_random_ports (bool): Whether to consider random ports as fixed.
                                       Optional, default is False.
        Returns:
            set[(str, int)]: Set of hosts and their fixed ports.
        """
        # Initialize fixed_ports
        fixed_ports = set()

        # Iterate over hosts and ports
        for (host, port), count in self.ports.items():

            # Current port number is considered as fixed if ...
            if (
                is_known_port(port, self.transport_protocol) or             # ... it is a well-known port
                (match_random_ports and count > 1 and count == self.count)  # ... it was used for all flows
            ):
                fixed_ports.add((host, port))

        # Return fixed ports
        return fixed_ports


    def _add_ports_from_dict(self, flow_dict: dict = {}) -> dict:
        """
        Add ports' data from a dictionary.

        Args:
            flow_dict (dict): dictionary to add ports' data from.
        Returns:
            dict: Updated ports dictionary.
        """
        # Source host & port
        src = flow_dict.get("src", None)
        sport = flow_dict.get("sport", None)
        if isinstance(src, str) and isinstance(sport, int):
            src_sport = (src, sport)
            self.ports[src_sport] = self.ports.get(src_sport, 0) + 1
        
        # Destination host & port
        dst = flow_dict.get("dst", None)
        dport = flow_dict.get("dport", None)
        if isinstance(dst, str) and isinstance(dport, int):
            dst_dport = (dst, dport)
            self.ports[dst_dport] = self.ports.get(dst_dport, 0) + 1

        return self.ports
    

    def add_ports(self, other: FlowFingerprint) -> dict:
        """
        Add ports from a given FlowFingerprint object.

        Args:
            flow_fingerprint (FlowFingerprint): FlowFingerprint object to add ports from.
        Returns:
            dict: Updated ports dictionary.
        """
        # If other object is not an FlowFingerprint, return False
        if not isinstance(other, FlowFingerprint):
            return False
        
        for (host, port), count in other.ports.items():
            try:
                h, p = next((h, p) for h, p in self.ports if compare_hosts(h, host) and p == port)
                self.ports[(h, p)] += count
            except StopIteration:
                self.ports[(host, port)] = count

        return self.ports


    def add_flow(self, flow: FlowFingerprint) -> None:
        """
        Add attributes of the given FlowFingerprint object to this FlowFingerprint.

        Args:
            flow (FlowFingerprint): FlowFingerprint object to add.
        """
        # Update attributes if needed
        self.src = flow.src if not self.src else self.src
        self.dst = flow.dst if not self.dst else self.dst
        self.transport_protocol = flow.transport_protocol if not self.transport_protocol else self.transport_protocol
        self.application_layer = flow.application_layer if not self.application_layer else self.application_layer
        self.count += flow.count
        self.add_ports(flow)

    
    def match_hosts(self, other: FlowFingerprint) -> bool:
        """
        Match FlowFingerprint objects based on source and destination hosts,
        regardless of the direction.

        Args:
            other (FlowFingerprint): FlowFingerprint to match with.
        Returns:
            bool: True if the FlowFingerprints' hosts match, False otherwise.
        """
        # If other object is not an FlowFingerprint, return False
        if not isinstance(other, FlowFingerprint):
            return False
        
        are_hosts_matching = (
            compare_hosts(self.src, other.src) and compare_hosts(self.dst, other.dst) or
            compare_hosts(self.src, other.dst) and compare_hosts(self.dst, other.src)
        )
        return are_hosts_matching
    

    def get_different_hosts(self, other: FlowFingerprint) -> set[tuple[str, str]]:
        """
        Retrieve the other FlowFingerprint's hosts
        which are different from this FlowFingerprint's hosts.

        Args:
            other (FlowFingerprint): FlowFingerprint to compare with.
        Returns:
            set[tuple[str, str]]: Set of pairs of different hosts.
        Raises:
            TypeError: If the other object is not a FlowFingerprint.
        """
        # If other object is not an FlowFingerprint, cannot compare
        if not isinstance(other, FlowFingerprint):
            raise TypeError(f"Cannot compare FlowFingerprint with {type(other)}")
        
        # Initialize hosts set
        different_hosts = set()
        
        # If the two FlowFingerprints' hosts are equivalent, return empty set
        if self.match_hosts(other):
            return different_hosts
        
        ## Hosts are not equivalent
        
        this_src_equals_other_src = compare_hosts(self.src, other.src)
        this_src_equals_other_dst = compare_hosts(self.src, other.dst)
        this_dst_equals_other_src = compare_hosts(self.dst, other.src)
        this_dst_equals_other_dst = compare_hosts(self.dst, other.dst)

        # Compare all pairs of hosts
        if this_src_equals_other_src and not this_dst_equals_other_dst:
            different_hosts.add((self.dst, other.dst))
        elif this_src_equals_other_dst and not this_dst_equals_other_src:
            different_hosts.add((self.dst, other.src))
        elif this_dst_equals_other_src and not this_src_equals_other_dst:
            different_hosts.add((self.src, other.dst))
        elif this_dst_equals_other_dst and not this_src_equals_other_src:
            different_hosts.add((self.src, other.src))
        else:
            # General case if both hosts are different
            different_hosts.add((self.src, other.src))
            different_hosts.add((self.dst, other.dst))


        return different_hosts
    

    def match_ports(self, other: FlowFingerprint, match_random_ports: bool = False) -> bool:
        """
        Check if the ports of given FlowFingerprint object,
        match the ports of this FlowFingerprint object.

        Args:
            other (FlowFingerprint): FlowFingerprint to match with.
            match_random_ports (bool): Whether to consider random ports as matching.
                                       Optional, default is False.
        Returns:
            bool: True if the given FlowFingerprints' ports match, False otherwise.
        """
        # If other object is not an FlowFingerprint, return False
        if not isinstance(other, FlowFingerprint):
            return False
        
        for (host, port) in other.ports.keys():
            try:
                h, p = next((h, p) for h, p in self.ports if compare_hosts(h, host))
                if (h, p) in self.get_fixed_ports(match_random_ports) and port != p:
                    return False
            except StopIteration:
                return False
        
        return True
    

    def get_different_ports(self, other: FlowFingerprint) -> set[tuple[str, int, str, int]]:
        """
        Compute the pairs of hosts and ports which are different
        between this and the other FlowFingerprint objects.
        The return value is defined as follows:
            {
              (host1, port1, host2, port2),
              (host2, port2, host1, port1),
              ...
            }

        Args:
            other (FlowFingerprint): FlowFingerprint to compare with.
        Returns:
            set[tuple[str, int, str, int]]: Set of pairs of different hosts and ports.
        Raises:
            TypeError: If the other object is not a FlowFingerprint.
        """
        # If other object is not an FlowFingerprint, cannot compare
        if not isinstance(other, FlowFingerprint):
            raise TypeError(f"Cannot compare FlowFingerprint with {type(other)}")
        
        # Initialize ports set
        different_ports = set()

        # If the two FlowFingerprints' ports are equivalent, return empty set
        if self.match_ports(other):
            return different_ports

        ## Ports are not equivalent

        this_fixed_ports  = self.get_fixed_ports()
        other_fixed_ports = other.get_fixed_ports()
        ports_both = this_fixed_ports.intersection(other_fixed_ports)
        ports_this_only = this_fixed_ports - ports_both
        ports_other_only = other_fixed_ports - ports_both

        # First pass
        # Find different ports which pertain to the same host
        ports_this_remaining = set()
        ports_other_remaining = set()
        for (this_host, this_port) in ports_this_only:
            try:
                other_host, other_port = next((h, p) for h, p in ports_other_only if compare_hosts(h, this_host) and p != this_port)
                different_ports.add((this_host, this_port, other_host, other_port))
            except StopIteration:
                ports_this_remaining.add((this_host, this_port))
                ports_other_remaining.add((other_host, other_port))


        # Second pass
        # Extract remaining ports, which do not pertain to the same host
        for (this_host, this_port) in ports_this_remaining:
            try:
                other_host, other_port = next((h, p) for h, p in ports_other_remaining if p != this_port)
                different_ports.add((this_host, this_port, other_host, other_port))
            except StopIteration:
                continue

        return different_ports

    
    def match_flow(self, other: FlowFingerprint, match_random_ports: bool = False) -> bool:
        """
        Compare the given FlowFingerprint with this FlowFingerprint,
        based on the following attributes:
            - Hosts (in any direction)
            - Fixed port
            - Transport protocol
            - Application layer protocol

        Args:
            other (FlowFingerprint): FlowFingerprint to match with.
            match_random_ports (bool): Whether to consider random ports in flow matching.
                                       Optional, default is False.
        Returns:
            bool: True if the given FlowFingerprint matches, False otherwise.
        """
        # If other object is not a FlowFingerprint, return False
        if not isinstance(other, FlowFingerprint):
            return False
        
        # If other object is a FlowFingerprint, compare attributes:
        are_flow_matching = (
            # Network protocol
            self.network_protocol == other.network_protocol and
            # Hosts (in any direction)
            self.match_hosts(other) and
            # Fixed port
            self.match_ports(other, match_random_ports) and
            # Transport protocol
            self.transport_protocol == other.transport_protocol and
            # Application layer protocol
            self.application_layer == other.application_layer
        )
        return are_flow_matching


    def __repr__(self) -> str:
        """
        String representation of a FlowFingerprint object.

        Returns:
            str: String representation of a FlowFingerprint object.
        """
        fixed_ports = self.get_fixed_ports()

        ## Hosts
        # Source
        s = f"{self.src}"
        for host, port in fixed_ports:
            if host == self.src:
                s += f":{port}"
        s += " <-> "
        # Destination
        s += f"{self.dst}"
        for host, port in fixed_ports:
            if host == self.dst:
                s += f":{port}"

        ## Protocol(s)
        # Transport layer
        s += f" [{self.transport_protocol}"
        # Application layer
        if self.application_layer is not None and self.application_layer != self.transport_protocol:
            s += f" / {self.application_layer}"
        s += "]"

        return s

    
    def __iter__(self) -> Iterator:
        """
        Iterate over the FlowFingerprint attributes.

        Returns:
            Iterator: Iterator over the packet fingerprint attributes.
        """

        ### NETWORK LAYER ###

        # Protocol
        yield "network_protocol", self.network_protocol

        ## Hosts
        # Source
        yield "src", self.src
        # Destination
        yield "dst", self.dst


        ### TRANSPORT LAYER ###

        # Transport-layer protocol
        yield "transport_protocol", self.transport_protocol

        ## Ports
        fixed_ports = self.get_fixed_ports()

        # Source port
        for host, port in fixed_ports:
            if host == self.src:
                yield "sport", port
        else:
            yield "sport", None
        
        # Destination port
        for host, port in fixed_ports:
            if host == self.dst:
                yield "dport", port
        else:
            yield "dport", None


        ### APPLICATION LAYER ###
        # Application-layer protocol
        if isinstance(self.application_layer, ApplicationLayer):
            yield "application_layer", tuple(self.application_layer)
        else:
            yield "application_layer", None


    def __eq__(self, other: FlowFingerprint) -> bool:
        """
        Check if two FlowFingerprint objects are equivalent.

        Args:
            other (FlowFingerprint): Other FlowFingerprint object.
        Returns:
            bool: True if the two FlowFingerprints are equivalent, False otherwise.
        """
        return self.match_flow(other, match_random_ports=False)

        
    def __hash__(self) -> int:
        """
        Hash function for FlowFingerprint objects,
        based on the attributes of the FlowFingerprint.

        Returns:
            int: Hash value of the FlowFingerprint object.
        """
        return hash(tuple(self))


    def get_id(self) -> str:
        """
        Generate an identifier for this FlowFingerprint.

        Returns:
            str: Identifier for this FlowFingerprint.
        """
        id = f"{self.src}-{self.dst}_{self.transport_protocol}"
        fixed_ports = self.get_fixed_ports()

        # Hosts & ports
        if fixed_ports:
            is_fixed_port = False
            for host, port in fixed_ports:
                if host == self.src:
                    is_fixed_port = True
                    id += f"_src_{port}"
                elif host == self.dst:
                    is_fixed_port = True
                    id += f"_dst_{port}"
            if not is_fixed_port:
                id += f"_{port}"
            
        # Application layer
        if self.application_layer is not None:
            id += f"_{repr(self.application_layer)}"
        
        return id

    
    def get_unique_id(self) -> str:
        """
        Generate a unique identifier for this FlowFingerprint,
        based on the current time.

        Returns:
            str: Unique identifier for this FlowFingerprint.
        """
        return f"{self.get_id()}_{int(time.time())}"
    

    def is_in_list(self, flows: list[FlowFingerprint]) -> bool:
        """
        Check if this FlowFingerprint is in a list of FlowFingerprint objects.

        Args:
            flows (list[FlowFingerprint]): List of FlowFingerprint objects.
        Returns:
            bool: True if this FlowFingerprint is in the list, False otherwise.
        """
        # Iterate over the list of FlowFingerprint objects
        for flow in flows:
            if self.match_flow(flow):
                return True
        
        return False


    def extract_policy(self, ipv4: IPv4Address) -> dict:
        """
        Extract a profile-compliant policy from this FlowFingerprint.
        
        Args:
            ipv4 (IPv4Address): IP address of the device.
        Returns:
            dict: Policy extracted from the FlowFingerprint.
        """
        # Hosts
        src_ip = "self" if self.src == str(ipv4) else self.src.replace("*","$")
        dst_ip = "self" if self.dst == str(ipv4) else self.dst.replace("*","$")
        policy = {
            "protocols": {
                self.network_protocol.lower(): {"src": src_ip, "dst": dst_ip}
            }
        }

        # Protocols
        protocol = self.transport_protocol.lower()
        fixed_ports = self.get_fixed_ports()
        if fixed_ports:
            is_fixed_port = False
            for host, port in fixed_ports:
                if host == self.src:
                    is_fixed_port = True
                    if protocol not in policy["protocols"]:
                        policy["protocols"][protocol] = {}
                    policy["protocols"][protocol]["src-port"] = port
                elif host == self.dst:
                    is_fixed_port = True
                    if protocol not in policy["protocols"]:
                        policy["protocols"][protocol] = {}
                    policy["protocols"][protocol]["dst-port"] = port
            if not is_fixed_port:
                policy["protocols"][protocol] = {}
        else:
            policy["protocols"][protocol] = {}

        # Application layer protocol
        if self.application_layer is not None:
            app_protocol = self.application_layer.get_protocol_name().lower()
            attrs = dict(self.application_layer)
            if "domain-name" in attrs:
                attrs["domain-name"] = attrs["domain-name"].replace("*","$")
            policy["protocols"][app_protocol] = attrs
        
        policy["bidirectional"] = self.bidirectional

        return policy


    def translate_to_firewall(self, device_name: str, ipv4: IPv4Address, output_dir: str = os.getcwd()) -> None:
        """
        Translate the FlowFingerprint to a firewall rule.

        Args:
            device_name (str): Name of the device.
            ipv4 (IPv4Address): IP address of the device.
            output_dir (str): Output directory. Optional, defaults to the current working directory.
        """
        # Validate output directory
        if not os.path.isdir(output_dir):
            logger.warning(f"Output directory {output_dir} does not exist. Using current directory.")
            output_dir = os.getcwd()
        
        # Device metadata
        device = {
            "name": device_name,
            "ipv4": str(ipv4)
        }

        policy = self.extract_policy(ipv4)
        translate_policy(device, policy, output_dir=output_dir)



    ##### DISTANCE METRICS #####


    def _distance_network_layer(self, other: FlowFingerprint) -> Fraction:
        """
        Compute distance between this and another FlowFingerprint's network layer attributes,
        i.e. network protocol, source and destination hosts.

        Args:
            other (FlowFingerprint): Other FlowFingerprint object.
        Returns:
            Fraction: Distance between this and the other FlowFingerprint's network layer attributes.
        """
        # Network protocol
        distance_protocol = discrete_distance(self.network_protocol, other.network_protocol)


        ### Hosts
        
        # Source
        distance_src_src = distance_hosts(self.src, other.src)
        distance_src_dst = distance_hosts(self.src, other.dst)
        is_same_direction = False
        if distance_src_src <= distance_src_dst:
            distance_src = distance_src_src
            is_same_direction = True
        else:
            distance_src = distance_src_dst
        
        # Destination
        if is_same_direction:
            distance_dst = distance_hosts(self.dst, other.dst)
        else:
            distance_dst = distance_hosts(self.dst, other.src)


        # Return final result
        return FlowFingerprint.WEIGHT_NETWORK_PROTOCOL * distance_protocol + FlowFingerprint.WEIGHT_HOSTS * FlowFingerprint.WEIGHT_SINGLE_HOST * (distance_src + distance_dst)
    

    def _distance_ports(self, other: FlowFingerprint) -> Fraction:
        """
        Compute distance metric between this and another FlowFingerprint's fixed ports, defined as follows:
        1 - (# identical ports / # max ports)

        Args:
            other (FlowFingerprint): Other FlowFingerprint object.
        Returns:
            Fraction: Distance between this and the other FlowFingerprint's fixed ports.
        """
        self_fixed_ports = self.get_fixed_ports()
        other_fixed_ports = other.get_fixed_ports()

        # Count identical ports
        n_identical_ports = 0
        for (host, port) in self_fixed_ports:
            try:
                next((h, p) for h, p in other_fixed_ports if port == p)
            except StopIteration:
                continue
            else:
                n_identical_ports += 1
        
        # Compute distance
        n_max_ports = max(len(self_fixed_ports), len(other_fixed_ports))
        distance = Fraction(1) - Fraction(n_identical_ports, n_max_ports)
        return distance
    

    def _distance_transport_layer(self, other: FlowFingerprint) -> Fraction:
        """
        Compute distance between this and another FlowFingerprint's transport layer attributes,
        i.e. transport protocol, source and destination ports.

        Args:
            other (FlowFingerprint): Other FlowFingerprint object.
        Returns:
            Fraction: Distance between this and the other FlowFingerprint's transport layer attributes.
        """
        # Transport protocol
        distance_protocol = discrete_distance(self.transport_protocol, other.transport_protocol)

        # Fixed ports
        distance_ports = self._distance_ports(other)

        # Return final result
        return FlowFingerprint.WEIGHT_TRANSPORT_PROTOCOL * distance_protocol + FlowFingerprint.WEIGHT_PORTS * distance_ports
    

    def _distance_application_layer(self, other: FlowFingerprint) -> Fraction:
        """
        Compute distance between this and another FlowFingerprint's application layer attributes
        (application protocol dependent).

        Args:
            other (FlowFingerprint): Other FlowFingerprint object.
        Returns:
            Fraction: Distance between this and the other FlowFingerprint's application layer attributes.
        """
        # If one of the two objects does not have an application layer,
        # return maximal distance (1)
        if self.application_layer is None or other.application_layer is None:
            return Fraction(1)

        return self.application_layer.compute_distance(other.application_layer)


    def compute_distance(self, other: FlowFingerprint) -> Fraction:
        """
        Compute distance metric between this and another FlowFingerprint object,
        taking into account the network, transport and application layers.

        Args:
            other (FlowFingerprint): Other FlowFingerprint object.
        Returns:
            Fraction: Distance between this and the other FlowFingerprint object.
        """
        distance = (
            FlowFingerprint.WEIGHT_NETWORK * self._distance_network_layer(other) +
            FlowFingerprint.WEIGHT_TRANSPORT * self._distance_transport_layer(other) +
            FlowFingerprint.WEIGHT_APPLICATION * self._distance_application_layer(other)
        )

        return distance
    

    def find_closest_flow(self, flows_other: list[FlowFingerprint]) -> FlowFingerprint:
        """
        Search a list of FlowFingerprint objects for the one minimizing the distance metric
        compared to this FlowFingerprint object.

        Args:
            flows_other (list[FlowFingerprint]): List of FlowFingerprint objects to compare with.
        Returns:
            FlowFingerprint: Closest FlowFingerprint object.
        """
        # Given list is empty, raise ValueError
        if not flows_other:
            raise ValueError("Given list is empty.")
        
        # Initialize closest flow
        flow_closest = flows_other[0]
        distance_min = self.compute_distance(flow_closest)

        # Iterate over the list of FlowFingerprint objects
        for flow_other in flows_other:
            distance = self.compute_distance(flow_other)
            if distance < distance_min:
                distance_min = distance
                flow_closest = flow_other
        
        return flow_closest



class FlowFingerprintJsonEncoder(JSONEncoder):
    """
    JSON encoder for FlowFingerprint objects.
    Converts FlowFingerprint objects to JSON-serializable dictionaries,
    i.e. its representative policy.
    """

    def __init__(self, ipv4: IPv4Address, *args, **kwargs) -> None:
        """
        Constructor.
        Provides the IPv4 address of the device to the JSON encoder.
        """
        super().__init__(*args, **kwargs)
        self.ipv4 = ipv4


    def default(self, obj):
        """
        Default JSON encoder for FlowFingerprint objects.

        Args:
            obj: Object to encode.
        Returns:
            dict: JSON-serializable dictionary.
        """
        # If the object is not a FlowFingerprint, use the default encoder
        if not isinstance(obj, FlowFingerprint):
            return super().default(obj)
        
        # Extract the FlowFingerprint's policy,
        # and use it as the JSON-serializable dictionary
        return obj.extract_policy(self.ipv4)
