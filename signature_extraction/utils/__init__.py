from .packet_utils import (
    DnsRtype, 
    DnsTableKeys,
    if_correct_type,
    policy_dict_to_other,
    is_ip_address,
    guess_network_protocol,
    is_known_port,
    compare_domain_names,
    compare_hosts,
    get_wildcard_subdomain,
    should_skip_pkt,
    get_last_layer,
    extract_domain_names,
    get_domain_name_from_ip
)
