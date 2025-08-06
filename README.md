# Extraction of network signatures of IoT events

![GitHub License](https://img.shields.io/github/license/smart-home-network-security/signature-extraction)
![GitHub language count](https://img.shields.io/github/languages/count/smart-home-network-security/signature-extraction)


`signature-extraction` is a Python package which extracts network pattern signatures,
i.e. a sequence of network flows, from network traffic related to IoT (smart home) events.


## Glossary

- **(User) event**: interaction with an IoT device that triggers a change in its state, and the associated network traffic.
- **(Network) packet**: unit of data transmitted over a network.
- **(Network) 5-tuple**: set of five values that uniquely identify a network flow: source IP address, source port, destination IP address, destination port, and layer 4 protocol.
- **(Network) flow**: time-ordered sequence of network packets having the same network 5-tuple.
- **Flow Fingerprint**: set of relevant packet features which identify a packet / flow. Includes part of, or all, the packet's 5-tuple, as well as other protocol-dependent features, e.g.:
    - HTTP: method, URI
    - DNS: query name, query type
    - DHCP: message type
    - CoAP: message type, method, URI 
- **Network pattern**: sequence of flows / flow fingerprints that repeatedly occurs together, potentially indicating a specific user event.
- **(Event) signature**: network pattern that uniquely identifies a user event.


## Features


This package is split into three main modules,
each responsible for part of the pipeline:
- [`pkt_extraction`](signature_extraction/pkt_extraction.py): read PCAP files and extract packets.
- [`flow_grouping`](signature_extraction/flow_grouping.py): group packets per flow and generate the flow fingerprint.
- [`event_signature_extraction`](signature_extraction/event_signature_extraction.py): extract an event signature from a set of flow fingerprints.

### Translation to firewall

Additionally, flow fingerprints can be converted to configuration scripts for [@fdekeers](https://github.com/fdekeers)'s [smart-home-firewall](https://github.com/smart-home-network-security/smart-home-firewall), or to a YAML profile exhaustively describing such configuration.


## Installation

### From PyPI

```bash
pip install signature-extraction
```

[PyPI project page](https://pypi.org/project/signature-extraction)

### From local source

Clone the repository and install the dependencies using `pip`.

```bash
git clone https://github.com/smart-home-network-security/signature-extraction.git
cd signature-extraction
pip install -r requirements.txt
pip install .
```

## License

This project is licensed under the GPL-3.0 License -- see the [LICENSE](LICENSE) file for details.

## Acknowledgements

This work is part of the [Smart Home Network Security](https://github.com/smart-home-network-security) research project made by [@fdekeers](https://github.com/fdekeers) and UCLouvain.

It was partially authored by [@remivanboxem](https://github.com/remivanboxem) during his internship at UCLouvain.
