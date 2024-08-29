# signature-extraction

![GitHub License](https://img.shields.io/github/license/smart-home-network-security/signature-extraction)
![GitHub language count](https://img.shields.io/github/languages/count/smart-home-network-security/signature-extraction)


`signature-extraction` is a Python library for extracting signatures from network traffic. It is designed to be used in the context of smart home network security.

## Features

This library is composed of three monolithic scripts that can be used independently. The scripts are:

- Read pcap files and extract headers from packets (`packet-translator.py`) ;
- Merge packets into flows (`stream-identifier.py`) ;
- Extract the recurring patterns from the flows (`signature-extractor.py`) ;
- Generate profile.yaml files containing the extracted signatures (WIP).

All the scripts can be used as standalone scripts, arguments can be passed to them using the command line.

`profile.yaml` files generated are the one compatible with the [smart-home-firewall](https://github.com/smart-home-network-security/smart-home-firewall) by @fdekeers. 

## Installation

**Requirements:** Python 3.8 or higher, `pip` and `git`.

Clone the repository and install the dependencies using [pip](https://pip.pypa.io/en/stable/).

```bash
git clone https://github.com/smart-home-network-security/smart-home-firewall
cd smart-home-firewall
pip install -r requirements.txt
```

## Usage

The library can be used as a standalone script or as a Python library.

```bash
python3 ./scripts/main.py DEVICE IPV4 PCAP [PCAP ...] [-o OUTPUT_DIR] [-h]
```
- Positional arguments:
  - `DEVICE`: name of the device to analyze the traffic from.
  - `IPV4`: IPv4 address of the device.
  - `PCAP`: path(s) to the PCAP file(s) to analyze.
- Optional arguments:
  - `-o OUTPUT_DIR`: path to the output directory.
    - If not specified, the working directory is used.
  - `-h`: display the help message.


This folder will be used to store the extracted signatures and all the intermediate files. It should be readable and writable for the user running the script.

### Interpreting the results

```
Pattern X: IP Addresses: ('hosta.com', 'hostb.com')
Protocol: TCP
Ports: [(443, {'number': 2, 'host': ['hostb.com']}), (48597, {'number': 1, 'host': ['hosta.com']}), (54457, {'number': 1, 'host': ['hosta.com']})]
Fixed port: 443 -> ['hostb.com']
Application Data: {'Length': {9608: 1, 9635: 1}, 'ApplicationSpecific': {'https': 2}, 'nbPacket': {22: 1, 24: 1}}
```

- `Pattern X` is the signature number.
- `IP Addresses` are the IP addresses involved in the signature.
- `Protocol` is the protocol used in the signature.
- `Ports` are the ports used in the signature with the number of packets and the hostnames. By default, it will only show the three most used ports for each host (usually, one of them is fixed).
- `Most Used Port` is the port most used in the signature. Useful to identify the application or when the port is not standard.
- `Application Data` contains the length of the packets, the application specific data and the number of packets.

*Possible improvements: make the output more readable, add more information about the signature.*

The profile.yaml is generated in the same folder as the pcap file. It contains the extracted signatures but can also provide incorrect signatures. It is recommended to check the generated profile.yaml file before using it ***and*** match the given information with those given in the terminal after the script execution.

> [!TIP]
> You can find the output of the script also in the pattern.txt file in the same folder as the pcap file.

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## Project Status

This work is part of the [Smart Home Network Security](https://github.com/smart-home-network-security) research project made by @fdekeers and UCLouvain.