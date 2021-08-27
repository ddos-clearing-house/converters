from typing import Set, Tuple
import json
import argparse
import logging
import os
import sys

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel('CRITICAL')
HANDLER = logging.StreamHandler()
HANDLER.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
LOGGER.addHandler(HANDLER)


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="Simple iptables converter", usage='%(prog)s [options]')
    parser.add_argument("--version", help="print version and exit", action="store_true")
    parser.add_argument("-v", "--verbose", help="print info msg", action="store_true")
    parser.add_argument("-d", "--debug", help="print debug info", action="store_true")
    parser.add_argument('-f', '--fingerprint', required=True, help="fingerprint json file")
    return parser


def load_fingerprint(path: os.PathLike) -> dict:
    if not os.path.exists(path):
        sys.exit(IOError(f"File '{path}' does not exist."))

    with open(path, 'r') as file:
        json_content: dict = json.load(file)

    return json_content


def extract_ips_ports(fingerprint: dict) -> Tuple[Set[str], Set[int]]:
    try:
        attack_vectors = fingerprint['attack_vector']
    except KeyError:
        LOGGER.critical("Fingerprint not compatible: missing attack_vector key.")
        sys.exit(-1)
    else:
        ip_set, port_set = set(), set()
        for vector in attack_vectors:
            ip_set.update(vector['src_ips'])
            port_set.update(vector['dstport'])
        LOGGER.info(f"{len(ip_set)} IP address{'es'*(len(ip_set) > 1)} found.")
        LOGGER.info(f"{len(port_set)} port{'s' * (len(port_set) > 1)} found.")
        return ip_set, port_set


def generate_iptables_rules(fingerprint_name: dict, ips: Set[str], ports: Set[int]) -> str:
    filename = fingerprint_name[:15] + ".iptables"
    with open(filename, "w") as myfile:
        myfile.write("#!/bin/sh\n")

        myfile.write(f"sudo ipset create {fingerprint_name[:15]} hash:net\n")
        for ip in ips:
            myfile.write(f"sudo ipset add {fingerprint_name[:15]} {ip}\n")
        string_ports = ','.join([str(p) for p in ports])
        myfile.write(f"sudo iptables -A INPUT -p tcp -m multiport --destination-ports {string_ports} -m set "
                     f"--set {fingerprint_name[:15]} src -j DROP\n")  # TODO ports only for UDP TCP
    return filename


if __name__ == '__main__':
    args = argument_parser().parse_args()
    if args.verbose:
        LOGGER.setLevel('INFO')
    if args.debug:
        LOGGER.setLevel('DEBUG')

    _fingerprint = load_fingerprint(args.fingerprint)
    _ips, _ports = extract_ips_ports(_fingerprint)
    generate_iptables_rules(args.fingerprint, _ips, _ports)
