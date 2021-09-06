from typing import Set, Tuple, Optional
import json
import argparse
import logging
import os
import sys
from pathlib import Path

VERSION = '2.0'
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
    parser.add_argument('-f', '--fingerprint', help="fingerprint json file")
    parser.add_argument('-e', '--enable', help="Automatically enable the generated iptables rules", action='store_true')
    return parser


def load_fingerprint(path: os.PathLike) -> dict:
    if not os.path.exists(path):
        sys.exit(IOError(f"File '{path}' does not exist."))

    with open(path, 'r') as file:
        json_content: dict = json.load(file)

    return json_content


def extract_ips_ports_protos(fingerprint: dict) -> Tuple[Set[str], Set[int], Set[str]]:
    try:
        attack_vectors = fingerprint['attack_vector']
    except KeyError:
        LOGGER.critical("Fingerprint not compatible: missing attack_vector key.")
        sys.exit(-1)
    else:
        ip_set, port_set, proto_set = set(), set(), set()
        for vector in attack_vectors:
            ip_set.update(vector['src_ips'])
            try:
                proto_set.update(vector['ip_proto'])
            except KeyError:
                LOGGER.info("No protocols found in fingerprint.")
            try:
                port_set.update(vector['dstport'])
            except KeyError:
                LOGGER.info("No ports found in fingerprint.")
        LOGGER.info(f"{len(ip_set)} IP address{'es' * (len(ip_set) > 1)} found.")
        LOGGER.info(f"{len(port_set)} port{'s' * (len(port_set) > 1)} found.")
        return ip_set, port_set, proto_set


def generate_iptables_rules(fingerprint_name: dict, ips: Set[str], ports: Set[int], proto: Optional[str]) -> None:
    directory = Path(fingerprint_name[:15])
    directory.mkdir(parents=True, exist_ok=True)
    # Write executable instruction files for iptables
    with open(directory / 'enable_rule', "w") as enable, open(directory / 'disable_rule', 'w') as disable:
        enable.write("#!/bin/sh\n")
        disable.write("#!/bin/sh\n")

        enable.write(f"sudo ipset create {fingerprint_name[:15]} hash:ip -!\n")
        for ip in ips:
            enable.write(f"sudo ipset add {fingerprint_name[:15]} {ip}\n")
        LOGGER.info(f'blocking {len(ips)} IP addresses.')
        protocol_flag = f'-p {proto.lower()}' if proto.lower() in ('tcp', 'udp', 'icmp') else ''
        if protocol_flag:
            LOGGER.info(f'blocking on protocol: {proto}')
        ports_flag = ('-m multiport --destination-ports ' + ','.join([str(p) for p in ports])) \
            if len(ports) > 0 and proto.lower() in ('tcp', 'udp') else ''
        if ports_flag:
            LOGGER.info(f'blocking on ports: {ports}')
        for method in ('INPUT', 'FORWARD'):
            enable.write(f"sudo iptables -I {method} {protocol_flag} {ports_flag} -m set "
                         f"--match-set {fingerprint_name[:15]} src -j DROP\n")
            disable.write(f"sudo iptables -D {method} {protocol_flag} {ports_flag} -m set "
                          f"--match-set {fingerprint_name[:15]} src -j DROP\n")
        disable.write(f"sudo ipset destroy {fingerprint_name[:15]}\n")
        enable.write(f'''echo "Enabled iptables blocking rules for fingerprint '{fingerprint_name}'"\n''')
        disable.write(f'''echo "Disabled iptables blocking rules for fingerprint '{fingerprint_name}'"\n''')
    # Make executable
    os.chmod(directory / 'enable_rule', 0o775)
    os.chmod(directory / 'disable_rule', 0o775)


if __name__ == '__main__':
    args = argument_parser().parse_args()
    if args.version:
        print(f"Converter version [{VERSION}]")
        sys.exit()
    if args.verbose:
        LOGGER.setLevel('INFO')
    if args.debug:
        LOGGER.setLevel('DEBUG')

    if not args.fingerprint:
        sys.exit("Please provide a DDoS fingerprint with '-f <path>'.")
    _fingerprint = load_fingerprint(args.fingerprint)
    _ips, _ports, _protos = extract_ips_ports_protos(_fingerprint)
    _proto = _protos.pop() if len(_protos) == 1 else None
    generate_iptables_rules(args.fingerprint, _ips, _ports, _proto)
    print(f"Iptables rules generated and saved in directory '{args.fingerprint[:15]}'")
    if args.enable:
        os.system(f'./{args.fingerprint[:15]}/enable_rule')
