import argparse
import ipaddr
import logging
import os
import signal
import sys
import pandas as pd


def setup(program_name):
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s:\n%(message)s\n'
    )
    handler.setFormatter(formatter)
    root.addHandler(handler)
    signal.signal(signal.SIGINT, signal_handler)
    parser = argparse.ArgumentParser(
        prog=program_name,
        usage='python3 %(prog)s [options]'
    )
    parser.add_argument(
        '-f',
        '--fingerprint',
        required=True,
        help='fingerprint json file'
    )
    parser.add_argument(
        '-u',
        '--misp_url',
        default='https://misp.url/',
        help='URL of the MISP instance where to publish'
    )
    parser.add_argument(
        '-k',
        '--misp_key',
        default='misp automation key',
        help='API key of the user of the MISP instance where to publish'
    )
    parser.add_argument(
        '-d',
        '--distribution',
        default=1,
        type=int,
        help='The distribution level setting used for the attributes and for t'
             'he newly created event, if relevant. [0-3].'
    )
    parser.add_argument(
        '-i',
        '--event_info',
        default='Test DDoS event',
        help='Used to populate the event info field, which is the event name i'
             'n MISP'
    )
    parser.add_argument(
        '-a',
        '--analysis_level',
        default=2,
        type=int,
        help='The analysis level of the newly created event, if applicable. [0'
             '-2]'
    )
    parser.add_argument(
        '-t',
        '--threat_level',
        default=2,
        type=int,
        help='The threat level ID of the newly created event, if applicable. ['
             '1-4]'
    )
    parser.add_argument(
        '-s',
        '--subnets',
        action='store_true',
        help='add subnets as attributes instead of ips'
    )
    parser.add_argument(
        '-g',
        '--sharing_group',
        default='Concordia Anti-DDoS Pilot IT',
        help='Group used to share the event on MISP'
    )
    args = parser.parse_args()
    if not os.path.exists(args.fingerprint):
        logging.critical('File {} is not readble.'.format(args.fingerprint))
        sys.exit(1)
    return args


def signal_handler(sig, frame):
    logging.debug('Ctrl+C detected.')
    sys.exit(0)


def smart_aggregate(df):
    grouped = df.groupby('src_net')['ip']
    all_networks = []
    for name, group in grouped:
        if len(group) > 1:
            ip_lst = sorted(group.reset_index()['ip'].to_list())
            lowest_ip = ip_lst[0]  
            highest_ip = ip_lst[-1] 
            lst_with_two_elements = []
            for i in range(0, len(ip_lst), 2):
                lst_with_two_elements.append(ip_lst[i: i + 2])
            for sub_lst in lst_with_two_elements:
                if ((len(sub_lst)) % 2) == 0:
                    lowest_ip = sub_lst[0]
                    highest_ip = sub_lst[1]
                    mask_length = ipaddr._get_prefix_length(
                        int(lowest_ip),
                        int(highest_ip),
                        lowest_ip.max_prefixlen
                    )
                    network_ip = ipaddr.IPNetwork('{}/{}'.format(
                        lowest_ip,
                        mask_length
                    )).network
                    network = ipaddr.IPNetwork(
                        '{}/{}'.format(network_ip, mask_length),
                        strict=True
                    )
                    all_networks.append(network)
                else:
                    network = ipaddr.IPNetwork(
                        '{}/{}'.format(sub_lst[0], 32),
                        strict=True
                    )
                    all_networks.append(network)
    return all_networks


def convert_tcp_flags(hex_num):
    try:
        hex_num = int(hex_num[0], 0)
        hex_num = f'0b{hex_num:08b}'
        hex_num = hex_num[4:]
    except Exception:
        return None
    flags_dict = {
        0: 'U',  # URG
        1: 'A',  # ACK
        2: 'P',  # PSH
        3: 'R',  # RST
        4: 'S',  # SYN
        5: 'F',  # FIN
    }
    detected_flags = ([pos for pos, char in enumerate(hex_num) if char == '1'])
    return list((pd.Series(detected_flags)).map(flags_dict))
