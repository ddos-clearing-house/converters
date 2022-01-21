import ipaddr
import json
import logging
import os
import pandas as pd


def find_ips(data):
    df = pd.DataFrame(data)
    df = df['src_ips'].apply(lambda x: ','.join(map(str, x))).to_frame()
    ips = df['src_ips'].str.cat(sep=',').split(',')
    df = pd.DataFrame(ips, columns=['ip'])
    df.drop_duplicates('ip', keep='first', inplace=True)
    ip_regex = '(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.)\\d{1,3}'
    df['src_net'] = df.ip.str.extract(ip_regex) + '0'
    df['ip'] = df['ip'].apply(lambda x: ipaddr.IPv4Address(x))
    return df


def build_iptables_rules(fingerprint, all_networks):
    fingerprint = os.path.splitext(os.path.basename(fingerprint))[0]
    filename = '{}.iptables'.format(fingerprint)
    with open(filename, 'w') as myfile:
        myfile.write('#/bin/sh\n')
        myfile.write(
            'sudo ipset create {} hash:net\n'.format(fingerprint[:30])
        )
        for ip in all_networks:
            myfile.write('sudo ipset add {} {}\n'.format(fingerprint[:30], ip))
        myfile.write(
            'sudo iptables -I INPUT -m set --match-set {} src -j DROP\n'
            .format(fingerprint[:30])
        )
    logging.info('IPTABLES rules saved on: {}'.format(filename))


def main(args):
    logging.info('Passing through converter_iptables')
    with open(args.fingerprint) as file:
        try:
            data = json.load(file)['attack_vector']
        except Exception:
            logging.error('Fingerprint not compatible.')
            return
    df = find_ips(data)
    subnets = utils.smart_aggregate(df)
    logging.info('Fingerprint processed: {}'.format(args.fingerprint))
    logging.info('IPs found: {}'.format(len(df['ip'])))
    logging.info('The IPs were summarized in: {} subnets'.format(len(subnets)))
    build_iptables_rules(args.fingerprint, subnets)


if __name__ == '__main__':
    import utils
    args = utils.setup(os.path.basename(__file__))
    main(args)
else:
    from . import utils
