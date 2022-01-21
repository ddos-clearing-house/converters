import ipaddr
import json
import logging
import os
import pandas as pd
import pathlib
import pymisp


def find_ips(data):
    df = pd.DataFrame(data['src_ips'], columns=['ip'])
    df.drop_duplicates('ip', keep='first', inplace=True)
    ip_regex = '(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.)\\d{1,3}'
    df['src_net'] = df.ip.str.extract(ip_regex) + '0'
    df['ip'] = df['ip'].apply(lambda x: ipaddr.IPv4Address(x))
    return df


def find_attr(data, column):
    df = pd.DataFrame(data, columns=[column])
    df.drop_duplicates(column, keep='first', inplace=True)
    logging.info('{} table size: {}'.format(column, len(df[column])))
    return df


def to_string(s):
    try:
        return str(s)
    except Exception:
        return s.encode('utf-8')


def add_attributes(event, objs, type, comment):
    for obj in objs:
        value = to_string(obj)
        logging.info('Adding value: {}'.format(value))
        event.add_attribute(
            category='Network activity',
            type=type,
            value=value,
            comment=comment
        )


def add_attribute_comment(event, comment, value):
    logging.info('Adding comment {}: {}'.format(comment, value))
    event.add_attribute(
        category='Network activity',
        type='comment',
        value=value,
        comment=comment
    )


def add_attribute_snort(event, snort):
    for protocol in (snort['protocol'] or ['any']):
        for src_ip in (snort['src_ip'] or ['any']):
            for src_port in (snort['src_port'] or ['any']):
                for dst_port in (snort['dst_port'] or ['any']):
                    value = 'alert {} {} {} -> $HOME_NET {}'.format(
                        protocol,
                        src_ip,
                        src_port,
                        dst_port
                    )
                    options = ' '.join(snort['options'])
                    if options != '':
                        value = '{} ({})'.format(value, options)
                    logging.info('Adding value: {}'.format(value))
                    event.add_attribute(
                        category='Network activity',
                        type='snort',
                        value=value,
                        comment='snort rule'
                    )


def snort_content(values):
    return list(map(lambda x: 'content: "{}";'.format(x), values))


def snort_itype(values):
    return list(map(lambda x: 'itype: {};'.format(x), values))


def snort_icode(values):
    return list(map(lambda x: 'icode: {};'.format(x), values))


def snort_ttl(values):
    return list(map(lambda x: 'ttl: "{}";'.format(x), values))


def snort_flags(values):
    return list(map(
        lambda x: 'flags: {};'.format(x),
        utils.convert_tcp_flags(values)
    ))


def main(args):
    logging.info('Passing through misp_exporter')
    with open(args.fingerprint) as file:
        try:
            data = json.load(file)
        except Exception:
            logging.error('Fingerprint not compatible.')
            return
    misp = pymisp.ExpandedPyMISP(args.misp_url, args.misp_key, ssl=False, debug=True)
    event = pymisp.MISPEvent(strict_validation=True)
    event.info = args.event_info
    event.distribution = args.distribution
    event.threat_level_id = args.threat_level
    event.analysis = args.analysis_level
    event.add_tag(tag='validated')
    ddos = pymisp.MISPObject('ddos', strict=True)
    logging.info('Fingerprint processed: {}'.format(args.fingerprint))
    if 'attack_vector' in data:
        av = data['attack_vector'][0]
        snort = {
            'protocol': [],
            'src_ip': [],
            'src_port': [],
            'dst_port': [],
            'options': [],
        }
        df = find_ips(av)
        logging.info('IPs found: {}'.format(len(df['ip'])))
        subnets = utils.smart_aggregate(df)
        logging.info(
            'The IPs were summarized in: {} subnets'.format(len(subnets))
        )
        if args.subnets:
            add_attributes(event, subnets, 'ip-src', 'attacker subnet')
            ddos.add_attributes('ip-src', *subnets)
            snort['src_ip'] += subnets
        else:
            add_attributes(event, df['ip'], 'ip-src', 'attacker ip')
            ddos.add_attributes('ip-src', *df['ip'])
            snort['src_ip'] += df['ip'].tolist()
        if 'srcport' in av:
            sport = find_attr(av['srcport'], 'srcport')
            add_attributes(
                event,
                sport['srcport'],
                'port',
                'source port of attack'
            )
            ddos.add_attributes('src-port', *sport['srcport'])
            snort['src_port'] += sport['srcport'].tolist()
        if 'dstport' in av:
            dport = find_attr(av['dstport'], 'dstport')
            add_attributes(
                event,
                dport['dstport'],
                'port',
                'destination port of attack'
            )
            ddos.add_attributes('dst-port', *sport['dstport'])
            snort['dst_port'] += sport['dstport']
        if 'ip_proto' in av:
            proto4 = find_attr(av['ip_proto'], 'ip_proto')
            add_attributes(
                event,
                proto4['ip_proto'],
                'other',
                '4 level protocol of attack'
            )
            ddos.add_attributes('protocol', *proto4['ip_proto'])
            snort['protocol'] += proto4['ip_proto'].tolist()
        if 'dns_qry_name' in av:
            snort['options'] += snort_content(av['dns_qry_name'])
        if 'http_request' in av:
            snort['options'] += snort_content(av['http_request'])
        if 'http_response' in av:
            snort['options'] += snort_content(av['http_response'])
        if 'http_user_agent' in av:
            snort['options'] += snort_content(av['http_user_agent'])
        if 'icmp_type' in av:
            snort['options'] += snort_itype(av['icmp_type'])
        if 'icmp_code' in av:
            snort['options'] += snort_icode(av['icmp_code'])
        if 'ip_ttl' in av:
            snort['options'] += snort_ttl(av['ip_ttl'])
        if 'ntp_priv_reqcode' in av:
            snort['options'] += snort_content(av['ntp_priv_reqcode'])
        if 'tcp_flags' in av:
            snort['options'] += snort_flags(av['tcp_flags'])
        if 'tags' in av:
            for tag in av['tags']:
                event.add_tag(tag=tag)
        if 'duration_sec' in av:
            add_attribute_comment(event, 'duration_sec', av['duration_sec'])
        if 'total_dst_ports' in av:
            add_attribute_comment(
                event,
                'total_dst_ports',
                av['total_dst_ports']
            )
        if 'total_ips' in av:
            add_attribute_comment(event, 'total_ips', av['total_ips'])
        if 'total_packets' in av:
            add_attribute_comment(event, 'total_packets', av['total_packets'])
        add_attribute_snort(event, snort)
        event.add_tag(tag='ddos attack')
    if 'amplifiers' in data:
        amp = data['amplifiers'][0]
        dfa = find_ips(amp)
        logging.info('Amplifier IPs found: {}'.format(len(dfa['ip'])))
        subnetsa = utils.smart_aggregate(dfa)
        logging.info(
            'The IPs were summarized in: {} subnets'.format(len(subnetsa))
        )
        if args.subnets:
            add_attributes(event, subnetsa, 'ip-src', 'amplifier subnet')
            for elem in subnetsa:
                ddos.add_attribute('ip-src', elem, to_ids=0)
        else:
            add_attributes(event, dfa['ip'], 'ip-src', 'amplifier ip')
            for elem in dfa['ip']:
                ddos.add_attribute('ip-src', elem, to_ids=0)
        event.add_tag(tag='ddos amplification attack')
    p = pathlib.Path(args.fingerprint)
    comment = 'DDoS fingerprint json file generated by dissector'
    event.add_attribute(
        type='attachment',
        value=p.name,
        data=p,
        comment=comment
    )
    event.add_object(ddos, pythonify=True)
    event = misp.add_event(event, pythonify=True)


if __name__ == '__main__':
    import utils
    args = utils.setup(os.path.basename(__file__))
    main(args)
else:
    from . import utils
