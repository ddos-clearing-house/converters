import json
import logging
import os


def convert_fingerprint_to_suricata(fingerprint, section):
    fingerprint = os.path.splitext(os.path.basename(fingerprint))[0]
    filename = '{}.snort'.format(fingerprint)
    ruler_option = []
    src_port = 'any'
    dst_port = 'any'
    src_net = 'any'
    dst_net = 'any'
    ip_proto = 'any'
    if 'tcp_flags' in section:
        tcp_flag = utils.convert_tcp_flags(section['tcp_flags'])
        if tcp_flag:
            ruler_option.append('flags:{};'.format(tcp_flag[0]))
    if 'ip_proto' in section:
        ip_proto = section['ip_proto'][0]
        if ip_proto == 'GRE':
            ruler_option.append('ip_proto:47;')
            ip_proto = 'any'
    if 'dstport' in section:
        dst_port = section['dstport'][0]
    if 'srcport' in section:
        src_port = section['srcport'][0]
    if 'udp_length' in section:
        ruler_option.append('dsize:{} ;'.format(section['udp_length'][0]))
    if 'dns_qry_name' in section:
        ruler_option.append(
            'dns_query; content:\'{}\'; nocase; endswith;'
            .format(section['dns_qry_name'][0])
        )
    if 'icmp_type' in section:
        ruler_option.append('itype:{};'.format(section['icmp_type'][0]))
    if 'ip_ttl' in fingerprint:
        ruler_option.append('ttl:{};'.format(section['ip_ttl'][0]))
    if 'fragmentation' in section:
        if (bool(section['fragmentation'])):
            ruler_option.append('fragbits: M; fragoffset: >0;')
    sid = int(''.join(format(ord(x), 'b') for x in str(section)[4:8]), 2)
    ruler_option.append('sid:{};'.format(sid))
    ruler_option.append('msg:\'ET DDoS Clearing House\';')
    rule = 'drop {} {} {} -> {} {} ({})\n'.format(
        ip_proto.lower(),
        src_net,
        src_port,
        dst_net,
        dst_port,
        ' '.join(str(x) for x in ruler_option),
    )
    with open(filename, 'a') as myfile:
        myfile.write(rule)
    logging.info('SNORT rules saved on: {}'.format(filename))


def main(args):
    logging.info('Passing through converter_snort')
    with open(args.fingerprint) as file:
        try:
            data = json.load(file)['attack_vector']
        except Exception:
            logging.error('Fingerprint not compatible.')
            return
    for section in data:
        logging.info('Original fingerprint {}'.format(section))
        convert_fingerprint_to_suricata(args.fingerprint, section)


if __name__ == '__main__':
    import utils
    args = utils.setup(os.path.basename(__file__))
    main(args)
else:
    from . import utils
