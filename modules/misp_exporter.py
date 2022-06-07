import json
import logging
import os
import pymisp


def main(args):
    logging.info('Passing through misp_exporter')
    with open(args.fingerprint) as file:
        try:
            data = json.load(file)
        except Exception:
            logging.error('Fingerprint not compatible.')
            return
    misp = pymisp.ExpandedPyMISP(args.misp_url, args.misp_key, ssl=False)
    sharing_group = [sh_grp for sh_grp in misp.sharing_groups(pythonify=True) if sh_grp.name == args.sharing_group]
    if len(sharing_group) == 0:
        sharing_group = misp.add_sharing_group({'name': args.sharing_group}, pythonify=True)
    else:
        sharing_group = sharing_group[0]
    event = pymisp.MISPEvent(strict_validation=True)
    event.info = args.event_info
    # ATTACK VECTORS
    for attack_vector, i in zip(data['attack_vectors'], range(len(data['attack_vectors']))):
        ddos = pymisp.MISPObject('ddos', strict=True)
        # ATTACK VECTOR SERVICE
        event.add_attribute(category='Network activity', type='comment', value=attack_vector['service'], comment=f'vector {i} service')
        # ATTACK VECTOR PROTOCOL
        ddos.add_attribute('protocol', attack_vector['protocol'])
        # ATTACK VECTOR SOURCE_PORT
        if type(attack_vector['source_port']) == int:
            ddos.add_attribute('src-port', attack_vector['source_port'])
        # ATTACK VECTOR FRACTION OF ATTACK
        if type(attack_vector['fraction_of_attack']) == float:
            event.add_attribute(category='Network activity', type='comment', value=attack_vector['fraction_of_attack'], comment=f'vector {i} fraction_of_attack')
        # ATTACK VECTOR DESTINATION PORTS
        if type(attack_vector['destination_ports']) == dict:
            ddos.add_attributes('dst-port', list(map(lambda x: int(x), attack_vector['destination_ports'].keys())))
        # ATTACK VECTOR TCP FLAGS
        if type(attack_vector['tcp_flags']) == dict:
            event.add_attribute(category='Network activity', type='comment', value=' '.join(attack_vector['tcp_flags']), comment=f'vector {i} tcp_flags')
        # ATTACK VECTOR NR FLOWS
        if 'nr_flows' in attack_vector:
            event.add_attribute(category='Network activity', type='comment', value=attack_vector['nr_flows'], comment=f'vector {i} nr_flows')
        # ATTACK VECTOR NR PACKETS
        event.add_attribute(category='Network activity', type='comment', value=attack_vector['nr_packets'], comment=f'vector {i} nr_packets')
        # ATTACK VECTOR NR MEGABYTES
        event.add_attribute(category='Network activity', type='comment', value=attack_vector['nr_megabytes'], comment=f'vector {i} nr_megabytes')
        # ATTACK VECTOR TIME START
        event.add_attribute(category='Network activity', type='comment', value=attack_vector['time_start'], comment=f'vector {i} time_start')
        # ATTACK VECTOR DURATION SECONDS
        event.add_attribute(category='Network activity', type='comment', value=attack_vector['duration_seconds'], comment=f'vector {i} duration_seconds')
        # ATTACK VECTOR SOURCE IPS
        ddos.add_attributes('ip-src', attack_vector['source_ips'])
        # TARGET
        ddos.add_attribute('ip-dst', data['target'])
        event.add_object(ddos, pythonify=True)
    # TAGS
    for tag in data['tags']:
        event.add_tag(tag=tag)
    event.add_tag(tag='validated')
    # KEY
    event.add_attribute(category='Network activity', type='md5', value=data['key'])
    # TIME START
    event.add_attribute(category='Network activity', type='comment', value=data['time_start'], comment='attack time_start')
    # DURATION SECONDS
    event.add_attribute(category='Network activity', type='comment', value=data['duration_seconds'], comment='attack duration_seconds')
    # TOTAL FLOWS
    if 'total_flows' in data:
        event.add_attribute(category='Network activity', type='comment', value=data['total_flows'], comment='total_flows')
    # TOTAL MEGABYTES
    event.add_attribute(category='Network activity', type='comment', value=data['total_megabytes'], comment='total_megabytes')
    # TOTAL PACKETS
    event.add_attribute(category='Network activity', type='comment', value=data['total_packets'], comment='total_packets')
    # TOTAL IPS
    event.add_attribute(category='Network activity', type='comment', value=data['total_ips'], comment='total_ips')
    # AVG BPS
    event.add_attribute(category='Network activity', type='comment', value=data['avg_bps'], comment='avg_bps')
    # AVG PPS
    event.add_attribute(category='Network activity', type='comment', value=data['avg_pps'], comment='avg_pps')
    # AVG BPP
    event.add_attribute(category='Network activity', type='comment', value=data['avg_Bpp'], comment='avg_Bpp')
    event = misp.add_event(event, pythonify=True)
    event = misp.change_sharing_group_on_entity(event, sharing_group.id, pythonify=True)
    misp.publish(event)


if __name__ == '__main__':
    import utils
    args = utils.setup(os.path.basename(__file__))
    main(args)
else:
    from . import utils
