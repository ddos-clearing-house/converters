#!/usr/bin/env python3
###############################################################################
# Concordia Project
#
# This project has received funding from the European Union’s Horizon
# 2020 Research and Innovation program under Grant Agreement No 830927.
#
# Joao Ceron - joaoceron@sidn.nl
###############################################################################

###############################################################################
### Python modules
import pandas as pd
import json
import argparse
import os
import signal
import sys
###############################################################################
### Program settings
verbose = False
version = 0.1
program_name = os.path.basename(__file__)

###############################################################################
### Subrotines

#------------------------------------------------------------------------------
def parser_args ():
    """
        Parse command line arguments 
    """

    parser = argparse.ArgumentParser(prog=program_name, usage='%(prog)s [options]')
    parser.add_argument("--version", help="print version and exit", action="store_true")
    parser.add_argument("-v","--verbose", help="print info msg", action="store_true")
    parser.add_argument("-d","--debug", help="print debug info", action="store_true")
    parser.add_argument('-f','--fingerprint', required=True, help="fingerprint json file")
    return parser

#------------------------------------------------------------------------------
def signal_handler(sig, frame):
    print('Ctrl+C detected.')
    sys.exit(0)

#------------------------------------------------------------------------------
def convert_tcp_flags(hex_num):
    """
        Convert TCP Flags from hex value to string
    """

    # string to binary
    try:
        hex_num  = int(hex_num[0],0)
        hex_num = f'0b{hex_num:08b}'
        hex_num = hex_num[4:]
    except:
        return None

    flags_dict =  {
        0 : "U", # URG
        1 : "A", # ACK
        2 : "P", # PSH
        3 : "R", # RST
        4 : "S", # SYN
        5 : "F", # FIN
    }

    detected_flags = ([pos for pos, char in enumerate(hex_num) if char == "1"])
    return list((pd.Series(detected_flags)).map(flags_dict))

#------------------------------------------------------------------------------
def convert_fingerprint_to_suricata(fingerprint):
    """
        Translate generated fingerprint to Suricata/Snort rules
    """

    ruler_option = []
    src_port = "any"
    dst_port = "any"
    src_net  = "any"
    dst_net  = "any"
    ip_proto = "any"
    
    if 'tcp_flags' in fingerprint:
        tcp_flag = convert_tcp_flags(fingerprint['tcp_flags'])
        if tcp_flag:
            ruler_option.append("flags:{};".format(tcp_flag[0]))
        
    if 'ip_proto' in fingerprint:
        ip_proto = fingerprint['ip_proto'][0]
        if ip_proto == "GRE":
            ruler_option.append("ip_proto:47;")
            ip_proto = "any"
            
    if 'dstport' in fingerprint:
        dst_port = fingerprint['dstport'][0]

    if 'srcport' in fingerprint:
        src_port = fingerprint['srcport'][0]
    
    if 'udp_length' in fingerprint:
        ruler_option.append("dsize:{} ;".format(fingerprint['udp_length'][0]))
        
    if 'dns_qry_name' in fingerprint:
        ruler_option.append("dns_query; content:\"{}\"; nocase; endswith;"
            .format(fingerprint['dns_qry_name'][0]))

    if 'icmp_type' in fingerprint:
        ruler_option.append("itype:{};".format(fingerprint['icmp_type'][0]))
        
    if 'ip_ttl' in fingerprint:
        ruler_option.append("ttl:{};".format(fingerprint['ip_ttl'][0]))
        
    if 'fragmentation' in fingerprint:
        if (bool(fingerprint['fragmentation'])):
            ruler_option.append("fragbits: M; fragoffset: >0;")
    
    # rule identification
    sid = int(''.join(format(ord(x), 'b') for x in str(fingerprint)[4:8]),2)

    ruler_option.append("sid:{};".format(sid))
    ruler_option.append("msg:\"ET DDoS Clearing House\";")
    rule = "drop {} {} {} -> {} {} ({})".format(ip_proto.lower(),
                                                     src_net,
                                                     src_port,
                                                     dst_net,
                                                     dst_port,
                                                     " ".join(str(x) for x in ruler_option),
                                               )
    return (rule)

###############################################################################
### Main Process
if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    parser = parser_args()
    args = parser.parse_args()

    if (not args.fingerprint):
        parser.print_help()
        sys.exit(IOError("\nInput file not provided. Use '-f' for that."))

    if (not os.path.exists(args.fingerprint)):
        sys.exit(IOError("File " + args.fingerprint + " is not readble"))

    fingerprint = args.fingerprint
    openfile=open(fingerprint)
    jsondata=json.load(openfile)
    try:
        data = (jsondata['attack_vector'])
    except:
        print ("Fingerprint not compatible.")
        sys.exit(1)
    
    print ("# DDoS-CH: rules generation for Suricata")
    if (len(data) <1):
        print ("Fingerprint not found in the provided file: {}".format(args.fingerprint))

    if (len(data) >1):
        print ("# This is a multivector fingerprint: #{}".format(len(data)))

    for fingerprint in data:
        print ("# Original fingerprint {}".format(fingerprint))
        rule = convert_fingerprint_to_suricata(fingerprint)
        print ("# Generated rule ")
        print ("{}\n".format(rule))
    sys.exit(0)

