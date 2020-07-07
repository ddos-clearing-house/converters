#!/usr/bin/env python3
###############################################################################
#  
#  
# @copyright - Joao Ceron - ceron@botlog.org
###############################################################################

###############################################################################
### Python modules
import argparse
import logging
import os
import pandas as pd
import re
import signal
import sys

import netaddr
import ipaddr
import json
import math
###############################################################################
### Program settings
verbose = False
version = 0.1
program_name = os.path.basename(__file__)
###############################################################################
### Subrotines
    
#------------------------------------------------------------------------------
def parser_args ():

    parser = argparse.ArgumentParser(prog=program_name, usage='%(prog)s [options]')
    parser.add_argument("--version", help="print version and exit", action="store_true")
    parser.add_argument("-v","--verbose", help="print info msg", action="store_true")
    parser.add_argument("-d","--debug", help="print debug info", action="store_true")
    parser.add_argument('-f','--fingerprint', required=True, help="fingerprint json file")
    parser.add_argument('-tdf','--tcpdumpfilter', required=False, help="generate tcpdump filter expression file", action="store_true")
    return parser

#------------------------------------------------------------------------------
def signal_handler(sig, frame):
    print('Ctrl+C detected.')
    sys.exit(0)
    
#------------------------------------------------------------------------------
def find_ips(args):

    file = args.fingerprint
    if (args.fingerprint):
        file = args.fingerprint
        if not (os.path.isfile(file)):
            print ("file not found: {}".format(file))
            sys.exit(0)

    openfile=open(args.fingerprint)
    jsondata=json.load(openfile)
    data = jsondata['attackers']
    df=pd.DataFrame(data,columns=['ip'])
    openfile.close()
    
    df.drop_duplicates('ip',keep='first',inplace=True)
    df['src_net'] =  df.ip.str.extract('(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.)\\d{1,3}')+"0"
    df['ip'] = df['ip'].apply(lambda x: ipaddr.IPv4Address(x))

    return df

#------------------------------------------------------------------------------
def smart_aggregate(df):

    grouped = df.groupby('src_net')['ip']
    all_networks = []
    for name, group in grouped:
        
        # more than one IP in the /24 subnet, try to summarize
        if (len(group)>1):        

            # sort list
            ip_lst = sorted(group.reset_index()['ip'].to_list())
            lowest_ip  = ip_lst[0]  
            highest_ip = ip_lst[-1] 
            
            # split the list of IPs from the same subnet in tuple
            lst_with_two_elements = []
            for i in range(0, len(ip_lst), 2):
                lst_with_two_elements.append(ip_lst[i : i+2])
             
            # try to summarize the IP range 
            # get range every two ips
            for sub_lst in (lst_with_two_elements):
    
                # sub_lst is even, so we can summarize
                if (((len(sub_lst))% 2) == 0):
                    lowest_ip = sub_lst[0]
                    highest_ip  = sub_lst[1]
                    mask_length = ipaddr._get_prefix_length(int(lowest_ip), int(highest_ip), lowest_ip.max_prefixlen)
                    network_ip = ipaddr.IPNetwork("{}/{}".format(lowest_ip, mask_length)).network
                    network = ipaddr.IPNetwork("{}/{}".format(network_ip, mask_length), strict = True)
                    all_networks.append(network)
                    
                # there is no range to merge
                else:
                    network = ipaddr.IPNetwork("{}/{}".format(sub_lst[0], 32), strict = True)
                    all_networks.append(network)
    
    return all_networks
#------------------------------------------------------------------------------
def build_iptables_rules(fingerprint,all_networks):

    fingerprint = os.path.basename(fingerprint)
    fingerprint = str(fingerprint.split(".")[0])
    filename = "{}.iptables".format(fingerprint)
    with open(filename, "w") as myfile:
        myfile.write("#/bin/sh\n")

        # create ipset
        myfile.write("sudo ipset create {} hash:net\n".format(fingerprint[:30]))
        for ip in all_networks:
            myfile.write("sudo ipset add {} {}\n".format(fingerprint[:30],ip))
        myfile.write("sudo iptables -I INPUT -m set --match-set {} src -j DROP\n".format(fingerprint[:30]))
    print ("IPTABLES rules saved on: {}".format(filename))

def build_tcpdump_filters(fingerprint,all_networks):

    fingerprint = os.path.basename(fingerprint)
    fingerprint = str(fingerprint.split(".")[0])
    filename = "{}.tcpdf".format(fingerprint)
    print("{} subnets to process".format(len(all_networks)))
    
    aggregate_subnets(all_networks)

    with open(filename, "w") as filter_file:
        for index, net in enumerate(all_networks):
            if index == 0:
                filter_file.write("src net not {} ".format(net))
            else:
                filter_file.write("and not {} ".format(net))
    print ("TCPDUMP filter rules saved on: {}".format(filename))

def aggregate_subnets(nets):
    repr = map(lambda x: netaddr.IPNetwork(str(x)), nets)
    merged = netaddr.cidr_merge(repr)
    print(str(len(nets)) + " -> " + str(len(merged)))
    if len(nets) < 100 or len(merged) < 0:
        print(nets, merged)

###############################################################################
### Main Process
if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    parser = parser_args()
    args = parser.parse_args()

    df = find_ips(args) 
    subnets = smart_aggregate(df)
    
    print ("Fingerprint processed: {}".format(args.fingerprint))
    print ("IPs found: {}".format(len(df['ip'])))
    print ("The IPs were summarized in: {} subnets".format(len(subnets)))

    build_iptables_rules(args.fingerprint, subnets)
    if args.tcpdumpfilter:
        build_tcpdump_filters(args.fingerprint, subnets)

