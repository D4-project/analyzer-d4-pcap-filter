#!/usr/bin/env python3

import os
import sys
import time
import redis
import argparse
#import ipaddress
from uuid import uuid4

import logging
import logging.handlers

import subprocess

log_level = {'DEBUG': 10, 'INFO': 20, 'WARNING': 30, 'ERROR': 40, 'CRITICAL': 50}

## options ##
options = {'print_timestamp': False, 'convert_addresses_to_names': False}

def add_tcpdump_options_flag(tcpdump_cmd, options):
    if options.get('convert_addresses_to_names', None):
        tcpdump_cmd.append('-n')
    if options.get('print_timestamp', None):
        tcpdump_cmd.append('-tttt')

def is_valid_ip_network(ip_network):
    try:
        ipaddress.ip_network(ip_network)
        return True
    except Exception as e:
        return False

# create pcap filter by list of ip networks
# def create_pcap_filter(l_iprange):
#     pcp_filter = ''
#     for ip_network in l_iprange:
#         if is_valid_ip_network(ip_network):
#             if not pcp_filter:
#                 pcp_filter = pcp_filter + 'net {}'.format(ip_network)
#             else:
#                 pcp_filter = pcp_filter + ' or net {}'.format(ip_network)
#     return pcp_filter

def build_tcpdump_cmd(tcpdump_filter, output_filename, options={}):
    tcpdump_cmd = ['tcpdump']
    add_tcpdump_options_flag(tcpdump_cmd, options)
    tcpdump_cmd.append('-r')
    tcpdump_cmd.append('-') # Standard input
    tcpdump_cmd.append(tcpdump_filter)

    # save to file
    tcpdump_cmd.append('-w')
    tcpdump_cmd.append(output_filename)
    return tcpdump_cmd

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Export d4 data to stdout')
    parser.add_argument('-t', '--type', help='d4 type or extended type' , type=str, dest='type', required=True)
    parser.add_argument('-f', '--filter', help='tcpdump filter' , type=str, dest='tcpdump_filter', required=True)
    parser.add_argument('-u', '--uuid', help='queue uuid' , type=str, dest='uuid', required=True)
    parser.add_argument('-l', '--log_level', help='log level: DEBUG, INFO, WARNING, ERROR, CRITICAL', type=str, default='INFO', dest='req_level')
    parser.add_argument('-ri', '--redis_ip',help='redis host' , type=str, default='127.0.0.1', dest='host_redis')
    parser.add_argument('-rp', '--redis_port',help='redis port' , type=int, default=6380, dest='port_redis')
    args = parser.parse_args()

    if not args.uuid and tcpdump_filter:
        parser.print_help()
        sys.exit(0)

    host_redis=args.host_redis
    port_redis=args.port_redis
    req_level = args.req_level

    tcpdump_filter = args.tcpdump_filter
    #tcpdump_filter = 'net 10.1.0.1/32'

    if req_level not in log_level:
        print('ERROR: incorrect log level')
        sys.exit(0)

    redis_d4= redis.StrictRedis(
                        host=host_redis,
                        port=port_redis,
                        db=2)
    try:
        redis_d4.ping()
    except redis.exceptions.ConnectionError:
        print('Error: Redis server {}:{}, ConnectionError'.format(host_redis, port_redis))
        sys.exit(1)

    d4_uuid = args.uuid
    d4_type = args.type
    data_queue = 'analyzer:{}:{}'.format(d4_type, d4_uuid)

    output_filename = 'new_{}_{}.cap'.format(d4_uuid, str(uuid4()).replace('-', ''))
    tcpdump_cmd = build_tcpdump_cmd(tcpdump_filter, output_filename, options)

    d4_uuid = args.uuid
    data_queue = 'analyzer:1:{}'.format(d4_uuid)

    while True:
        d4_data = redis_d4.rpop(data_queue)
        #d4_data = 'fae58cdc30024239874f4c7ce53fbf4d-2019-06-17-132154.cap.gz'
        if d4_data is None:
            time.sleep(1)
            continue
        cmd_zcat = ['zcat']
        cmd_zcat.append(d4_data)

        p1 = subprocess.Popen(cmd_zcat, stdout=subprocess.PIPE)
        p2 = subprocess.Popen(tcpdump_cmd, stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.

        output = p2.communicate()[0]
        if output:# If error
            print(output.decode())

        # not empty pcap
        if os.path.getsize(output_filename) > 25:
            pass

        #os.remove(output_filename)

        #sys.exit(0)

        # # TODO: specify misp module
