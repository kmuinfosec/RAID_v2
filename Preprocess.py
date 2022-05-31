import os
import sys

import pandas as pd
import multiprocessing as mp
import numpy as np

from scapy.all import *
from tqdm import tqdm

from Utils import get_dir, write_csv


def make_pcap_payload(pcap_path):
    if os.path.getsize(pcap_path) == 0:
        return []

    pkts = rdpcap(pcap_path)
    processed_pkts = []

    for pkt in pkts:
        if pkt.haslayer('IP'):
            sip = pkt['IP'].src
            dip = pkt['IP'].dst
            
            if pkt.haslayer('TCP'):
                protocol = 'TCP'
            elif pkt.haslayer('UDP'):
                protocol = 'UDP'
            else:
                # processed_pkts.append([detect_rule, sip, None, dip, None, bytes(pkt['IP'].payload).hex()])
                continue
            sport = int(pkt[protocol].sport)
            dport = int(pkt[protocol].dport)
            # detect_type = pcap_path.rsplit('_', 2)[1]
            detect_type = "result"
            processed_pkts.append([detect_type, dip+'_'+str(dport), sip+'_'+str(dport),sip, sport, dip, dport, pcap_path, bytes(pkt[protocol].payload).hex()])
        else:
            pass
    return processed_pkts

def get_parsed_packets(pcap_dir):
    files = os.listdir(pcap_dir)
    path_list = []

    for file_name in files:
        if os.path.splitext(file_name)[-1] == ".pcap" or ".done":
            path_list.append(os.path.join(pcap_dir, file_name))

    process_count = os.cpu_count() // 2
    data = []
    with mp.Pool(process_count) as pool:    
        for pkts_list in tqdm(pool.imap_unordered(make_pcap_payload, path_list, chunksize=1), total=len(path_list)):
            data += pkts_list
    return data

def filter_null_payload(data):
    print(f"total payloads : {len(data)}", end="")
    data = list(filter(lambda x: len(x[-1]), data))
    print(f"\tfiltered 0-size payloads : {len(data)}")
    
    return data

def separate_by_detect(data):
    data_dict = {}
    for idx, d in enumerate(data):
        detect_type = d[0]
        if not detect_type in data_dict:
            data_dict[detect_type] = []
        data_dict[detect_type].append(d)

    return data_dict

def preprocess(pcap_dir, csv_path=False):
    mp.freeze_support()
    if isinstance(pcap_dir, list):
        data = []
        for dir in pcap_dir:
            data += get_parsed_packets(dir)
    else:
        data = get_parsed_packets(pcap_dir)

    if csv_path:
        data_key = ['data_type', 'dip_dport', 'sip_dport', 'sip', 'sport', 'dip', 'dport', 'path', 'raw_payload']
        write_csv(csv_path, data_key, data)
    data = filter_null_payload(data)

    return separate_by_detect(data)

if __name__ == '__main__':
    if len(sys.argv) == 1:
        pcap_dir = os.getcwd()
    else:
        pcap_dir = sys.argv[1]

    if len(sys.argv) < 3:
        csv_path = get_dir(os.getcwd())
    else:
        csv_path = get_dir(sys.argv[2], sys.argv[3])

    preprocess(pcap_dir, csv_path)
    