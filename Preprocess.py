import os
import sys

import pandas as pd
import multiprocessing as mp
import numpy as np

from scapy.all import *
from tqdm import tqdm

from Utils import get_dir


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
                # processed_pkts.append([pcap_path, sip, None, dip, None, bytes(pkt['IP'].payload).hex()])
                continue
            sport = int(pkt[protocol].sport)
            dport = int(pkt[protocol].dport)
            processed_pkts.append([pcap_path, dip+'_'+str(dport), sip+'_'+str(dport),sip, sport, dip, dport, bytes(pkt['IP'].payload).hex()])
        else:
            pass
    return processed_pkts

def get_parsed_packets(pcap_dir):
    files = os.listdir(pcap_dir)
    path_list = []

    for file_name in files:
        if os.path.splitext(file_name)[-1] == ".pcap":
            path_list.append(os.path.join(pcap_dir, file_name))

    process_count = os.cpu_count() // 2
    data = []
    with mp.Pool(process_count) as pool:    
        for pkts_list in tqdm(pool.imap_unordered(make_pcap_payload, path_list), total=len(path_list)):
            data += pkts_list

    return data

def preprocess(pcap_dir, csv_path=False):
    data = get_parsed_packets(pcap_dir)
    data = np.array(data)

    if csv_path:
        data_key = ['path', 'dip_dport', 'sip_dport', 'sip', 'sport', 'dip', 'dport', 'raw_payload']
        np.savetxt( os.path.join(csv_path, "train_data.csv"),
                    data, comments='',
                    header=','.join(data_key),
                    delimiter=',',
                    fmt="%s")
    
    return data

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