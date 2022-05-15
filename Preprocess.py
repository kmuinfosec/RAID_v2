import os

import pandas as pd


from scapy.all import *
import os
from tqdm import tqdm


def make_pcap_payload(pcap_file):
    if os.path.getsize(pcap_file) == 0:
        return None
    if not os.path.exists(folder_name):
        os.mkdir(folder_name)
    pkts = rdpcap(pcap_file)
    for i, pkt in enumerate(pkts):
        if pkt.haslayer('IP'):
            sip = pkt['IP'].src
            dip = pkt['IP'].dst
            if pkt.haslayer('TCP'):
                protocol = 'TCP'
            elif pkt.haslayer('UDP'):
                protocol = 'UDP'
            else:
                with open(rf"{folder_name}{os.sep}{i + 1}_{sip}_{dip}.txt", 'w', encoding='utf-8') as f:
                    f.write(bytes(pkt['IP'].payload).hex() + '\n')
                continue
            with open(rf"{folder_name}{os.sep}{i + 1}_{sip}_{pkt[protocol].sport}_{dip}_{pkt[protocol].dport}.txt",
                        'w', encoding='utf-8') as f:
                f.write(bytes(pkt[protocol].payload).hex() + '\n')
        else:
            pass


if __name__ == '__main__':
    # pcap_path = r"test"
    pcaps_path = r"C:\Lab\Project\KT\Data\20220419\211.216.98.60\Snort\result"
    for pcap_file in tqdm(os.listdir(pcaps_path)):
        pcap_path = os.path.join(pcaps_path, pcap_file)
        make_pcap_payload(pcap_path, session=True) # PCAP 위치 넣어주기

def get_packet_csv(path):
    files = os.listdir(path)
    flag = False
    
    df = pd.DataFrame()

    with open()
    for fn in files:
        if os.path.splitext(fn)[-1] == ".pcap":
            flag = True
            

def preprocess(pcap_path, result_path, result_dname):
    if not os.path.exists(os.path.join(result_path, result_dname)):
        os.mkdir(os.path.join(result_path, result_dname))
    
    pass

if __name__ == '__main__':
    preprocess()