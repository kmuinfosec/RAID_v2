import os
if os.name == "posix":
    import logging

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
import multiprocessing as mp

from scapy.all import *
from tqdm.auto import tqdm
from itertools import repeat

from Utils import get_dir, write_csv


def make_pcap_payload(input):
    pcap_path, data_idx = input
    if os.path.getsize(pcap_path) == 0:
        return []

    pkts = PcapReader(pcap_path)
    processed_pkts = []
    for idx, pkt in enumerate(pkts):
        if pkt.haslayer("IP"):
            sip = pkt["IP"].src
            dip = pkt["IP"].dst

            if pkt.haslayer("TCP"):
                protocol = "TCP"
            elif pkt.haslayer("UDP"):
                protocol = "UDP"
            else:
                # processed_pkts.append([detect_rule, sip, None, dip, None, bytes(pkt['IP'].payload).hex()])
                continue
            sport = int(pkt[protocol].sport)
            dport = int(pkt[protocol].dport)
            if bool(pkt[protocol].payload):
                if "Padding" in pkt[protocol].payload:
                    if (
                        pkt[protocol].payload["Padding"].load
                        == pkt[protocol].payload.load
                    ):
                        payload = ""
                    else:
                        payload = bytes(pkt[protocol].payload.load).hex()
                else:
                    payload = bytes(pkt[protocol].payload).hex()
            else:
                payload = ""
            processed_pkts.append(
                [
                    dip + "_" + str(dport),
                    sip + "_" + str(dport),
                    sip,
                    sport,
                    dip,
                    dport,
                    data_idx,
                    idx,
                    payload,
                ]
            )
        else:
            pass
    return processed_pkts


def get_parsed_packets(pcap_dir, files, cpu_count=os.cpu_count() // 2, extension = ".pcap"):
    if not files:
        files = os.listdir(pcap_dir)
    
    path_list = []
    for file_name in files:
        ext = os.path.splitext(file_name)[-1]
        if ext == extension:
            path_list.append(os.path.join(pcap_dir, file_name))
    if len(path_list) == 0:
        raise Exception(f'There are no files with <{extension}> extension')

    path_list.sort()
    data = []
    with mp.Pool(cpu_count) as pool:
        for pkts_list in tqdm(
            pool.imap_unordered(
                make_pcap_payload, zip(path_list, range(len(path_list))), chunksize=1
            ),
            total=len(path_list),
            desc='Preprocessing pcap files'
        ):
            data += pkts_list
    return data


def preprocess(pcap_dir, pcap_list, cpu_count=None, extension='.pcap'):
    mp.freeze_support()
    data = get_parsed_packets(pcap_dir, pcap_list, cpu_count, extension)

    return data


# if __name__ == "__main__":
#     if len(sys.argv) == 1:
#         pcap_dir = os.getcwd()
#     else:
#         pcap_dir = sys.argv[1]

#     if len(sys.argv) < 3:
#         csv_path = get_dir(os.getcwd())
#     else:
#         csv_path = get_dir(sys.argv[2], sys.argv[3])

#     preprocess(pcap_dir, csv_path)
