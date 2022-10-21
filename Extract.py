import os
import subprocess
import shutil
import multiprocessing as mp

if os.name == "posix":
    import logging
    
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from tqdm.auto import tqdm

def CustomPcapWriter(filename,pkt,overwritting=False):
    if overwritting:
        wrpcap(filename, pkt)
    else :
        if os.path.isfile(filename):
            wrpcap(filename, pkt, append=True)
        else:
            wrpcap(filename, pkt)

def write_to_file(args):
    fileidx, file_path, data = args
    # fileidx = pcap의 파일 index
    pkts = PcapReader(file_path)

    dp = dict()

    for key in data:
        directory = key + "/pcaps/"
        if not os.path.exists(directory):
            os.makedirs(directory)
        for clidx in data[key].keys():
            cluster = data[key][clidx]
            writing_file = directory + "cluster " + str(clidx) + ".pcap"
            for index in range(len(cluster[0])):

                packet_index = cluster[1][index]
                file_index = cluster[0][index]

                if file_index != fileidx:
                    continue

                group_key = (packet_index, clidx)
                if packet_index not in dp.keys():
                    dp[packet_index] = []
                dp[packet_index].append(writing_file)
    
    for idx, pkt in enumerate(pkts):
        if idx not in dp.keys():
            continue
        for writing_file in dp[idx]:
            CustomPcapWriter(writing_file, pkt)

def extract(data,pcap_dir,cpu_count=os.cpu_count()//2):
    mp.freeze_support()
    if os.path.isdir(pcap_dir):
        files = os.listdir(pcap_dir)
    else:
        pcap_dir, filename = os.path.split(pcap_dir)
        files = [ filename ]

    path_list = []

    for file_name in files:
        if (os.path.splitext(file_name)[-1] == ".pcap") or (
            os.path.splitext(file_name)[-1] == ".done"
        ):
            path_list.append(os.path.join(pcap_dir, file_name))
    path_list.sort()
    
    for key in data:
        directory = key + "/pcaps"
        if os.path.exists(directory):
            shutil.rmtree(directory)
    
    pool = mp.Pool(cpu_count)
    args = []
    for fileidx, file_path in enumerate(path_list):
        args.append([fileidx,file_path,data])
    with tqdm(total=len(args), desc="Extracting packets from files") as pbar:
        for _ in pool.imap_unordered(write_to_file, args):
            pbar.update(1)
    pool.close()
    pool.join()
    
    
""" Lagacy extraction method
def get_editcap_path():
    if os.name == "nt":
        return 'C:\\"Program Files"\\Wireshark\\tshark.exe'
    else:
        system_path = os.environ["PATH"]
        for path in system_path.split(os.pathsep):
            filename = os.path.join(path, "tshark")
            if os.path.isfile(filename):
                return filename
    return ""


def extract_pcap(filter_data, pcap_dir, result_path, method):
    if os.path.isdir(pcap_dir):
        files = os.listdir(pcap_dir)
    else:
        files = [pcap_dir]

    path_list = []

    for file_name in files:
        if (os.path.splitext(file_name)[-1] == ".pcap") or (
            os.path.splitext(file_name)[-1] == ".done"
        ):
            path_list.append(os.path.join(pcap_dir, file_name))

    for i in range(len(filter_data)):
        for filt in tqdm(filter_data[i], desc="Applying filter"):
            for file_path in path_list:
                type = "dip_dport"

                if method == "tshark":
                    tshark_path = get_editcap_path()
                    cmd = tshark_path + " -r " + file_path + " -Y "
                    if i == 0:
                        # dip_dport filtering
                        cmd = (
                            cmd
                            + '"((tcp.dstport=='
                            + filt[1]
                            + ") or (udp.dstport=="
                            + filt[1]
                            + ")) and (ip.dst=="
                            + filt[0]
                            + ')"'
                        )
                    else:
                        # sip_sport filtering
                        type = "sip_dport"
                        cmd = (
                            cmd
                            + '"((tcp.dstport=='
                            + filt[1]
                            + ") or (udp.dstport=="
                            + filt[1]
                            + ")) and (ip.src=="
                            + filt[0]
                            + ')"'
                        )
                    directory = (
                        result_path
                        + "/"
                        + type
                        + str(filt[0])
                        + "_"
                        + str(filt[1])
                        + "/pcaps/"
                    )
                    if not os.path.exists(directory):
                        os.makedirs(directory)
                    cmd += " -w " + directory + os.path.basename(file_path)
                    print(cmd)
                    subprocess.call(cmd)

                elif method == "scapy":

                    if i == 0:
                        # dip_dport filtering
                        res = sniff(
                            offline=file_path,
                            filter=f"dst port {filt[1]} and host {filt[0]}",
                        )

                    else:
                        # sip_sport filtering
                        type = "sip_dport"
                        res = sniff(
                            offline=file_path,
                            filter=f"dst port {filt[1]} and src host {filt[0]}",
                        )

                    directory = (
                        result_path
                        + "/"
                        + type
                        + str(filt[0])
                        + "_"
                        + str(filt[1])
                        + "/pcaps/"
                    )
                    if not os.path.exists(directory):
                        os.makedirs(directory)
                    if os.name == "nt":
                        writing_file = PcapWriter(
                            directory + os.path.basename(file_path), append=True
                        )
                        writing_file.write(res)
                        writing_file.flush()
                    else:
                        wrpcap(
                            directory + os.path.basename(file_path),
                            res,
                        )

            # print("RESULT")
            # print(res.summary)
"""
