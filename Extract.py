import os
from scapy.all import *
from tqdm import tqdm
import pickle
import platform
import subprocess
import multiprocessing as mp


def get_editcap_path():
    if platform.system() == "Windows":
        return 'C:\\"Program Files"\\Wireshark\\tshark.exe'
    else:
        system_path = os.environ["PATH"]
        for path in system_path.split(os.pathsep):
            filename = os.path.join(path, "tshark")
            if os.path.isfile(filename):
                return filename
    return ""


def write_to_file(args):
    path_list, cluster, clidx, key = args
    res = []

    for fileidx, file_path in enumerate(path_list):
        pkts = PcapReader(file_path)
        index = 0
        if not fileidx in cluster[0]:
            continue
        while index < len(cluster[0]):
            for idx, pkt in enumerate(pkts):
                if idx == cluster[1][index] and fileidx == cluster[0][index]:
                    res.append(pkt)
                    index = index + 1
                if index >= len(cluster[0]):
                    break

    # print(key)
    directory = key + "/pcaps/"
    if not os.path.exists(directory):
        os.makedirs(directory)
    #print(res)
    if os.name == "nt":
        writing_file = PcapWriter(
            directory + "cluster" + str(clidx) + ".pcap", append=True
        )
        writing_file.write(res)
        writing_file.flush()
    else:
        wrpcap(
            directory + "cluster " + str(clidx) + ".pcap",
            res,
        )


def extract_pcap_cl(data, pcap_dir, cpu_count=os.cpu_count() // 2):
    # print(data)
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
    path_list.sort()

    for key in data:
        pool = mp.Pool(cpu_count)
        args = []
        for clidx, cluster in tqdm(enumerate(data[key]), desc="Extracting packets from files"):
            args.append([path_list, cluster, clidx, key])
        pool.map(write_to_file, args)
        pool.close()
        pool.join()


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
                        """
                        dip_dport filtering
                        """
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
                        """
                        sip_sport filtering
                        """
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
                        """
                        dip_dport filtering
                        """
                        res = sniff(
                            offline=file_path,
                            filter=f"dst port {filt[1]} and host {filt[0]}",
                        )

                    else:
                        """
                        sip_sport filtering
                        """
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
