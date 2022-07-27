import os
from scapy.all import *
from tqdm import tqdm
import platform
import subprocess

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
