import codecs
import os
from scapy.all import *
from tqdm import tqdm


def extract_pcap(filter_data, pcap_dir, result_path):
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

                # print(filt)
                # print(type+str(filt[0])+"_"+str(filt[1])+"_"+os.path.basename(file_path))
                if i == 0:
                    res = sniff(
                        offline=file_path,
                        filter=f"dst port {filt[1]} and host {filt[0]}",
                    )
                else:
                    res = sniff(
                        offline=file_path,
                        filter=f"dst port {filt[1]} and src host {filt[0]}",
                    )
                    type = "sip_dport"
                dirctory = (
                    result_path
                    + "/"
                    + type
                    + str(filt[0])
                    + "_"
                    + str(filt[1])
                    + "/pcaps/"
                )
                if not os.path.exists(dirctory):
                    os.makedirs(dirctory)
                wrpcap(
                    dirctory + os.path.basename(file_path),
                    res,
                )

            # print("RESULT")
            # print(res.summary)
