import sys
import os
import pickle
import csv

from Preprocess import preprocess
from tqdm import tqdm

from Utils import get_dir
from Raid import raid
from Group import group
# from Extract import extract


def main(args):
    if len(args) == 1:
        print("Usage : \npython Main.py <pcap files path> <result path> <result directory name> <threshold>\n")
        pcap_dir = os.getcwd()
        result_dir = os.getcwd()
        result_path = get_dir(result_dir)
        threshold = 0.6 # default
    else:
        pcap_dir = args[1]
        result_dir = args[2]
        result_path = get_dir(result_dir, args[3])
        threshold = float(args[4])

    print("Preprocessing pcap files")
    data = preprocess(pcap_dir, csv_path="./")


    # (1, 3) means ('dip|dport', 'sip'), (2, 6) means('sip|dport', 'dip'), card_th == top_k cardinality
    key = [(1, 3), (2, 5)]
    key_name = {0:'dip_dport', 1:'sip_dport'}
    print(f"Grouping packets by {[key_name[i] for i in range(len(key_name))]}")
    topn_data_dict = group(data, key=key, card_th=5)


    print("Clustering")
    for detect_type in topn_data_dict.keys():
        topn_data = topn_data_dict[detect_type]
        for k in range(len(key)):
            for i in tqdm(topn_data[k]):
                detect_dir = get_dir(result_path, detect_type)
                cluster_dir = get_dir(detect_dir, key_name[k] + i[0])
                X = i[1][1]
                # result_dict = raid(X, threshold, 256, 3, i[0], cluster_dir)
                result_dict = raid(X, threshold, 256, 3, cluster_dir)
                for ci in list(result_dict.keys()):
                    c_dict = result_dict[ci]
                    with open(os.path.join(cluster_dir, f"{ci}_result.csv"), 'w', newline="") as cf:
                        writer = csv.writer(cf)
                        writer.writerow(['common_string', 'decoded_AE', 'decoded_payload'])
                        for i in range(len(c_dict['decoded AE'])):
                            writer.writerow([list(c_dict['common string']), c_dict['decoded AE'][i], c_dict['decoded payload'][i]])
            
    return 0





if __name__ == '__main__':
    main(sys.argv)