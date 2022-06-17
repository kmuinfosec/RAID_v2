import sys
import os

from Preprocess import preprocess
from tqdm import tqdm

from Utils import get_dir, write_csv
from Raid import raid
from Group import group
# from Extract import extract


def main(args):
    if len(args) == 1:
        print("Usage : \npython Main.py <pcap files path> <result path> <result directory name> <threshold> <is group>\n")
        pcap_dir = os.getcwd()
        result_dir = os.getcwd()
        result_path = get_dir(result_dir)
        threshold = 0.6 # default
        detect_type_flag = False
        isall = False
    else:
        pcap_dir = args[1]
        result_dir = args[2]
        result_path = get_dir(result_dir, args[3])
        threshold = float(args[4])
        detect_type_flag = args[5]
        if not isinstance(args[5], bool):
            detect_type_flag = eval(detect_type_flag)
        isall = args[6]

    print("Preprocessing pcap files")
    data = preprocess(pcap_dir, detect_type_flag, csv_path=os.path.join(result_path, "train_data.csv"))

    # (1, 3) means ('dip|dport', 'sip'), (2, 6) means('sip|dport', 'dip'), card_th == top_k cardinality
    if isall:
        key = ['all']
    else:
        key = [(1, 3), (2, 5)]
    key_name = ['dip_dport', 'sip_dport']
    print(f"Grouping packets by {[key_name[i] for i in range(len(key_name))]}")
    topn_data_dict = group(data, key=key, card_th=5,all=isall)
        

    print("Clustering")
    # per detect_type (if detect_type)
    for detect_type in topn_data_dict.keys():
        topn_data = topn_data_dict[detect_type]
        detect_dir = get_dir(result_path, detect_type)
        summary_list = []

    # per key(DIP||DPORT, ...)
        for k in range(len(key)):
            
    # per group(top k)
            for i in tqdm(topn_data[k]):
                cluster_dir = get_dir(detect_dir, key_name[k] + i[0])
                X = i[1][1]
                result_dict = raid(X, threshold, 256, 3, cluster_dir)

    # per cluster
                for ci in list(result_dict.keys()):
                    c_dict = result_dict[ci]
                    csv_data = [[   list(c_dict['common string']),
                                    c_dict['decoded AE'][i],
                                    str(c_dict['decoded payload'][i])
                                ] for i in range(len(c_dict['decoded AE']))]
                    write_csv(  os.path.join(cluster_dir, f"{ci}_result.csv"),
                                ['common_string', 'decoded_AE', 'decoded_payload'],
                                csv_data)
                    key_card = set()
                    # print(c_dict)
                    # exit()
                    # for idx in c_dict['index']:
                    #     key_card.add(i[1][0][idx])
                    summary_list.append([key_name[k] + i[0], len(set(i[1][0])), len(i[1][1]), len(key_card) ,ci, len(c_dict['decoded AE'])])

        write_csv(  os.path.join(detect_dir, "group_clustering_summary.csv"),
                    ['group', 'key_card', 'group_packet', 'cluster_key_card', 'cluster', 'cluster_packet'],
                    summary_list)


if __name__ == '__main__':
    main(sys.argv)