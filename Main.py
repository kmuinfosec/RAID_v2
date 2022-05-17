import sys
import os
import pickle

from Preprocess import preprocess

from Utils import get_dir
from Raid import raid
from Group import group
from tqdm import tqdm

# def decode(x):
#     l=[]
#     for i in range(0, len(x),2):
#         f = int(x[i:i+2],16)
#         if (f>=32)&(f<=126):
#             l.append(chr(f))
#         else:
#             l.append(x[i:i+2])
#     return "".join(l)

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

    print("Preprocess pcap files")
    data = preprocess(pcap_dir, csv_path=False)

    # (1, 3) means ('dip|dport', 'sip'), (2, 6) means('sip|dport', 'dip'), card_th == top_k cardinality
    key = [(1, 3), (2, 5)]
    key_name = {0:'dip_dport', 1:'sip_dport'}
    topn_data = group(data, key=key, card_th=10)

    for k in range(len(key)):
        for i in tqdm(topn_data[k]):
            X = i[1][1]
            row_key = i[0]
            raid(X, threshold, 256, 3, row_key, os.path.join(result_path, key_name[k] + i[0]))
            # with open(os.path.join(result_path, key_name[k]+row_key, "result_data_merge.pkl"), "rb") as f:
            #     result_data = pickle.load(f)
            #     for c in result_data:
            #         if len(result_data[c]):
            #             result = [[decode(raw_p), c, len(result_data[c])] for raw_p in X]
            #             print(result_data[c])

    # for k in range(len(key[:1])):
    
        
    # have to convert to git RAID version
    return 0





if __name__ == '__main__':
    main(sys.argv)