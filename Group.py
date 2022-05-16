from collections import Counter
import numpy as np
from tqdm import tqdm


def get_topn_key(data, key, card_th):
    key_dict = {}


    # k[0] == concat key, k[1] == standard of cardinality
    for k in key:
        key_dict[k[0]] = {}

    for pkt in tqdm(data):
        for k in key:
            card_key = pkt[k[0]]
            if not card_key in key_dict[k[0]]:
                key_dict[k[0]][card_key] = [set(), []]
            key_dict[k[0]][card_key][0].add(pkt[k[1]])
            key_dict[k[0]][card_key][1].append(pkt[-1])

    topn_data = [[] for _ in key]
    for idx, k in enumerate(key):
        # (key, [[sips], [payloads]])
        topn_data[idx] += sorted(key_dict[k[0]].items(), key=lambda x: len(x[1][0]), reverse=True)[:card_th]
        
    return topn_data

def group(data, key, card_th):
    topn_data = get_topn_key(data, key, card_th)

    return topn_data
    

    