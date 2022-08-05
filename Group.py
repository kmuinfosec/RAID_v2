import numpy as np

from collections import Counter
from tqdm.auto import tqdm


def get_topn_key(data, key, card_th):
    key_dict = {}

    # k[0] == concat key, k[1] == standard of cardinality
    for k in key:
        key_dict[k[0]] = {}

    for pkt in tqdm(data):
        for k in key:
            card_key = pkt[k[0]]
            if not card_key in key_dict[k[0]]:
                key_dict[k[0]][card_key] = [[], []]
            key_dict[k[0]][card_key][0].append(pkt[k[1]])
            key_dict[k[0]][card_key][1].append([pkt[-1], pkt[-3], pkt[-2]])

    topn_data = [[] for _ in range(len(key))]
    for idx, k in enumerate(key):
        # (key, [[sips], [payloads, data_idx, packet_idx]])
        topn_data[idx] += sorted(
            key_dict[k[0]].items(), key=lambda x: len(set(x[1][0])), reverse=True
        )[:card_th]

    return topn_data


def all_keys(data):
    return [[("all", [{"all"}, [[i[-1],i[-3],i[-2]] for i in data]])]]


def group(data, key, card_th, all):
    if all:
        return all_keys(data)

    return get_topn_key(data, key, card_th)
