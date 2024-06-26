import os
import pickle
import random

from collections import Counter

from RaidUtils import (
    prototypeClustering,
    hierarchicalClustering,
    decode,
    AE2,
    contents2count,
)


def raid(
    data,
    th,
    vec_size,
    win_size,
    uniq_count_data,
    save_path=False,
    earlystop=False,
    sample=1000,
    detect_rate=0.4,
    payloads_card = None
):
    payloads = [i[0] for i in data]
    if not payloads_card:
        payloads_card = len(set(payloads))
    if earlystop:
        X = random.sample(X, sample)
        if payloads_card == 1:
            return False
    
    if payloads_card != 1:
        X = contents2count(payloads, vec_size=vec_size, win_size=win_size)

        prev_label_list = prototypeClustering(X, th, opt1=False)
        label_list = hierarchicalClustering(X, prev_label_list, th)
    else:
        label_list = [0] * len(payloads)

    if not earlystop:
        chunks_list = []
        for payload in payloads:
            chunks = AE2(payload, win_size)
            for idx in range(len(chunks)):
                chunks[idx] = decode(chunks[idx])
            chunks_list.append(chunks)

        ans = dict()
        for idx, label in enumerate(label_list):
            if label not in ans.keys():
                ans[label] = {
                    "raw payload": [],
                    "common string": set(chunks_list[idx]),
                    "decoded AE": [],
                    "decoded payload": [],
                    "index": [],
                    "idx": [[], []],
                    "uniq_sip": [],
                    "uniq_sport" : [],
                    "uniq_dip" : [],
                    "uniq_dport" : []
                }

            ans[label]["raw payload"].append(payloads[idx])
            ans[label]["common string"].intersection_update(chunks_list[idx])
            ans[label]["decoded AE"].append(chunks_list[idx])
            ans[label]["decoded payload"].append(decode(payloads[idx]))
            ans[label]["index"].append(idx)
            ans[label]["idx"][1].append(data[idx][2])
            ans[label]["idx"][0].append(data[idx][1])
            ans[label]["uniq_sip"].append(uniq_count_data[idx][0])
            ans[label]["uniq_sport"].append(uniq_count_data[idx][1])
            ans[label]["uniq_dip"].append(uniq_count_data[idx][2])
            ans[label]["uniq_dport"].append(uniq_count_data[idx][3])
            

        if save_path:
            with open(os.path.join(save_path, "result_data_merge.pkl"), "wb") as f:
                pickle.dump(ans, f)

        return ans

        """
        result_data_merge.pkl
        dict[key = cluster name] = dict{
            common string:[common string]
            decoded_AE:[payload1(AE), payload2(AE)...]
            decoded_payload:[payload1, payload2]}
        """
    else:
        counter = []
        for label in label_list:
            if label != -1:
                counter.append(label)
        counter = Counter(counter)

        if len(counter) == 0:
            return False

        p_hat = counter.most_common(1)[0][1]
        if (p_hat / len(X)) >= detect_rate:
            return True
        return False
