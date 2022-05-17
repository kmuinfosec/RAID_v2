import os
import pickle

from RaidUtils import prototypeClustering, hierarchicalClustering, decode, AE2, contents2count


def raid(payloads, th, vec_size, win_size, save_path=False):

    X = contents2count(payloads, vec_size=vec_size, win_size=win_size)

    prev_label_list = prototypeClustering(X, th, opt1=False)
    label_list = hierarchicalClustering(X, prev_label_list, th)

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
                'common string': set(chunks_list[idx]),
                'decoded AE': [],
                'decoded payload': []
            }

        ans[label]['common string'].intersection_update(chunks_list[idx])
        ans[label]['decoded AE'].append(chunks_list[idx])
        ans[label]['decoded payload'].append(decode(payloads[idx]))

    if save_path:
        with open(os.path.join(save_path, 'result_data_merge.pkl'), 'wb') as f:
            pickle.dump(ans, f)
    
    return ans

    """
    result_data_merge.pkl
    dict[key = cluster name] = dict{
        common string:[common string]
        decoded_AE:[payload1(AE된거), payload2(AE된거)...]
        decoded_payload:[payload1, payload2]}
    """