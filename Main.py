import os
from tkinter import E
from tqdm.auto import tqdm
from types import SimpleNamespace

from Utils import get_dir, write_csv, filter_null_payload, get_payloads_by_index, decode_ascii, encode_hex
from Preprocess import preprocess
from Group import group
from Raid import raid
from ToNUtils import doubleHeavyHitters
from SummaryGraph import SummaryGraph
from Extract import extract_pcap_cl_v2

GROUP_SIGNATURES_COLUMN = [
    "group",
    "key_card",
    "group_packet",
    "group_unique_packet",
    "clusters",
    "biggest_cluster",
    "cluster_key_card",
    "cluster_packet",
    "cluster_unique_packet",
    "occurrence of most frequent signature",
    "common signatures",
]

ALL_CLUSTER_SIGNATURES_COLUMN = [
    "group",
    "key_card",
    "group_packet",
    "group_unique_packet",
    "cluster_key_card",
    "cluster",
    "cluster_packet",
    "cluster_unique_packet",
    "occurrence of most frequent signature",
    "common signatures",
]

KEY_DICT = {
    'all': (['all'], ['all_group-'], True),
    'ip': ([(5, 3), (3, 5)], ['dip-', 'sip-'], False),
    'ip_dport': ([(1, 3), (2, 5)], ["dip_dport-", "sip_dport-"], False),
}


def main(args):
    n = SimpleNamespace(**args)

    print("Preprocessing pcap files")
    data = preprocess(n.pcap_dir, csv_path=os.path.join(n.result_path, "train_data.csv"))
    
    key, key_name, isall = KEY_DICT[n.group_type]

    print(f"Grouping packets by {[key_name[i] for i in range(len(key_name))]}")
    topn_data = group(data, key=key, card_th=n.card_th, all=isall)

    print("Clustering")
    summary_list = []
    clusters = {}
    packet_idx_dict = dict()

    group_key_pair = []
    for key_idx in range(len(key)):
        group_key_pair += [(key_idx, group_info) for group_info in topn_data[key_idx]]
    
    for key_idx, group_info in group_key_pair:
        group_dir = get_dir(n.result_path, key_name[key_idx] + group_info[0])
        dhh_dir = get_dir(group_dir, "ToN_result")
        cluster_dir = get_dir(group_dir, "Clustering_result")

        X = filter_null_payload(group_info[1][1])
        if len(X) == 0:
            print("Skip: all 0-padding")
            continue
        if n.earlystop and len(X) > 1000 and raid(X, n.threshold, n.vector_size, n.window_size, earlystop=True) == False:
            print("earlystop", group_dir)
            continue

        result_dict = raid(X, n.threshold, n.vector_size, n.window_size, group_dir)

        clusters[key_name[key_idx] + group_info[0]] = list(result_dict.keys())

        packet_idx_dict[group_dir] = [list() for _ in range(len(result_dict))]
        for cluster_idx in result_dict.keys():
            packet_idx_dict[group_dir][cluster_idx] += result_dict[cluster_idx]["idx"]

        # has common signatures for each cluster
        common_signatures = dict()
        max_card = -1
        # per cluster
        for ci in list(result_dict.keys()):
            c_dict = result_dict[ci]
            common_signatures[ci] = set()
            # extracting signatures and writing on csv
            candidate_X = get_payloads_by_index(X, c_dict['index'])
            decode_X = [decode_ascii(x) for x in candidate_X]
            dhh_result = doubleHeavyHitters(
                decode_X, hh1_size=n.hh1_size, hh2_size=n.hh2_size, ratio=n.ratio, deduplication=n.deduplication
            )
            ret = [
                [encode_hex(x[0], n.israw), x[1]]
                for x in sorted(
                    dhh_result.items(), key=lambda x: x[1], reverse=True
                )
            ]

            ## finding common signature
            compare_key = "decoded payload"
            if n.israw == True:
                compare_key = "raw payload"

            ## finding actual signature frequency with string matching
            if n.iscount:
                nxt_ret = []
                for x, _ in ret:
                    count = 0
                    for payload in c_dict[compare_key]:
                        if x in payload:
                            count += 1
                    nxt_ret.append([x, count])
                ret = nxt_ret

            write_csv(
                os.path.join(dhh_dir, f"{ci}_result_ToN.csv"),
                ["signature", "frequency"],
                ret,
            )

            for x, _ in ret:
                flag = True
                for payload in c_dict[compare_key]:
                    if x not in payload:
                        flag = False
                        break
                if flag:
                    common_signatures[ci].add(x)

            indices = dict()
            anchor_packet = c_dict["decoded payload"][0]
            for common_signature in common_signatures[ci]:
                index = anchor_packet.find(common_signature)
                indices[common_signature] = [
                    index,
                    index + len(common_signature),
                ]
            indices = dict(
                sorted(indices.items(), key=lambda x: (x[1][0], x[1][1]))
            )

            common_signatures[ci] = list(indices.keys())

            csv_data = [
                [
                    list(c_dict["common string"]),
                    c_dict["decoded AE"][i],
                    str(c_dict["decoded payload"][i]),
                ]
                for i in range(len(c_dict["decoded AE"]))
            ]

            write_csv(
                os.path.join(cluster_dir, f"{ci}_result.csv"),
                ["common_string", "decoded_AE", "decoded_payload"],
                csv_data,
            )

            key_card = set()
            if not isall:
                for idx in c_dict["index"]:
                    key_card.add(group_info[1][0][idx])

            group_unique_packet = set()
            for payload in X:
                payload = payload[0]
                group_unique_packet.add(payload)

            summary_list.append(
                [
                    key_name[key_idx] + group_info[0],
                    len(set(group_info[1][0])),
                    len(group_info[1][1]),
                    len(group_unique_packet),
                    len(key_card),
                    ci,
                    len(c_dict["decoded AE"]),
                    len(set(c_dict["decoded payload"])),
                    ret[0][1] if len(ret) > 0 else 0,
                    common_signatures[ci],
                ]
            )

    one_big_cluster_list = []
    keys = set(x[0] for x in summary_list)
    for key in keys:
        summary_group = list(filter(lambda x: x[0] == key, summary_list))
        filtered_summary = list(filter(lambda x: x[5] != -1, summary_group))
        if len(filtered_summary) > 0:
            one_big_cluster = max(filtered_summary, key=lambda x: x[4])
        else:
            one_big_cluster = max(summary_group, key=lambda x: x[4])

        one_big_cluster = (
            one_big_cluster[:4] + [len(clusters[key])] + one_big_cluster[4:]
        )
        one_big_cluster[5], one_big_cluster[6] = one_big_cluster[6], one_big_cluster[5]
        one_big_cluster_list.append(one_big_cluster)

    write_csv(
        os.path.join(n.result_path, "all_cluster_signatures.csv"),
        ALL_CLUSTER_SIGNATURES_COLUMN,
        summary_list,
    )

    write_csv(
        os.path.join(n.result_path, "group_signatures.csv"),
        GROUP_SIGNATURES_COLUMN,
        one_big_cluster_list,
    )

    SummaryGraph(n.result_path)

    extract_pcap_cl_v2(packet_idx_dict, n.pcap_dir)