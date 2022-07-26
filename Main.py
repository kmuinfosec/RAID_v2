import os
import argparse

from tqdm.auto import tqdm

from Utils import get_dir, write_csv, filter_null_payload
from Preprocess import preprocess
from Group import group
from Raid import raid
from ToNUtils import doubleHeavyHitters
from SummaryGraph import SummaryGraph
from Extract import extract_pcap


def main(args):
    pcap_dir = args.pcap_path
    result_path = get_dir(args.result_path, args.result_dir)
    threshold = args.threshold
    card_th = args.card_th
    isall = eval(args.is_all)

    #print(type(args.is_all))
    #print(args.is_all)
    print("Preprocessing pcap files")
    data = preprocess(pcap_dir, csv_path=os.path.join(result_path, "train_data.csv"))
    if isall:
        key = ["all"]
    else:
        # (1, 3) means ('dip|dport', 'sip'), (2, 6) means('sip|dport', 'dip'), card_th == top_k cardinality
        key = [(1, 3), (2, 5)]

    key_name = ["dip_dport", "sip_dport"]
    print(f"Grouping packets by {[key_name[i] for i in range(len(key_name))]}")

    topn_data = group(data, key=key, card_th=card_th, all=isall)
    clusters = {}
    print("Clustering")
    # per detect_type (if detect_type)
    summary_list = []
    # per key(DIP||DPORT, ...)

    for k in range(len(key)):

        # per group(top k)
        for i in tqdm(topn_data[k]):
            group_dir = get_dir(result_path, key_name[k] + i[0])
            dhh_dir = get_dir(group_dir, "ToN_result")
            cluster_dir = get_dir(group_dir, "Clustering_result")

            X = filter_null_payload(i[1][1])
            if len(X) == 0:
                print("Skip: all 0-padding")
                continue
            if len(X) > 1000 and raid(X, threshold, 256, 3, earlystop=True) == False:
                print("earlystop", group_dir)
                continue

            result_dict = raid(X, threshold, 256, 3, group_dir)
            clusters[key_name[k] + i[0]] = list(result_dict.keys())
            # has common signatures for each cluster
            common_signatures = dict()
            max_card = -1
            # per cluster
            for ci in list(result_dict.keys()):
                c_dict = result_dict[ci]
                common_signatures[ci] = set()
                # extracting signatures and writing on csv
                dhh_result = doubleHeavyHitters(
                    c_dict["decoded payload"], hh1_size=200, hh2_size=200, ratio=0.6
                )
                ret = [
                    list(x)
                    for x in sorted(
                        dhh_result.items(), key=lambda x: x[1], reverse=True
                    )
                ]
                write_csv(
                    os.path.join(dhh_dir, f"{ci}_result_ToN.csv"),
                    ["signature", "frequency"],
                    ret,
                )

                ## finding common signature
                for x, _ in ret:
                    flag = True
                    for payload in c_dict["decoded payload"]:
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
                        key_card.add(i[1][0][idx])

                summary_list.append(
                    [
                        key_name[k] + i[0],
                        len(set(i[1][0])),
                        len(i[1][1]),
                        len(key_card),
                        ci,
                        len(c_dict["decoded AE"]),
                        ret[0][1] if len(ret) > 0 else 0,
                        common_signatures[ci],
                    ]
                )

    one_big_cluster_list = []
    keys = set(x[0] for x in summary_list)
    for key in keys:
        summary_group = list(filter(lambda x: x[0] == key, summary_list))
        filtered_summary = list(filter(lambda x: x[4] != -1, summary_group))
        if len(filtered_summary) > 0:
            one_big_cluster = max(filtered_summary, key=lambda x: x[3])
        else:
            one_big_cluster = max(summary_group, key=lambda x: x[3])

        one_big_cluster = (
            one_big_cluster[:3] + [len(clusters[key])] + one_big_cluster[3:]
        )
        one_big_cluster_list.append(one_big_cluster)

    write_csv(
        os.path.join(result_path, "all_cluster_signatures.csv"),
        [
            "group",
            "key_card",
            "group_packet",
            "cluster_key_card",
            "cluster",
            "cluster_packet",
            "occurrence of most frequent signature",
            "common signatures",
        ],
        summary_list,
    )

    write_csv(
        os.path.join(result_path, "group_signatures.csv"),
        [
            "group",
            "key_card",
            "group_packet",
            "clusters",
            "biggest_cluster",
            "cluster_key_card",
            "cluster_packet",
            "occurrence of most frequent signature",
            "common signatures",
        ],
        one_big_cluster_list,
    )

    # SummaryGraph(result_path)
    print("Extracting pcaps")
    # print(topn_data)
    filter_data = []
    for l in tqdm(range(len(topn_data)), desc="Extracting filter data"):
        filter_data.append(set([]))
        for i in topn_data[l]:
            for j in i:
                filter_data[l].add((i[0].split("_")[0], i[0].split("_")[1]))
    extract_pcap(filter_data, pcap_dir, result_path)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument("pcap_path", help="Input the path of the pcap files")
    argparser.add_argument("result_path", help="Input the path of the result directory")
    argparser.add_argument(
        "result_dir",
        help="Input the name of the result directory",
    )
    argparser.add_argument(
        "-t",
        "--threshold",
        type=float,
        required=False,
        default=0.6,
        help="Input the threshold of the clustering | Default : 0.6",
    )
    argparser.add_argument(
        "-c",
        "--card_th",
        type=int,
        required=False,
        default=5,
        help="Select top \{card_th\} group per each key | Default : 5",
    )
    argparser.add_argument(
        "-a",
        "--is_all",
        required=False,
        default="False",
        help="True if don't want to make group | Default : False",
    )
    args = argparser.parse_args()
    main(args)
