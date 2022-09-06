import os
import argparse
from tqdm.auto import tqdm

from Utils import get_dir, write_csv, filter_null_payload, get_payloads_by_index, decode_ascii, encode_hex
from Preprocess import preprocess
from Group import group
from Raid import raid
from ToNUtils import doubleHeavyHitters
from SummaryGraph import SummaryGraph
from Extract import extract_pcap_cl_v2


def main(args):
    pcap_dir = args.pcap_path
    result_path = get_dir(args.result_path, args.result_dir)
    threshold = args.threshold
    card_th = args.card_th
    group_type = args.group
    israw = eval(args.israw)
    deduplication = eval(args.deduplication)
    iscount = eval(args.count)

    print("Preprocessing pcap files")
    data = preprocess(pcap_dir, csv_path=os.path.join(result_path, "train_data.csv"))

    if group_type == 'all':
        key = ["all"]
        key_name = ["all_group-"]
    elif group_type == 'ip_dport':
        # (1, 3) means ('dip|dport', 'sip'), (2, 6) means('sip|dport', 'dip'), card_th == top_k cardinality
        key = [(1, 3), (2, 5)]
        key_name = ["dip_dport-", "sip_dport-"]
    else:
        key = [(5, 3), (3, 5)]
        key_name = ["dip-", "sip-"]
    
    print(f"Grouping packets by {[key_name[i] for i in range(len(key_name))]}")

    isall = False
    if group_type == 'all':
        isall = True

    topn_data = group(data, key=key, card_th=card_th, all=isall)
    clusters = {}

    print("Clustering")
    summary_list = []
    # per key(DIP||DPORT, ...)

    packet_idx_dict = dict()

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
            """
            if len(X) > 1000 and raid(X, threshold, 256, 3, earlystop=True) == False:
                print("earlystop", group_dir)
                continue
            """

            result_dict = raid(X, threshold, 256, 3, group_dir)

            clusters[key_name[k] + i[0]] = list(result_dict.keys())

            packet_idx_dict[group_dir] = [list() for _ in range(len(result_dict))]
            for cluster_idx in result_dict.keys():
                packet_idx_dict[group_dir][cluster_idx] += result_dict[cluster_idx][
                    "idx"
                ]

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
                    decode_X, hh1_size=1024, hh2_size=200, ratio=0.6, deduplication=deduplication
                )
                ret = [
                    [encode_hex(x[0], israw=israw), x[1]]
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
                compare_key = "decoded payload"
                if israw == True:
                    compare_key = "raw payload"

                ## finding actual signature frequency with string matching
                if iscount:
                    nxt_ret = []
                    for x, _ in ret:
                        count = 0
                        for payload in c_dict[compare_key]:
                            if x in payload:
                                count += 1
                        nxt_ret.append([x, count])
                    ret = nxt_ret

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
                        key_card.add(i[1][0][idx])

                group_unique_packet = set()
                for payload in X:
                    payload = payload[0]
                    group_unique_packet.add(payload)

                summary_list.append(
                    [
                        key_name[k] + i[0],
                        len(set(i[1][0])),
                        len(i[1][1]),
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
        os.path.join(result_path, "all_cluster_signatures.csv"),
        [
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
        ],
        summary_list,
    )

    write_csv(
        os.path.join(result_path, "group_signatures.csv"),
        [
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
        ],
        one_big_cluster_list,
    )

    SummaryGraph(result_path)

    """
    print("Extracting pcaps")
    filter_data = []
    for l in tqdm(range(len(topn_data)), desc="Extracting filter data"):
        filter_data.append(set([]))
        for i in topn_data[l]:
            for _ in i:
                filter_data[l].add((i[0].split("_")[0], i[0].split("_")[1]))
    """

    extract_pcap_cl_v2(packet_idx_dict, pcap_dir)
    """
    tshark or scapy on the last value
    tshark is currently not confirmed to stable
    """
    # extract_pcap(filter_data, pcap_dir, result_path, "tshark")


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
        "-g",
        "--group",
        required=False,
        default="ip_dport",
        help="select grouping type: [ip_dport, ip, all] | Default : ip_dport",
    )
    argparser.add_argument(
        "-r",
        "--israw",
        required=False,
        default="False",
        help="True if you don't want to convert signature to ASCII | Default : False",
    )
    argparser.add_argument(
        "-d",
        "--deduplication",
        required=False,
        default="False",
        help="True if you want deduplication | Default : False",
    )
    argparser.add_argument(
        "-co",
        "--count",
        required=False,
        default="False",
        help="True if you want actual count | Default : False",
    )
    args = argparser.parse_args()
    main(args)
