import sys
import os
import argparse

from Preprocess import preprocess
from SummaryGraph import SummaryGraph
from tqdm import tqdm

from Utils import get_dir, write_csv
from Raid import raid, detectCluster
from Group import group
from ToNUtils import doubleHeavyHitters
from SummaryGraph import SummaryGraph

# from Extract import extract


def main(args):
    pcap_dir = args.pcap_path
    result_dir = args.result_path
    result_path = args.result_name
    threshold = float(args.threshold)
    detect_type_flag = bool(args.is_group)
    isall = bool(args.is_all)

    print("Preprocessing pcap files")
    data = preprocess(
        pcap_dir, detect_type_flag, csv_path=os.path.join(result_path, "train_data.csv")
    )

    # (1, 3) means ('dip|dport', 'sip'), (2, 6) means('sip|dport', 'dip'), card_th == top_k cardinality
    if isall:
        key = ["all"]
    else:
        key = [(1, 3), (2, 5)]
    key_name = ["dip_dport", "sip_dport"]
    print(f"Grouping packets by {[key_name[i] for i in range(len(key_name))]}")
    topn_data_dict = group(data, key=key, card_th=5, all=isall)

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
                dhh_dir = get_dir(cluster_dir, "ToN_result")

                X = i[1][1]

                if len(X) > 1000 and detectCluster(X, threshold, 256, 3, sample=1000, detect_rate=0.4)==False:
                    print('earlystop -', cluster_dir)
                continue

                result_dict = raid(X, threshold, 256, 3, cluster_dir)

                # has common signatures for each cluster
                common_signatures = dict()
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
                    common_signature_result = [
                        [x[0], list(x[1])] for x in common_signatures.items()
                    ]
                    write_csv(
                        os.path.join(
                            cluster_dir, "cluster_common_signature_summary.csv"
                        ),
                        ["cluster", "common signatures"],
                        common_signature_result,
                    )

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
                        ]
                    )

        write_csv(
            os.path.join(detect_dir, "group_clustering_summary.csv"),
            [
                "group",
                "key_card",
                "group_packet",
                "cluster_key_card",
                "cluster",
                "cluster_packet",
            ],
            summary_list,
        )
        SummaryGraph(os.path.join(result_dir, detect_dir))


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument("pcap_path", help="input the path of the pcap files")
    argparser.add_argument("result_path", help="input the path of the result directory")
    argparser.add_argument(
        "result_name",
        help="Input the name of the result directory",
    )
    argparser.add_argument(
        "-t",
        "--threshold",
        required=False,
        default=0.6,
        help="Input the threshold of the clustering | Default : 0.6",
    )
    argparser.add_argument(
        "-g",
        "--is_group",
        required=False,
        default=False,
        help="Want to see in group | Default : False",
    )
    argparser.add_argument(
        "-a",
        "--is_all",
        required=False,
        default=False,
        help="Want to see all | Default : False",
    )
    args = argparser.parse_args()

    main(args)
