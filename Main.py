import os
from tqdm.auto import tqdm
from types import SimpleNamespace
from collections import Counter

from Utils import get_dir, write_csv, filter_null_payload, get_payloads_by_index, decode_ascii, encode_hex
from Utils import hex2PrintableByte
from Utils import CUniqCounts
from Preprocess import preprocess
from Group import group
from Raid import raid
from DHHUtils import doubleHeavyHitters
from SummaryGraph import SummaryGraph
from Extract import extract
from Match import match

GROUP_SIGNATURES_COLUMN = [
    "group", # 0
    "key_card", # 1
    "group_packet", # 2
    "group_unique_packet", # 3
    "clusters", # 4
    "biggest_cluster", # 5
    "cluster_key_card", # 6
    "cluster_packet", # 7
    "cluster_unique_packet", # 8
    "occurrence of most frequent signature", # 9
    "common signatures", # 10
    "num_of_clusters", # 11
    "signature_match_ratio", # 12
    "match_ratio_sig_main_info", #13
    "packet_match_ratio", # 14
    "match_ratio_pkt_main_info", #15
    "signature_match_ratio_-1", #16
    "match_ratio_sig_main_info", #17
    "packet_match_ratio_-1", #18
    "match_ratio_pkt_main_info", #19
    "cs_str_list", #20
    "cs_list_cnts", #21
    "remain_cluster_cnts", #22
    "uniq_src_ip_list_topN", #23
    "uniq_src_ip_list_cnts", #24
    "uniq_src_port_list_topN", #25
    "uniq_src_port_list_cnts", #26
    "uniq_dst_ip_list_topN", #27
    "uniq_dst_ip_list_cnts", #28
    "uniq_dst_port_list_topN", #29
    "uniq_dst_port_list_cnts", #30
]

ALL_CLUSTER_SIGNATURES_COLUMN = [
    "group", # 0
    "key_card", # 1
    "group_packet", # 2
    "group_unique_packet", # 3
    "cluster_key_card", # 4
    "cluster", # 5
    "cluster_packet", # 6
    "cluster_unique_packet", #7
    "occurrence of most frequent signature", # 8
    "common signatures", # 9
    "signature_match_ratio", # 10
    "packet_match_ratio", # 11
    "cs_str_list", # 12
    "cs_list_cnts", # 13
    "match_ratio_sig_info", #14
    "match_ratio_pkt_info", #15
    "all_cs_len_sum", #16
    "all_pkt_len_mean", #17
    "pkt_unique_cnts", #18
]

KEY_DICT = {
    'all': (['all'], ['all_group-'], True),
    'ip': ([(4, 2), (2, 4)], ['dip-', 'sip-'], False),
    'ip_dport': ([(0, 2), (1, 4)], ["dip_dport-", "sip_dport-"], False),
}

gDictIP_PortGroup = {
        "uniq_src_ip_list": 2, # data index
        "uniq_dst_ip_list": 4,
        "uniq_src_port_list": 3,
        "uniq_dst_port_list": 5,
        }
gTopNtIP_PortGroup = 5

def main(args):
    n = SimpleNamespace(**args)

    data = preprocess(n.pcap_dir, n.pcap_list, n.cpu_count, n.extension)

    # UniqCnt Calculate
    instUniqCnt = CUniqCounts(data)
    instUniqCnt.setSummaryGroup(gDictIP_PortGroup) 
    instUniqCnt.calculate()
    szUniqSrcIPList = str(instUniqCnt.getTopNList("uniq_src_ip_list",
        gTopNtIP_PortGroup)) # GROUP-18
    nUniqSrcIPLen = instUniqCnt.getLength("uniq_src_ip_list")
    szUniqSrcPortList = str(instUniqCnt.getTopNList("uniq_src_port_list",
        gTopNtIP_PortGroup))
    nUniqSrcPortLen = instUniqCnt.getLength("uniq_src_port_list")

    szUniqDstIPList = str(instUniqCnt.getTopNList("uniq_dst_ip_list",
        gTopNtIP_PortGroup))
    nUniqDstIPLen = instUniqCnt.getLength("uniq_dst_ip_list")
    szUniqDstPortList = str(instUniqCnt.getTopNList("uniq_dst_port_list",
        gTopNtIP_PortGroup))
    # GROUP-26
    nUniqDstPortLen = instUniqCnt.getLength("uniq_dst_port_list")

    
    key, key_name, isall = KEY_DICT[n.group_type]

    topn_data = group(data, key=key, key_name=key_name, card_th=n.card_th, all=isall)

    summary_list = []
    clusters = {}
    packet_idx_dict = dict()

    group_key_pair = []
    for key_idx in range(len(key)):
        group_key_pair += [(key_idx, group_info) for group_info in topn_data[key_idx]]
    
    for key_idx, group_info in tqdm(group_key_pair, desc='Processing RAID and DHH'):
        group_dir = get_dir(n.result_path, key_name[key_idx] + group_info[0])
        dhh_dir = get_dir(group_dir, "DHH_result")
        cluster_dir = get_dir(group_dir, "Clustering_result")

        X = filter_null_payload(group_info[1][1], key_name[key_idx] + group_info[0])
        payloads = [x[0] for x in X]

        if len(X) == 0:
            print("Skip: No packet with application payload in this group")
            # continue
        if len(set(payloads)) == 1:
            print("Skip: All of payloads are same in this group")
#            continue
        if n.earlystop and len(X) > 1000 and raid(X, n.threshold, n.vector_size, n.window_size, earlystop=True) == False:
            print("Earlystop", group_dir)
            continue

        result_dict = raid(X, n.threshold, n.vector_size, n.window_size, group_dir)

        clusters[key_name[key_idx] + group_info[0]] = list(result_dict.keys())

        packet_idx_dict[group_dir] = dict()
        for cluster_idx in result_dict.keys():
            if cluster_idx not in packet_idx_dict[group_dir].keys():
                packet_idx_dict[group_dir][cluster_idx] = []
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
                os.path.join(dhh_dir, f"{ci}_result_DHH.csv"),
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
            
            common_signatures_set = set(common_signatures[ci])

            sorted_common_signatures = sorted(common_signatures[ci], key=lambda x: len(x), reverse=True)

            for idx in range(len(sorted_common_signatures) - 1):
                s = sorted_common_signatures[idx]
                for s_p in sorted_common_signatures[idx+1:]:
                    if s_p in common_signatures_set:
                        if s_p in s:
                            common_signatures_set.remove(s_p)

            lst_cs_str_list, cs_list_cnts = (
                    hex2PrintableByte(common_signatures[ci]))
            cluster_all_pkts = len(c_dict["decoded AE"])
            all_cs_len_sum = sum([len(sig) for sig in common_signatures_set])
            all_pkt_len_mean = (sum([len(encode_hex(pay, n.israw)) for pay in c_dict["decoded payload"]])/len(c_dict["decoded AE"]))
            most_freq_pkt_uniq_cnts = Counter(c_dict["decoded payload"]).most_common()[0][1]
            summary_list.append(
                [
                    key_name[key_idx] + group_info[0],
                    len(set(group_info[1][0])) if n.group_type != 'all' else 0,
                    len(group_info[1][1]),
                    len(group_unique_packet),
                    len(key_card) if n.group_type != 'all' else 0,
                    ci,
                    cluster_all_pkts,
                    len(set(c_dict["decoded payload"])),
                    ret[0][1] if len(ret) > 0 else 0,
                    common_signatures[ci],
                    round(all_cs_len_sum/all_pkt_len_mean,3),
                    round(most_freq_pkt_uniq_cnts/cluster_all_pkts, 3),
                    lst_cs_str_list, cs_list_cnts,
                    (all_cs_len_sum,all_pkt_len_mean),
                    (most_freq_pkt_uniq_cnts,cluster_all_pkts),
                    all_cs_len_sum,
                    all_pkt_len_mean,
                    most_freq_pkt_uniq_cnts,
                    
                ]
            )

    one_big_cluster_list = []
    keys = set(x[0] for x in summary_list)
    summary_list.sort(key=lambda x: x[4], reverse=True)
    for key in keys:
        summary_group = []
        filtered_summary = []
        summary_group = list(filter(lambda x: x[0] == key, summary_list))
        filtered_summary = list(filter(lambda x: x[5] != -1, summary_group))
        remain = list(filter(lambda x: x[5] == -1, summary_group))[0]

        if len(filtered_summary) > 0:
            max_card = max([i[4] for i in filtered_summary])
            one_big_cluster = max(list(filter(lambda x: x[4] == summary_group[0][4], summary_group)), key=lambda x: x[6])
            filtered_summary.sort(key = lambda x: x[6], reverse=True)
        else:
            one_big_cluster = max(summary_group, key=lambda x: x[4])
        num_of_cluster = len(filtered_summary)
        

        signature_match_ratio = [(clu[5], clu[10]) for clu in filtered_summary[:5]]
        packet_match_ratio = [(clu[5], clu[11]) for clu in filtered_summary[:5]]
        signature_match_ratio_info = [(clu[5], clu[13]) for clu in filtered_summary[:5]]
        packet_match_ratio_info = [(clu[5], clu[14]) for clu in filtered_summary[:5]]
        if len(remain) == 0:
            remain = [0] * len(summary_list[0])
        signature_match_ratio_remain= remain[10]
        packet_match_ratio_remain = remain[11]
        signature_match_ratio_remain_info= remain[13]
        packet_match_ratio_remain_info = remain[14]
        
        remain_cluster_cnts = len(clusters[key]) - num_of_cluster
        one_big_cluster = (
            # 0~ 3
            one_big_cluster[:4] +
            # 4
            [len(clusters[key])] +
            # 5,6,7,8,9,10
            one_big_cluster[4:4+6] +
            # 11
            [num_of_cluster] +
            # 12
            [signature_match_ratio] +
            # 13
            [signature_match_ratio_info] +
            # 14
            [packet_match_ratio] +
            # 15
            [packet_match_ratio_info] +
            # 16
            [signature_match_ratio_remain] +
            # 17
            [signature_match_ratio_remain_info] +
            # 18
            [packet_match_ratio_remain] +
            # 19
            [packet_match_ratio_remain_info] +
            # 20, 21 cs_str_list,cs_list_cnts
            [ one_big_cluster[12], one_big_cluster[13] ] +
            # 22 remain_cluster_cnts
            [remain_cluster_cnts] +
            # 23 ~ 27
            [szUniqSrcIPList, nUniqSrcIPLen, szUniqSrcPortList, nUniqSrcPortLen] +
            # 28~ 32
            [szUniqDstIPList, nUniqDstIPLen, szUniqDstPortList, nUniqDstPortLen]
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

    print("Making Summary Graph")
    SummaryGraph(n.result_path)

    print("Extracting PCAP for each cluster")
    extract(packet_idx_dict, n.pcap_dir, n.cpu_count)

    print("Making Regex Matching Result")
    match(n.result_path, n.regex_path)
