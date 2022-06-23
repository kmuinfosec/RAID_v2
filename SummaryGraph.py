import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os

def SummaryGraph(dir):
    main_df = pd.read_csv(os.path.join(dir, "group_clustering_summary.csv"))
    if len(main_df['cluster_key_card'].unique()) == 0:
        main_df['cluster_key_card'] = 1
    group_key_df = main_df[['group', 'key_card']]
    group_key_df = group_key_df.drop_duplicates()
    group_key_df = group_key_df.sort_values('key_card', ascending=False)

    x = []
    packet = []
    key_card = []
    cluster_count = []
    cluster_packets = []

    for i in group_key_df['group'].tolist():
        temp_df = main_df[main_df['group'] == i]
        temp = temp_df.values.tolist()
        x.append(temp[0][0])
        packet.append(temp[0][2])
        key_card.append(temp[0][1])
        if len(temp_df) == len(temp_df[temp_df['cluster'] != -1]):
            cluster_count.append(len(temp_df))
        else:
            cluster_count.append(len(temp_df) - 1)
        c_packets = []
        if len(temp_df[temp_df['cluster'] == -1]) == 0:
            c_packets.append(0)
        else:
            c_packets.append(temp_df[temp_df['cluster'] == -1]['cluster_packet'].values[0])
        if len(temp_df[temp_df['cluster'] != -1]) != 0:
            c_packets.append(sorted(temp_df[temp_df['cluster'] != -1]['cluster_packet'].tolist(), reverse=True)[0])
        cluster_packets.append(c_packets)

    print(cluster_count)
    bar_width = 0.3
    alpha = 1

    # b0 = plt.bar(x2, value, color='g', width=bar_width, alpha=alpha, label='Packet Count')
    # b3 = plt.bar(x2, value, color='none', width=bar_width, alpha=alpha, label='Remain', edgecolor=['r'])
    # b4 = plt.bar(x2, value, color='b', width=bar_width, alpha=alpha, label='Opposite Cardinality')

    bar_width = 0.3
    #for legend

    index = range(len(x))


    b1 = plt.bar(index, packet, color='limegreen', width=bar_width, alpha=alpha, label='Packet Count', edgecolor='g')
    b2 = plt.bar([i + bar_width for i in index], cluster_count, color='b', width=bar_width, alpha=alpha, label='Cluster Count')

    for i in range(len(x)):
        if len(cluster_packets[i]) == 2:
            b4 = plt.bar(index[i], sum(cluster_packets[i][:2]), color = 'limegreen', label='Biggest Cluster', width=bar_width, alpha=alpha, edgecolor='black')
        b3 = plt.bar(index[i], cluster_packets[i][0], color = 'darkgreen', label='Remain', width=bar_width, alpha=1, edgecolor='black')
    if 'b4' in locals():
        plt.legend(handles=(b1, b2, b3, b4))
    else:
        plt.legend(handles=(b1, b2, b3))
    # plt.yticks(range(max(cluster_count) + 1, ))
    plt.title("Group Cluster Result(sort by cardinality)")
    plt.xlabel('Cluster Name')
    plt.ylabel('Count')
    plt.yscale('log')
    plt.xticks(np.arange(bar_width/2, len(x) + bar_width/2, 1), x, fontsize = 8, rotation=25, ha='right', rotation_mode='anchor')
    plt.savefig(os.path.join(dir, "group_summary_graph"), dpi=300, facecolor='#eeeeee',transparent=True,bbox_inches='tight')
    plt.clf()
    for i in group_key_df['group'].tolist():
        temp_df = main_df[main_df['group'] == i]
        remain = temp_df[temp_df['cluster'] == -1]
        temp_df = temp_df[temp_df['cluster'] != -1].sort_values('cluster_packet', ascending=False)
        
        x = range(11 if len(temp_df) > 10 else len(temp_df) + 1)
        x = [float(i) for i in x]
        
        if len(remain) == 0:
            remain_packet = 0
            remain_card = 0
        else:
            remain_packet = int(remain['cluster_packet'])
            remain_card = int(remain['cluster_key_card'])
        value = [remain_packet] + temp_df['cluster_packet'][:(10 if len(temp_df) > 10 else len(temp_df))].tolist()
        card = [remain_card] + temp_df['cluster_key_card'][:(10 if len(temp_df) > 10 else len(temp_df))].tolist()
        clusters = ['Remain'] + temp_df['cluster'].tolist()[:10]
        
        x2 = [i - bar_width/2 for i in x]
        x1 = [i + bar_width/2 for i in x]
        
        bar_width = 0.3
        alpha = 0.5

    #     b0 = plt.bar(x2, value, color='g', width=bar_width, alpha=alpha, label='Packet Count')
    #     b3 = plt.bar(x2, value, color='none', width=bar_width, alpha=alpha, label='Remain', edgecolor=['r'])
    #     b4 = plt.bar(x2, value, color='b', width=bar_width, alpha=alpha, label='Cardinality')

    #     fig, ax1 = plt.subplots()
    #     #for legend

        b1 = plt.bar(x2, value, color='g', width=bar_width, alpha=alpha, label='Packet Count')
        plt.ylabel('Count')
        plt.yscale('log')
    #     ax2 = ax1.twinx()
    #     ax2.set_ylabel('Cardinality')
        b2 = plt.bar(x1, card, color='b', width=bar_width, alpha=alpha, label='Cardinality')
        plt.legend()
    #     plt.yticks(range(max(card) + 1))
        plt.title(temp_df['group'].tolist()[0])
        plt.xticks(x, clusters)
        plt.savefig(os.path.join(dir, i, 'cluster_summary_graph.png'), dpi=300, facecolor='#eeeeee',transparent=True,bbox_inches='tight')
        plt.clf()