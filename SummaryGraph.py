import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os

def SummaryGraph(dir):
    main_df = pd.read_csv(os.path.join(dir, "group_clustering_summary.csv"))
    if int(main_df['cluster_key_card'].unique()) == 0:
        main_df['cluster_key_card'] = 1
    group_key_df = main_df[['group', 'key_card']]
    group_key_df = group_key_df.drop_duplicates()
    group_key_df = group_key_df.sort_values('key_card', ascending=False)

    x = []
    packet = []
    key_card = []
    cluster_count = []

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
    bar_width = 0.3
    alpha = 0.5

    # b0 = plt.bar(x2, value, color='g', width=bar_width, alpha=alpha, label='Packet Count')
    # b3 = plt.bar(x2, value, color='none', width=bar_width, alpha=alpha, label='Remain', edgecolor=['r'])
    # b4 = plt.bar(x2, value, color='b', width=bar_width, alpha=alpha, label='Opposite Cardinality')

    fig, ax1 = plt.subplots()

    bar_width = 0.3
    #for legend

    index = range(len(x))


    b1 = ax1.bar(index, packet, color='g', width=bar_width, alpha=alpha, label='Packet Count')
    ax1.set_ylabel('Packet Count')

    ax2 = ax1.twinx()
    ax2.set_ylabel('ClusterCount')
    b2 = ax2.bar([i + bar_width for i in index], cluster_count, color='b', width=bar_width, alpha=alpha, label='Cluster Count')

    legend = plt.legend(handles=(b1, b2))
    # plt.yticks(range(max(cluster_count) + 1, ))
    plt.title("Heavy Hitter Clutering Result(sort by cardinality)")
    plt.xlabel('Cluster Name')
    fig.autofmt_xdate(rotation=30)
    plt.xticks(np.arange(bar_width, len(x) + bar_width, 1), x)
    plt.savefig(os.path.join(dir, "group_summary_graph"), dpi=300)

    for i in group_key_df['group'].tolist():
        temp_df = main_df[main_df['group'] == i]
        remain = temp_df[temp_df['cluster'] == -1]
        temp_df = temp_df[temp_df['cluster'] != -1].sort_values('cluster_packet', ascending=False)
        
        x = range(11 if len(temp_df) > 10 else len(temp_df) + 1)
        x = [float(i) for i in x]
        value = [int(remain['cluster_packet'])] + temp_df['cluster_packet'][:(10 if len(temp_df) > 10 else len(temp_df))].tolist()
        card = [int(remain['cluster_key_card'])] + temp_df['cluster_key_card'][:(10 if len(temp_df) > 10 else len(temp_df))].tolist()

        clusters = ['Remain'] + temp_df['cluster'].tolist()[:10]
        
        x2 = [i - bar_width/2 for i in x]
        x1 = [i + bar_width/2 for i in x]
        
        bar_width = 0.3
        alpha = 0.5

        b0 = plt.bar(x2, value, color='g', width=bar_width, alpha=alpha, label='Packet Count')
        b3 = plt.bar(x2, value, color='none', width=bar_width, alpha=alpha, label='Remain', edgecolor=['r'])
        b4 = plt.bar(x2, value, color='b', width=bar_width, alpha=alpha, label='Cardinality')

        fig, ax1 = plt.subplots()
        #for legend

        b1 = ax1.bar(x2, value, color='g', width=bar_width, alpha=alpha, label='Packet Count', edgecolor=['r'] + ['w'] * (len(x)-1))
        ax1.set_ylabel('Packet Count')
        ax2 = ax1.twinx()
        ax2.set_ylabel('Cardinality')
        b2 = ax2.bar(x1, card, color='b', width=bar_width, alpha=alpha, label='Cardinality', edgecolor=['r'] + ['w'] * (len(x)-1))
        legend = plt.legend(handles=(b0, b4, b3))
        plt.yticks(range(max(card) + 1))
        plt.title(main_df['group'].tolist()[0])
        # plt.xlabel('Cluster Name')
        plt.xticks(x, clusters)
        plt.savefig(os.path.join(dir, i, 'cluster_summary_graph'), dpi=300)