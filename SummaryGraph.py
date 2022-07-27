import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os


def SummaryGraph(result_path):
    main_df = pd.read_csv(os.path.join(result_path, "group_signatures.csv"))
    # if len(main_df["cluster_key_card"].unique()) == 0:
    #     main_df["cluster_key_card"] = 1
    group_key_df = main_df[
        [
            "group",
            "key_card",
            "group_packet",
            "biggest_cluster",
            "cluster_packet",
            "occurrence of most frequent signature",
        ]
    ]
    group_key_df = group_key_df.drop_duplicates()
    group_key_df = group_key_df.sort_values("key_card", ascending=False)

    x = []
    packet = []
    bigcluster_packets = []
    most_occurrence_signature = []

    for group in group_key_df["group"].tolist():
        sub_df = group_key_df[group_key_df["group"] == group]
        group_summary = sub_df.values.tolist()
        x.append(group_summary[0][0])
        packet.append(group_summary[0][2])

        if len(sub_df[sub_df["biggest_cluster"] != -1]) != 0:
            bigcluster_packets.append(group_summary[0][4])
        else:
            bigcluster_packets.append(0)
        most_occurrence_signature.append(group_summary[0][5])

    alpha = 0.7
    bar_width = 0.2
    fig, ax1 = plt.subplots(figsize=(20, 4))

    index = range(0, len(x) * 2, 2)
    index2 = np.arange(-0.3, len(x) * 2 - 2, 2)

    ax1.set_xticks(index)
    ax1.set_xticks(index2, minor=True)
    ax1.grid(which="major", alpha=0, axis="x")
    ax1.grid(which="minor", alpha=1, axis="x")

    b1 = plt.bar(
        [0.4 + i for i in index],
        packet,
        color="limegreen",
        width=bar_width,
        alpha=alpha,
        zorder=3,
        align="center",
        label="All Packets",
    )
    b2 = plt.bar(
        [0.5 + i + bar_width for i in index],
        bigcluster_packets,
        color="darkgreen",
        width=bar_width,
        zorder=3,
        align="center",
        label="Largest-cluster Packets",
    )
    b3 = plt.bar(
        [0.8 + i + bar_width for i in index],
        most_occurrence_signature,
        color="yellow",
        width=bar_width,
        zorder=3,
        align="center",
        label="Mode Signature Count",
    )
    plt.legend(handles=(b1, b2, b3))
    plt.yticks(range(max(packet) + 1))
    plt.title("Group Cluster Result(sort by cardinality)")
    plt.xlabel("Group Name")
    plt.ylabel("Count")
    plt.yscale("log")
    plt.grid()
    plt.tight_layout()
    plt.xticks(np.arange(bar_width + 0.5, len(index) * 2 + bar_width, 2), x, fontsize=8)
    plt.savefig(
        os.path.join(result_path, "group_summary_graph.png"),
        dpi=300,
        facecolor="#eeeeee",
        transparent=True,
        bbox_inches="tight",
    )
    plt.clf()

    main_df = pd.read_csv(os.path.join(result_path, "all_cluster_signatures.csv"))
    if len(main_df["cluster_key_card"].unique()) == 0:
        main_df["cluster_key_card"] = 1
    group_key_df = main_df[["group", "key_card"]]

    for i in group_key_df["group"].tolist():
        temp_df = main_df[main_df["group"] == i]
        remain = temp_df[temp_df["cluster"] == -1]
        temp_df = temp_df[temp_df["cluster"] != -1].sort_values(
            "cluster_packet", ascending=False
        )

        x = range(11 if len(temp_df) > 10 else len(temp_df) + 1)
        x = [float(i) for i in x]

        if len(remain) == 0:
            remain_packet = 0
            remain_card = 0
        else:
            remain_packet = int(remain["cluster_packet"])
            remain_card = int(remain["cluster_key_card"])
        value = [remain_packet] + temp_df["cluster_packet"][
            : (10 if len(temp_df) > 10 else len(temp_df))
        ].tolist()
        card = [remain_card] + temp_df["cluster_key_card"][
            : (10 if len(temp_df) > 10 else len(temp_df))
        ].tolist()
        clusters = ["Remain"] + temp_df["cluster"].tolist()[:10]

        x2 = [i - bar_width / 2 for i in x]
        x1 = [i + bar_width / 2 for i in x]

        bar_width = 0.3
        alpha = 0.5

        #     b0 = plt.bar(x2, value, color='g', width=bar_width, alpha=alpha, label='Packet Count')
        #     b3 = plt.bar(x2, value, color='none', width=bar_width, alpha=alpha, label='Remain', edgecolor=['r'])
        #     b4 = plt.bar(x2, value, color='b', width=bar_width, alpha=alpha, label='Cardinality')

        #     fig, ax1 = plt.subplots()
        #     #for legend

        b1 = plt.bar(
            x2, value, color="g", width=bar_width, alpha=alpha, label="Packet Count"
        )
        plt.ylabel("Count")
        plt.yscale("log")
        #     ax2 = ax1.twinx()
        #     ax2.set_ylabel('Cardinality')
        b2 = plt.bar(
            x1, card, color="b", width=bar_width, alpha=alpha, label="Cardinality"
        )
        plt.legend()
        #     plt.yticks(range(max(card) + 1))
        if len(temp_df["group"].tolist()) != 0:
            plt.title(temp_df["group"].tolist()[0])
        plt.xticks(x, clusters)
        plt.savefig(
            os.path.join(result_path, i, "cluster_summary_graph.png"),
            dpi=300,
            facecolor="#eeeeee",
            transparent=True,
            bbox_inches="tight",
        )
        plt.clf()
