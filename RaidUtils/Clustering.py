import numpy as np

from sklearn.cluster import AgglomerativeClustering

from .Cosine import (
    getCosinePairwise,
    getAverageVector,
    getCosineSimilarity,
    getProxyDistance,
)


def prototypeClustering(x_data, th, opt1=True):

    ready_list = [i for i in range(0, len(x_data))]
    label_list = [-1] * len(x_data)

    cluster_idx = 0
    nxt_idx = 0

    if opt1:
        cos_mat = getCosinePairwise(x_data)

    while len(ready_list) != 0:
        temp_ready_list = []
        src_idx = nxt_idx
        nxt_score = 1
        cluster_count = 0

        for trg_idx in ready_list:

            if opt1:
                score = cos_mat[src_idx][trg_idx]
            else:
                score = getCosineSimilarity(x_data[src_idx], x_data[trg_idx])

            if score >= th:
                label_list[trg_idx] = cluster_idx
                cluster_count += 1
            else:
                temp_ready_list.append(trg_idx)

            if nxt_score > score:
                nxt_score = score
                nxt_idx = trg_idx

        if cluster_count == 1:
            label_list[src_idx] = -1
            cluster_idx -= 1

        ready_list = temp_ready_list
        cluster_idx += 1

    return label_list


def hierarchicalClustering(x_data, prev_label_list, th):

    cluster_list = [[] for _ in range(max(prev_label_list) + 1)]
    for i, label in enumerate(prev_label_list):
        if label != -1:
            cluster_list[label].append(i)

    centroid_list = []
    for idxs in cluster_list:
        vectors = [x_data[i] for i in idxs]
        centroid_list.append(getAverageVector(vectors))

    if len(centroid_list) == 0:
        return prev_label_list
    elif len(centroid_list) == 1:
        labels = np.array([0])
    else:
        labels = (
            AgglomerativeClustering(
                n_clusters=None,
                affinity=getProxyDistance,
                linkage="single",
                distance_threshold=1 - th,
            )
            .fit(centroid_list)
            .labels_
        )

    label_list = []
    for i in range(len(x_data)):
        prev = prev_label_list[i]
        if prev == -1:
            label_list.append(-1)
        else:
            label_list.append(labels[prev])

    return label_list
