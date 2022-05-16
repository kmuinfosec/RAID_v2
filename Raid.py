import hashlib
import pickle
import time
import numpy as np
from tqdm import tqdm
from sklearn.cluster import AgglomerativeClustering

from numpy import dot
from numpy.linalg import norm
import numpy as np
from sklearn.metrics import pairwise_distances

import os
import pandas as pd
from datetime import datetime

TIMEOUT = 120999999999
LIMIT = 500

def AE2(_input , w):
    if(_input==None):
        return ""
    result = []
    input_size = len(_input)
    m = _input[:2]
    last_index = 0
    recent_index = 0
    window_count = 0
    appned_index = 0
    while(recent_index < input_size):
        if (window_count > w):
            result.append(_input[last_index:recent_index])
            last_index = recent_index
            m = _input[recent_index-2:recent_index]
            window_count = 0
            appned_index = recent_index
        elif (_input[recent_index] > m):
            window_count = 0
            m = _input[recent_index-2:recent_index]
        recent_index = recent_index+2
        window_count = window_count+1
    if(appned_index <= input_size-1):
        result.append(_input[last_index:recent_index])
    return result

def contents2count(return_data, vec_size, win_size):
    vectors = []
    for per_data in return_data:
        fh = [0 for i in range(0, vec_size)]
        for chunk in AE2(per_data, win_size):
            chunk_fh = int(hashlib.md5(chunk.encode()).hexdigest(),16)%vec_size
            fh[chunk_fh] = fh[chunk_fh] + 1
        vectors.append(fh)
    return vectors

def cosine_pairwise(A):
    A = np.array(A)
    similarity = np.dot(A, A.T)
    square_mag = np.diag(similarity)
    inv_square_mag = 1 / square_mag
    inv_square_mag[np.isinf(inv_square_mag)] = 0
    inv_mag = np.sqrt(inv_square_mag)
    cosine = similarity * inv_mag
    cosine = cosine.T * inv_mag
    return cosine

def getAvgVec(rd, vector):
    vec_size = len(vector[0])
    av = [0] * vec_size
    for idx in rd:
        for i in range(vec_size):
            av[i] += vector[idx][i]
    for i in range(vec_size):
        av[i] /= len(rd)
    return av

def cos_sim_reverse(A, B):
       return 1 - dot(A, B)/(norm(A)*norm(B))
    
def proxy_distance(X):
    return pairwise_distances(X, metric=cos_sim_reverse)

def cos_sim(A, B):
    return dot(A, B)/(norm(A)*norm(B))

def prototype_clustering(df, th, vector_size, window_size, detectname):
    result_data = {}
    vectors = {}
    loss = {}
    remain_key = []
    
    payload_list = df
    labels = [1 for _ in range(len(df))]
    x_data = contents2count(payload_list, vector_size, window_size)

    sim_data_list = []
    temp_loss = []
    remain_data_list = [i for i in range(0,len(x_data))]
    cluster_count = 1
    start = time.time()
    optFlag = False

    if len(x_data) <= LIMIT:
        cosMat = cosine_pairwise(x_data)
        optFlag = True

    nxt_idx = 0
    real_remain = []
    isTimeOut = False
    while len(remain_data_list)!=0:
        src_idx = nxt_idx
        nxt_score = 1
        sim_data_list = []
        temp_loss = []
        temp_remain_data_list = []

        for trg_idx in remain_data_list:
            if optFlag == False:
                score = cos_sim(x_data[src_idx], x_data[trg_idx])
            else:
                score = cosMat[src_idx][trg_idx]

            if score >= th:
                sim_data_list.append(trg_idx)
                temp_loss.append(th-score)
            else:
                temp_remain_data_list.append(trg_idx)

            if nxt_score > score:
                nxt_score = score
                nxt_idx = trg_idx

        if len(sim_data_list)==1:
            real_remain.append(src_idx)
        else:    
            result_data[detectname+f"^Clustering_{cluster_count}"] = sim_data_list
            loss[detectname+f"^loss_{cluster_count}"] = temp_loss
            cluster_count +=1
        remain_data_list = temp_remain_data_list

        if(time.time() - start >= TIMEOUT):
            isTimeOut = True
            for idx in range(1,cluster_count):
                del result_data[detectname+f"^Clustering_{idx}"]
                del loss[detectname+f"^loss_{idx}"] 
            remain_key.append({detectname:len(x_data)})
            print(detectname)
            break

    if (len(real_remain)!=0) and (isTimeOut==False):
        result_data[detectname+f"^Remain_{cluster_count}"] = real_remain
    vectors[detectname] = x_data
        
    return result_data, vectors, loss, remain_key, labels

def save_log(_result_data, _vectors, _remain_key, _loss, th, label_list, dirname):
    if not os.path.exists(dirname):
        os.mkdir(dirname)
    with open(os.path.join(dirname,"result_data.pkl"), "wb") as f:
        pickle.dump(_result_data,f)
    with open(os.path.join(dirname,"vectors.pkl"), "wb") as f:
        pickle.dump(_vectors,f)
    with open(os.path.join(dirname,"remain_key.pkl"), "wb") as f:
        pickle.dump(_remain_key,f)
    
    with open(os.path.join(dirname, f"result_{th}.csv"), "a") as f:
        f.write("DetectName, Ben, Mal, Purity, loss, avg_loss, events\n")
        for detectname in _result_data:
            ben = 0
            mal = 0
            index_data = _result_data[detectname]
            split_detectname = detectname.split("^")[:1][0]
            
            for index in index_data:
                label = int(label_list[index])
                if(label==0 or label==2):
                    ben +=1
                else:
                    mal +=1
                    
            if ("Remain" in detectname):
                f.write(f"{detectname},{ben},{mal},{max(ben,mal)/(ben+mal)},0,0,{ben+mal}\n")
            else:
                sum_loss = sum(_loss[detectname.replace("Clustering","loss")])
                len_loss = len(_loss[detectname.replace("Clustering","loss")])
                avg_loss = sum_loss/len_loss
                f.write(f"{detectname},{ben},{mal},{max(ben,mal)/(ben+mal)},{avg_loss},{th+abs(avg_loss)},{ben+mal}\n")

def hist_clustering(result_data, vectors, th, basepath):
    f = open(basepath+f'/result_{th}_merge.csv', 'w')
    f.write('DetectName,Ben,Mal,Purity,events\n')
    result_ = pd.read_csv(basepath+f'/result_{th}.csv')
    nxt_result_data = dict()

    for name in vectors.keys():    
        vectors_ = vectors[name]
            
        cluster = list()
        remain = None
        avgVecList = list()
            
        for i in range(1, 100000):
            if f'{name}^Clustering_{i}' in result_data.keys():
                cluster.append(result_data[f'{name}^Clustering_{i}'])
                av = getAvgVec(cluster[-1], vectors_)
                avgVecList.append(av)
            else:
                break

        if f'{name}^Remain_{i}' in result_data:
            remain_name = f'{name}^Remain_{i}'
            remain = result_data[f'{name}^Remain_{i}']
        if len(avgVecList)>1:
            labels = AgglomerativeClustering(n_clusters=None, affinity=proxy_distance, linkage='single',
                                        distance_threshold=1-th).fit(avgVecList).labels_
        elif len(avgVecList)==1:
            labels = np.array([0])

        last_idx = None
        if len(avgVecList)!=0:
            for i in range(max(labels)+1):
                idxs = np.where(labels==i)[0]
                recentname = name + f'^Clustering_{i+1}'
                last_idx = i+1
                nxt_result_data[recentname] = []

                ben = mal = 0
                for idx in idxs:
                    nxt_result_data[recentname] += result_data[f'{name}^Clustering_{int(idx)+1}']
                    aa = result_[result_['DetectName']==f'{name}^Clustering_{int(idx)+1}']
                    ben += sum(aa[' Ben'].astype('int'))
                    mal += sum(aa[' Mal'].astype('int'))
                purity = max(ben, mal)/(ben+mal)
                events = len(nxt_result_data[recentname])
                f.write(f'{recentname},{ben},{mal},{purity},{events}\n')

        if remain != None:
            if last_idx == None:
                recentname = name + f'^Remain_1'
            else:
                recentname = name + f'^Remain_{last_idx+1}'
            nxt_result_data[recentname] = remain
            aa = result_[result_['DetectName']==remain_name]
            ben = sum(aa[' Ben'].astype('int'))
            mal = sum(aa[' Mal'].astype('int'))
            purity = max(ben, mal)/(ben+mal)
            events = len(nxt_result_data[recentname])
            f.write(f'{recentname},{ben},{mal},{purity},{events}\n')
    
    with open(basepath+f'/result_data_merge.pkl', 'wb') as f:
        pickle.dump(nxt_result_data, f)
    f.close()

def raid(df, th, vector_size, window_size, detectName, savepath):
    result_data, vectors, loss, remain_key, labels = prototype_clustering(df, th, vector_size, window_size, detectName)
    save_log(result_data, vectors, remain_key, loss, th, labels, savepath)
    hist_clustering(result_data, vectors, th, savepath)
    return 0