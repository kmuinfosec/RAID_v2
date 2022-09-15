import os
import csv

from datetime import datetime


def get_dir(path, dir=False):
    if not dir:
        dir = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path_ = os.path.join(path, dir)
    if not os.path.exists(path_):
        os.mkdir(path_)

    return path_

def parse_config(cfgs):
    args_dict = dict()
    args_dict['pcap_dir'] = cfgs["DEFAULT"]['pcap_dir']
    args_dict['cpu_count'] = eval(cfgs["DEFAULT"]['cpu_count'])
    args_dict['result_path'] = get_dir(cfgs["DEFAULT"]['result_path'], cfgs["DEFAULT"]['result_dir'])
    args_dict['threshold'] = float(cfgs["DEFAULT"]['threshold'])
    args_dict['card_th'] = int(cfgs["DEFAULT"]['card_th'])
    args_dict['group_type'] = cfgs["DEFAULT"]['group']
    args_dict['israw'] = eval(cfgs["DEFAULT"]['israw'])
    args_dict['deduplication'] = eval(cfgs["DEFAULT"]['deduplication'])
    args_dict['iscount'] = eval(cfgs["DEFAULT"]['count'])
    args_dict['earlystop'] = eval(cfgs["DEFAULT"]['earlystop'])
    args_dict['vector_size'] = int(cfgs["DEFAULT"]['vector_size'])
    args_dict['window_size'] = int(cfgs["DEFAULT"]['window_size'])
    args_dict['hh1_size'] = int(cfgs["DEFAULT"]['hh1_size'])
    args_dict['hh2_size'] = int(cfgs["DEFAULT"]['hh2_size'])
    args_dict['ratio'] = float(cfgs["DEFAULT"]['ratio'])
    
    return args_dict

def write_csv(path, header, data):
    file = open(path, "w", newline="")
    writer = csv.writer(file)
    writer.writerow(header)
    writer.writerows(data)


def filter_null_payload(data):
    print(f"total payloads : {len(data)}", end="")
    data = list(filter(lambda x: len(x[0]), data))
    print(f"\tfiltered 0-size payloads : {len(data)}")
    return data


def get_payloads_by_index(X, indices):
    return [X[idx][0] for idx in indices]


def decode_ascii(payload):
    arr, cur = [], ''
    for char in payload:
        cur += char
        if len(cur)==2:
            data_hex = int('0x' + cur, 16)
            arr.append(chr(data_hex))
            cur = ''
    
    return ''.join(arr)


def encode_hex(payload, israw=False):
    ans = []
    for char in payload:
        if israw==True:
            ans.append(hex(ord(char))[2:].rjust(2, '0'))
        else:
            data_hex = (ord(char))
            if 0x20 <= data_hex < 0x7F:
                ans.append(char)
            else:
                ans.append(hex(ord(char))[2:].rjust(2, '0'))
    return ''.join(ans)
