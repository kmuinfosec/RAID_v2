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
def get_dir_result(path, dir=False):
    
    if not os.path.exists(path):
        print('this path does not exist.')
        return 0 
    else:
        path_ = os.path.join(path, dir)
        if not os.path.exists(path_):
            dir_t = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            print('this direcotry does not exist.')
            path_ = os.path.join(path, dir_t)
            os.mkdir(path_)
        return path_

def parse_config(cfgs, args):
    args_dict = dict()
    args_dict['pcap_dir'] = args['pcap_dir'] if args['pcap_dir'] else cfgs["DEFAULT"]['pcap_dir']
    args_dict['cpu_count'] = eval(args['cpu_count']) if args['cpu_count'] else eval(cfgs["DEFAULT"]['cpu_count'])
    if args_dict['cpu_count'] == False:
        args_dict['cpu_count'] = os.cpu_count() // 2

    args_dict['result_path'] = get_dir_result(args['result_path'] if args['result_path'] else cfgs["DEFAULT"]['result_path'],\
                                    args['result_dir'] if args['result_dir'] else cfgs["DEFAULT"]['result_dir'])
    args_dict['threshold'] = float(args['threshold']) if args['threshold'] else float(cfgs["DEFAULT"]['threshold'])
    args_dict['card_th'] = int(args['card_th']) if args['card_th'] else int(cfgs["DEFAULT"]['card_th'])
    args_dict['group_type'] = args['group'] if args['group'] else cfgs["DEFAULT"]['group']
    args_dict['israw'] = eval(args['israw']) if args['israw'] else eval(cfgs["DEFAULT"]['israw'])
    args_dict['deduplication'] = eval(args['deduplication']) if args['deduplication'] else eval(cfgs["DEFAULT"]['deduplication'])
    args_dict['iscount'] = eval(args['count']) if args['count'] else eval(cfgs["DEFAULT"]['count'])
    args_dict['earlystop'] = eval(args['earlystop']) if args['earlystop'] else eval(cfgs["DEFAULT"]['earlystop'])
    args_dict['vector_size'] = int(args['vector_size']) if args['vector_size'] else int(cfgs["DEFAULT"]['vector_size'])
    args_dict['window_size'] = int(args['window_size']) if args['window_size'] else int(cfgs["DEFAULT"]['window_size'])
    args_dict['hh1_size'] = int(args['hh1_size']) if args['hh1_size'] else int(cfgs["DEFAULT"]['hh1_size'])
    args_dict['hh2_size'] = int(args['hh2_size']) if args['hh2_size'] else int(cfgs["DEFAULT"]['hh2_size'])
    args_dict['ratio'] = float(args['ratio']) if args['ratio'] else float(cfgs["DEFAULT"]['ratio'])
    args_dict['extension'] = args['extension'] if args['extension'] else cfgs["DEFAULT"]['extension']
    
    return args_dict

def write_csv(path, header, data):
    file = open(path, "w", newline="")
    writer = csv.writer(file)
    writer.writerow(header)
    writer.writerows(data)


def filter_null_payload(data, group_name):
    print(f"\n{group_name}\ttotal payloads : {len(data)}", end="")
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
