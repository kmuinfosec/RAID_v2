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
