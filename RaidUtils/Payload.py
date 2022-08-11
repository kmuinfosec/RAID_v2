import numpy as np
import hashlib


def decode(payload):

    ans = str()
    for i in range(0, len(payload), 2):
        data = payload[i : i + 2]
        data_hex = int("0x" + data, 16)

        if 0x20 <= data_hex < 0x7F:
            data = chr(data_hex)
        ans += data
    return ans

def AE2(_str, window_size):
    bytes_len = len(_str)
    chunk_bytes_list = []
    byte_idx = 0
    byte_arr = []
    while byte_idx < bytes_len:
        max_value = int(_str[byte_idx:byte_idx+2], 16)
        max_position = byte_idx
        byte_arr.append(_str[byte_idx:byte_idx+2])
        byte_idx += 2
        while byte_idx < bytes_len:
            if int(_str[byte_idx:byte_idx+2], 16) <= max_value:
                if byte_idx == max_position + 2 * window_size:
                    byte_arr.append(_str[byte_idx:byte_idx+2])
                    content_bytes = "".join(byte_arr)
                    chunk_bytes_list.append(content_bytes)
                    byte_arr = []
                    byte_idx += 2
                    break
            else:
                max_value = int(_str[byte_idx:byte_idx+2], 16)
                max_position = byte_idx
            byte_arr.append(_str[byte_idx:byte_idx+2])
            byte_idx += 2
    if len(byte_arr):
        content_bytes = "".join(byte_arr)
        chunk_bytes_list.append(content_bytes)
    return chunk_bytes_list


def contents2count(return_data, vec_size, win_size):
    vectors = []
    for per_data in return_data:
        vector = [0] * vec_size
        for chunk in AE2(per_data, win_size):
            chunk_fh = int(hashlib.md5(chunk.encode()).hexdigest(), 16) % vec_size
            vector[chunk_fh] += 1
        vectors.append(np.array(vector))
    return vectors
