import numpy as np
import hashlib

def decode(payload):

    ans = str()
    for i in range(0, len(payload), 2):
        data = payload[i:i+2]
        data_hex = int('0x'+data, 16)
            
        if 0x20 <= data_hex < 0x7F:
            data = chr(data_hex)
        ans += data
    return ans

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
        vector = [0] * vec_size
        for chunk in AE2(per_data, win_size):
            chunk_fh = int(hashlib.md5(chunk.encode()).hexdigest(),16) % vec_size
            vector[chunk_fh] += 1
        vectors.append(np.array(vector))
    return vectors