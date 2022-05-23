
import os

from datetime import datetime

def get_dir(result_path, result_dir=False):
    if not result_dir:
        result_dir = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    if not os.path.exists(os.path.join(result_path, result_dir)):
        os.mkdir(os.path.join(result_path, result_dir))

    return os.path.join(result_path, result_dir)

def write_csv(result_path, header, data):
    col_num = len(data[0])
    format_str = '\t'.join(['{'+ str(i) +'}' for i in range(col_num)])
    with open(result_path, 'w') as f:
        f.write('\t'.join(header)+ '\n')
        for d in data:
            f.write(format_str.format(*d) + '\n')