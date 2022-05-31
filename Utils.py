
import os
import csv
from datetime import datetime
from typing_extensions import dataclass_transform

def get_dir(result_path, result_dir=False):
    if not result_dir:
        result_dir = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    if not os.path.exists(os.path.join(result_path, result_dir)):
        os.mkdir(os.path.join(result_path, result_dir))

    return os.path.join(result_path, result_dir)

def write_csv(result_path, header, data):
    file = open(result_path, 'w', newline="")
    writer = csv.writer(file)
    writer.writerow(header)
    writer.writerows(data)

def raid_to_csv(result_dict, cluster_dir, key_name, writer):
    for ci in list(result_dict.keys()):
        c_dict = result_dict[ci]
        csv_data = [[   str(list(c_dict['common string'])),
                        str(c_dict['decoded AE'][i]),
                        str(c_dict['decoded payload'][i])
                    ] for i in range(len(c_dict['decoded AE']))]
        write_csv(  os.path.join(cluster_dir, f"{ci}_result.csv"),
                    ['common_string', 'decoded_AE', 'decoded_payload'],
                    csv_data)
        writer.writerow([key_name[k] + str(i[0]), str(len(i[1][0])), str(len(i[1][1])), str(ci), str(len(c_dict['decoded AE']))])