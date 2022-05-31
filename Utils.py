
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