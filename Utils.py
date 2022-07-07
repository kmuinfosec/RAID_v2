
import os
import csv
from datetime import datetime

def get_dir(path, dir=False):
    if not dir:
        dir = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    path_ = os.path.join(path, dir)
    if not os.path.exists(path_):
        os.mkdir(path_)

    return path_

def write_csv(path, header, data):
    file = open(path, 'w', newline="")
    writer = csv.writer(file)
    writer.writerow(header)
    writer.writerows(data)