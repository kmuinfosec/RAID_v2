
import os

from datetime import datetime

def get_dir(result_path, result_dir=False):
    if not result_dir:
        result_dir = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    if not os.path.exists(os.path.join(result_path, result_dir)):
        os.mkdir(os.path.join(result_path, result_dir))

    return os.path.join(result_path, result_dir)