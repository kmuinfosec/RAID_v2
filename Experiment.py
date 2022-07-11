from configparser import ConfigParser

from Main import main
import os
import platform


def experiment():
    cfgs = ConfigParser()
    cfgs.read("config.ini", encoding="UTF-8")

    osp = "python"
    if platform.system() == "Windows":
        osp = "python"
    else:
        osp = "python3"

    os.system(
        osp
        + " Main.py "
        + cfgs["DEFAULT"]["pcap_dir"]
        + " "
        + cfgs["DEFAULT"]["result_dir"]
        + " "
        + cfgs["DEFAULT"]["result_name"]
        + " -t "
        + cfgs["DEFAULT"]["threshold"]
        + " -a "
        + cfgs["DEFAULT"]["isall"]
    )


if __name__ == "__main__":
    experiment()
