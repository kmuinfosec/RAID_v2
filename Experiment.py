from configparser import ConfigParser
import argparse

from Main import main
from Utils import parse_config

ARG_STORE = ["pcap_dir", "pcap_list", "regex_path", "cpu_count", "result_path", 'result_dir',\
        "threshold", "card_th", "group", "vector_size", "window_size", "hh1_size",\
        "hh2_size", "ratio", "extension", "summary_graph"]

ARG_STORE_TRUE = ["israw", "deduplication", "count", "earlystop"]


def experiment(args_user):
    cfgs = ConfigParser()
    cfgs.read("config.ini", encoding="UTF-8")
    parsed_args = parse_config(cfgs, args_user)
    
    main(args=parsed_args)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()

    for arg in ARG_STORE:
        argparser.add_argument(f"-{arg}", dest= arg, action= "store")

    for arg in ARG_STORE_TRUE:
        argparser.add_argument(f"-{arg}", dest= arg, action= "store_true")

    args_user = vars(argparser.parse_args())
    experiment(args_user)