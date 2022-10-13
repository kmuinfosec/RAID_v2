from configparser import ConfigParser
import argparse

from Main import main

from Utils import parse_config


def experiment(args_user):
    cfgs = ConfigParser()
    cfgs.read("config.ini", encoding="UTF-8")
    parsed_args = parse_config(cfgs, args_user)

    if (parsed_args["result_path"]!=0): 
        main(args=parsed_args)

if __name__ == "__main__":
    argument_store = ["pcap_dir", "cpu_count", "result_path", 'result_dir',\
            "threshold", "card_th", "group", "vector_size", "window_size", "hh1_size",\
            "hh2_size", "ratio", "extension"]

    argument_store_true = ["israw", "deduplication", "count", "earlystop"]
    argparser = argparse.ArgumentParser()

    for i in argument_store:
        argparser.add_argument(f"-{i}", dest= i, action= "store")

    for i in argument_store_true:
        argparser.add_argument(f"-{i}", dest= i, action= "store_true")

    args_user = vars(argparser.parse_args())
    experiment(args_user)