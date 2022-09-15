from configparser import ConfigParser

from Main import main
import os
from Utils import get_dir, parse_config


def experiment():
    cfgs = ConfigParser()
    cfgs.read("config.ini", encoding="UTF-8")
    parsed_args = parse_config(cfgs)

    main(args=parsed_args)

if __name__ == "__main__":
    experiment()
