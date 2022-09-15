from configparser import ConfigParser

from Main import main
import os


def experiment():
    cfgs = ConfigParser()
    cfgs.read("config.ini", encoding="UTF-8")

    main(args=cfgs["DEFAULT"])

if __name__ == "__main__":
    experiment()
