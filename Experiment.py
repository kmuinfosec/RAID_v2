from configparser import ConfigParser

from Main import main
import os
from Utils import get_dir

def parse_config(cfgs):
    args_dict = dict()
    args_dict['pcap_dir'] = cfgs["DEFAULT"]['pcap_dir']
    args_dict['result_path'] = get_dir(cfgs["DEFAULT"]['result_path'], cfgs["DEFAULT"]['result_dir'])
    args_dict['threshold'] = float(cfgs["DEFAULT"]['threshold'])
    args_dict['card_th'] = int(cfgs["DEFAULT"]['card_th'])
    args_dict['group_type'] = cfgs["DEFAULT"]['group']
    args_dict['israw'] = eval(cfgs["DEFAULT"]['israw'])
    args_dict['deduplication'] = eval(cfgs["DEFAULT"]['deduplication'])
    args_dict['iscount'] = eval(cfgs["DEFAULT"]['count'])
    args_dict['earlystop'] = eval(cfgs["DEFAULT"]['earlystop'])
    args_dict['vector_size'] = int(cfgs["DEFAULT"]['vector_size'])
    args_dict['window_size'] = int(cfgs["DEFAULT"]['window_size'])
    args_dict['hh1_size'] = int(cfgs["DEFAULT"]['hh1_size'])
    args_dict['hh2_size'] = int(cfgs["DEFAULT"]['hh2_size'])
    args_dict['ratio'] = float(cfgs["DEFAULT"]['ratio'])
    
    return args_dict

def experiment():
    cfgs = ConfigParser()
    cfgs.read("config_temp.ini", encoding="UTF-8")
    parsed_args = parse_config(cfgs)

    main(args=parsed_args)

if __name__ == "__main__":
    experiment()
