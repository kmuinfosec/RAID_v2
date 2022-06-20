import os

from Main import main
from Utils import *


def experiment():

    # pcap_path = r"C:\Users\user\spectator05\RAID_IoT-DDoS\data\3번째 데이터셋_2차익명화처리"
    # pcap_dir = os.listdir(pcap_path)
    # main([  'secret moon is best',
    #         [os.path.join(pcap_path, dir) for dir in pcap_dir],
    #         r"C:\Users\user\spectator05\RAID_IoT-DDoS\result",
    #         "3rd_dataset_0.8",
    #         0.8
    #     ])
    #example
    pcap_path = rf"C:\Users\seclab\Downloads\6th_dataset\Possible_CVE_20220613\Elastic_Kibana_Timelion_Prototype_Pollution_Remote_Code_Execution_CVE-2019-7609"
    pcap_dir = os.listdir(pcap_path)
    main([  'secret moon is best',
            [os.path.join(pcap_path, dir) for dir in pcap_dir],
            os.getcwd(),
            get_dir(os.getcwd()),
            0.6,
            False,
            False
        ])


if __name__ == "__main__":
    experiment()