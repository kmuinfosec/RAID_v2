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
    pcap_path = rf"C:\Users\seclab\Downloads\6th_dataset\Impossible_CVE_20220613\DNSmasq_sort_rrset_Heap_OOB_Write_CVE-2020-25683"
    pcap_dir = os.listdir(pcap_path)
    main([  'secret moon is best',
            [os.path.join(pcap_path, dir) for dir in pcap_dir],
            os.getcwd(),
            get_dir(os.getcwd()),
            0.6,
            False,
            True
        ])


if __name__ == "__main__":
    experiment()