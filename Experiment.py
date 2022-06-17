from Main import main
import os

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

    for p in os.listdir(rf"C:\Workspace\kukmin_lab\KT\RAID_v2-main\RAID_v2\Dataset\no.6\Impossible_CVE_20220613/"):
        pcap_path = rf"C:\Workspace\kukmin_lab\KT\RAID_v2-main\RAID_v2\Dataset\no.6\Impossible_CVE_20220613/{p}"
        pcap_dir = os.listdir(pcap_path)
        main([  'secret moon is best',
                [os.path.join(pcap_path, dir) for dir in pcap_dir],
                r"C:\Workspace\kukmin_lab\KT\RAID_v2-main\RAID_v2\res",
                p,
                0.6,
                False,
                True
            ])


if __name__ == "__main__":
    experiment()