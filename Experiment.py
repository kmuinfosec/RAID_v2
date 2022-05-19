from Main import main
import os

def experiment():

    pcap_path = r"C:\Users\user\spectator05\RAID_IoT-DDoS\data\3번째 데이터셋_2차익명화처리"
    pcap_dir = os.listdir(pcap_path)
    main([  'secret moon is best',
            [os.path.join(pcap_path, dir) for dir in pcap_dir],
            r"C:\Users\user\spectator05\RAID_IoT-DDoS\result",
            "3rd_dataset",
            0.8
        ])

if __name__ == "__main__":
    experiment()