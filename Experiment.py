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
    pcap_dir = r"C:\Users\user\Downloads\complete\CTU-IoT-Malware-Capture-1-1"
    # for i in iot23_dir:
    #     pcap_dir = os.path.join(r"C:\Users\user\Downloads\opt\Malware-Project\BigDataset\IoTScenarios", i)
        # pcap_dir = os.listdir(pcap_path)
    print(pcap_dir)
    main([  'secret moon is best',
            [pcap_dir],
            r"C:\Users\user\spectator05\RAID_IoT-DDoS\result",
            '34-1',
            0.8,
            False,
            False
        ])


if __name__ == "__main__":
    experiment()