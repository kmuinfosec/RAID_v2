from configparser import ConfigParser

from Main import main
import os
import platform


def experiment():
    cfgs = ConfigParser()
    cfgs.read("config.ini")
    # pcap_path = r"C:\Users\user\spectator05\RAID_IoT-DDoS\data\3번째 데이터셋_2차익명화처리"
    # pcap_dir = os.listdir(pcap_path)
    # main([  'secret moon is best',
    #         [os.path.join(pcap_path, dir) for dir in pcap_dir],
    #         r"C:\Users\user\spectator05\RAID_IoT-DDoS\result",
    #         "3rd_dataset_0.8",
    #         0.8
    #     ])
    # example
    # pcap_dir = r"C:\Users\user\Downloads\complete\CTU-IoT-Malware-Capture-1-1"
    # for i in iot23_dir:
    #     pcap_dir = os.path.join(r"C:\Users\user\Downloads\opt\Malware-Project\BigDataset\IoTScenarios", i)
    #     pcap_dir = os.listdir(pcap_path)
    # print(pcap_dir)
    """
    main([  'secret moon is best',
            cfgs["DEFAULT"]["pcap_dir"],
            cfgs["DEFAULT"]["result_dir"],
            cfgs["DEFAULT"]["result_name"],
            cfgs["DEFAULT"]["threshold"],
            bool(cfgs["DEFAULT"]["detect_type_flag"]),
            bool(cfgs["DEFAULT"]["isall"])
        ])
    """
    osp = "python"
    if platform.system() == "Windows":
        osp = "python"
    else:
        osp = "python3"

    os.system(
        osp
        + " Main.py "
        + cfgs["DEFAULT"]["pcap_dir"]
        + " "
        + cfgs["DEFAULT"]["result_dir"]
        + " "
        + cfgs["DEFAULT"]["result_name"]
        + " -t "
        + cfgs["DEFAULT"]["threshold"]
        + " -g "
        + cfgs["DEFAULT"]["isgroup"]
        + " -a "
        + cfgs["DEFAULT"]["isall"]
    )


if __name__ == "__main__":
    experiment()
