# RAID_v2

## How to use

```
usage: Main.py [-h] [-t THRESHOLD] [-c CARD_TH] [-a IS_ALL] pcap_path result_path result_dir

positional arguments:
  pcap_path             Input the path of the pcap files
  result_path           Input the path of the result directory
  result_dir            Input the name of the result directory

optional arguments:
  -h, --help            show this help message and exit
  -t THRESHOLD, --threshold THRESHOLD
                        Input the threshold of the clustering | Default : 0.6
  -c CARD_TH, --card_th CARD_TH
                        Select top \{card_th\} group per each key | Default : 5
  -a IS_ALL, --is_all IS_ALL
                        True if don't want to make group | Default : False
```

추가 예정
