# RAID_v2

## 목차
[1. 사용방법](#1-사용방법)  
[2. 결과물목록](#2-결과물-목록)  
[3. 모듈 설명](#3-모듈-설명)
- [Experiment.py](#experimentpy)
- [Main.py](#mainpy)
- [Preprocess.py](#preprocesspy)
- [Group.py](#grouppy)
- [Raid.py](#raidpy)
- [SummaryGraph.py](#summarygraphpy)
- [Extract.py](#extractpy)
- [Match.py](#matchpy)
- [RaidUtils](#raidutils)
- [DHHUtils](#dhhutils)
- [Utils.py](#utilspy)

## 약어 설명
- DHH(Double Heavy-Hitter): 주어진 패킷들에서 공통 시그니처를 추출할 때 사용하는 기술, "[Zero-Day Signature Extraction for High Volume Attacks](https://www.openu.ac.il/personal_sites/shir-landau-feibish/papers/2019_AutoSigGen_ToN.pdf)" 논문의 제안 아이디어에 포함되는 기술이다.
- RAID(Reducing Alert Fatigue in Network Intrusion Detection): 페이로드를 컨텐츠 기반 AE청킹으로 청킹한 후, 해당 청크들을 해싱하여 프로토타입 클러스터링과 계층적 클러스터링을 통해 효과적으로 워크로드를 감쇄하는 국민대학교 정보보호연구실 독자 기술이다. 현재 [INFOCOM2023](https://infocom2023.ieee-infocom.org) review 진행 중이다.

## 1. 사용방법

1. `config.ini` 에 파라미터를 작성한다.
    
    파라미터 목록
    - *pcap_dir* : 분석에 사용할 [`'.pcap'`, `'.done'`, `'.cap'`] 파일들이 위치한 폴더 경로
    - *pcap_list* : 분석에 사용할 파일들의 이름 리스트
    - *regex_path* : 시그니처 라벨링에 사용할 정규표현식 파일이 위치한 경로
    - *cpu_count* : 전처리와 pcap추출 멀티프로세싱 과정에서 사용할 cpu_count 개수(False일 경우 현재 cpu 코어의 절반만 사용한다.)
    - *result_path* : 결과 폴더를 생성할 경로
    - *result_dir* : *result_path*에 생성할 결과 저장 폴더 이름
    - *threshold* (`float`) - 프로토타입 클러스터링의 클러스터 강도 threshold
    - *card_th* (`int`) - 각 그룹 키별로 분석 그룹 선정 최대 개수
    - *group* (`string`) - 그룹의 타입 [ip_dport('sip_dport', 'dip_dport'), ip('sip', 'dip'), all]
    - *israw* (`bool`) - ASCII encoding 적용 여부 (True시 미적용)
    - *deduplication* (`bool`) - DHH 수행 시 한 패킷 내의 동일 시그니처 중복 빈도 집계 제거 여부
    - *count* (`bool`) - 시그니처의 실제 빈도를 계산 및 출력할지 여부(False시 빈도는 DHH 추정값)
    - *earlystop* (`bool`) - earlystop을 적용할지 여부
    - *vector_size* (`int`) - RAID의 청크 해싱 vector의 크기
    - *window_size* (`int`) - RAID의 AE청킹 윈도우의 사이즈
    - *hh1_size* (`int`) - DHH의 1번째 HeavyHitter의 크기
    - *hh2_size* (`int`) - DHH의 2번째 HeavyHitter의 크기
    - *ratio* (`float`) - DHH의 n-garm을 concat하여 시그니처로 만드는 강도(낮을 수록 더 긴 시그니처가 생성됨)
    - *extension* (`string`) - 분석을 진행할 파일의 확장자
    
    *Ratio가 낮은경우 발생이 적은 단어도 concat되고 높은경우 발생 빈도가 높아야 concat 됨 

    *상세 설명은 아래 모듈 설명에 기재되어 있음
    
2. `Experiment.py`를 python으로 실행한다.<br>
    실행할 때 실행 인자를 지정해 줄 수 있으며, 실행 인자는 `config.ini`의 파라미터 이름과 동일하다.<br>
    명령어 실행시에 작성한 실행 인자는 `config.ini`의 파라미터값을 덮어쓴다.<br>
    명령어 작성 방식은 다음과 같다. ( []는 선택 옵션 )
    ```bash
    python Experiment.py [-pcap_dir <dir>] [-pcap_list <pcap_name_list>] [-regex_path <regex_path>] 
    [-cpu_count <cpu_count>] [-result_path <path>] [-result_dir <result_dir_name>] [-threshold <threshold>] 
    [-card_th <card_th>] [-group <group_type>] [-israw] [-deduplication] [-count] [-earlystop] 
    [-vector_size <vector_size>] [-window_size <window_size>] [-hh1_size <dhh_size>] [-hh2_size <dhh_size>] 
    [-ratio <ratio>] [-extension <extension>]
    ```

    실행 인자 옵션 목록 (\*표시는 입력값이 없는 argument를 나타냄.)
    
    | Parameter                 | Data Type       | Description   |	
    | :------------------------ |:-------------:| :-------------|
    | -pcap_dir	       |	string           | 분석에 사용할 pcap의 파일 경로
    | -pcap_list	       |	string           | 분석에 사용할 pcap의 이름 리스트
    | -regex_path	       |	string           | 시그니처 라벨링에 사용할 정규표현식 파일이 위치한 경로
    | -cpu_count          |   int           | 멀티프로세싱 과정에서 사용할 cpu_count 개수
    | -result_path	       |	string	            | 결과 폴더를 생성할 경로
    | -result_dir 		       | string	           | 결과를 저장할 폴더의 이름
    | -threshold	           |  float            | 프로토타입 클러스터링의 threshold
    | -card_th	        |  int          |  각 그룹 키별로 분석 그룹 선정 최대 개수
    | -group         |  sting          | 그룹의 타입 [ ip_dport \| ip \| all ]
    | -israw \*         |  bool          | ASCII encoding 적용 여부
    | -deduplication \*      |   bool      | DHH 수행 시 한 패킷 내의 동일 시그니처 중복 빈도 집계 제거 여부
    | -count \*  | bool         | 시그니처의 실제 빈도를 계산 및 출력할지 여부
    | -earlystop \*			             | bool 	           | earlystop을 적용할지 여부
    | -vector_size			     | int         | RAID의 청크 해싱 vector의 크기
    | -window_size			             | int     	     | RAID의 AE청킹 윈도우의 사이즈
    | -hh1_size	    | int     	     | DHH의 1번째 HeavyHitter의 크기
    | -hh2_size		      | int     	   | DHH의 2번째 HeavyHitter의 크기
    | -ratio            | float       | DHH의 n-garm을 concat하여 시그니처로 만드는 강도
    | -extension            | string       | 분석을 진행할 파일의 확장자
    | -summary_graph    | float       | 그래프 출력 여부
    | - sig_th      | float     | 사용자 지정 공통 시그니처 비율(cs_th_hex_list에 반영)



## 2. 결과물 목록
- `train_data.csv` : Pcap파일에서 추출한 데이터를 csv로 저장한 파일 (optional) 
- `group_signatures.csv` : 그룹별 정보, 그룹별 가장 큰 클러스터 정보, 클러스터의 summary 정보가 작성 된 파일
- - `biggest` : 그룹 내에서 기준과 통신한 중복 제거된 ip 수가 가장 높은 클러스터(동순위일 경우 패킷 개수 순)

| Column | Explaination |
| :-- | :--: |
| group_info | <그룹 키 종류>-<그룹 키 값> |
| group_uniq_ip_cnts | 그룹과 통신한 중복 제거된 ip 수<br/>`group type`이 all인 경우 0 |
| group_all_pkts | 그룹에 속한 패킷의 수 |
| group_uniq_pkts | 그룹에 속한 중복 제거된 패킷의 수 |
| biggest_cluster_index | 가장 cluster_uniq_ip_cnts가 높은 클러스터의 고유 인덱스 번호 |
| group_cluster_cnts | 그룹 내 클러스터 수 (remain 미포함) |
| biggest_cluster_uniq_ip_cnts | 가장 큰 클러스터에서 기준과 통신한 중복 제거된 ip 수<br/>`group type`이 all인 경우 0 |
| biggest_all_pkts | 가장 큰 클러스터에 속한 패킷의 수 |
| biggest_cluster_uniq_pkts | 가장 큰 클러스터에 속한 중복 제거된 패킷의 수 |
| occurrence_most_freq_sig_pkts | 가장 많이 나온 시그니처의 빈도 |
| cs_hex_list | 가장 큰 클러스터에 속한 모든 패킷에 공통으로 등장한 시그니처 |
| cluster_all_cnts | 클러스터의 수 (remain 포함) |
| match_ratio_sig_main | 클러스터 별 시그니처 일치율 리스트(일치율 : 모든 common_signatures 길이의 합 / 패킷 길이 평균)<br/>(패킷 개수 top5 클러스터) |
| match_ratio_sig_main_info | (모든 common_signatures 길이의 합 , 패킷 길이 평균) 리스트 |
| match_ratio_pkt_main | 클러스터 별 가장 많은 동일한 패킷 수의 일치율 리스트<br/>(패킷 개수 top5 클러스터) |
| match_ratio_pkt_main_info | (가장 큰 클러스터 내 가장 많은 동일한 패킷 수 , 가장 큰 클러스터 내 전체 패킷 수) 리스트 |
| match_ratio_sig_remain | 클러스터가 생성되지 않은 경우, 그룹 별 시그니처 일치율 리스트 |
| match_ratio_sig_remain_info | match_ratio_sig의 (분자, 분모) : (all_cs_len_sum, all_pkt_len_mean) 리스트 |
| match_ratio_pkt_remain | 클러스터가 생성되지 않은 경우, 그룹 별 패킷 비율 리스트 |
| match_ratio_pkt_remain_info | match_ratio_pkt의 (분자, 분모) : ( most_freq_pkt_uniq_cnts, cluster_all_pkts) 리스트 |
| cs_str_list | cs_hex_list 를 utf8 베이스 hex2print 포맷으로 한 부분 |
| cs_list_cnts | cs_hex_list 에 대한 엘리먼트의 수 |
| remain_cluster_cnts | remain 클러스터 카운트 ( 0 or 1) 1이면 있음 |
| uniq_src_ip_list_topN | 그룹 내 전체 패킷의 중복 제거된 SRC IP Top N |
| uniq_src_ip_list_cnts | 그룹 내 전체 패킷의 중복 제거된 SRC IP 수 |
| uniq_src_port_list_topN | 그룹 내 전체 패킷의 중복 제거된 SRC Port Top N |
| uniq_src_port_list_cnts | 그룹 내 전체 패킷의 중복 제거된 SRC Port 수 |
| uniq_dst_ip_list_topN | 그룹 내 전체 패킷의 중복 제거된 DST IP Top N |
| uniq_dst_ip_list_cnts | 그룹 내 전체 패킷의 중복 제거된 DST IP 수 |
| uniq_dst_port_list_topN | 그룹 내 전체 패킷의 중복 제거된 DST Port Top N |
| uniq_dst_port_list_cnts | 그룹 내 전체 패킷의 중복 제거된 DST Port 수 |
| cs_th_str_list | 
    "cs_th_list_cnts", # 33
    
- `all_cluster_signatures.csv` : 모든 그룹의 모든 클러스터들의 정보, 정규표현식과 일치하는 시그니처의 정보가 작성 된 파일

| Column | Explaination |
| :-- | :--: |
| group_info | <그룹 키 종류>-<그룹 키 값> |
| group_uniq_ip_cnts | 그룹과 통신한 중복 제거된 ip 수<br/>`group type`이 all인 경우 0 |
| group_all_pkts | 그룹에 속한 패킷의 수 |
| group_uniq_pkts | 그룹에 속한 서로 다른 패킷의 수 |
| cluster_uniq_ip_cnts | 클러스터에서 기준과 통신한 중복 제거된 ip 수<br/>`group type`이 all인 경우 0 |
| cluster_index | 클러스터의 고유 인덱스 번호<br/>(-1은 클러스터가 되지 않음을 의미) |
| cluster_all_pkts | 클러스터에 속한 패킷의 수 |
| cluster_uniq_pkts | 그룹에 속한 서로 다른 패킷의 수 |
| occurrence_most_freq_sig_pkts | 가장 많이나온 시그니처의 빈도 |
| cs_hex_list | 클러스터에 속한 모든 패킷에 공통으로 나타나는 시그니처 |
| match_ratio_sig | 클러스터의 시그니처 일치율 |
| match_ratio_pkt | 클러스터에 속한 가장 많은 동일한 패킷 수의 비율 |
| cs_str_list | cs_hex_list 를 utf8 베이스 hex2print 포맷으로 한 부분 |
| cs_list_cnts | cs_hex_list 에 대한 엘리먼트 수 |
| match_ratio_sig_info | match_ratio_sig의 (분자, 분모) : (all_cs_len_sum, all_pkt_len_mean) |
| match_ratio_pkt_info | match_ratio_pkt의 (분자, 분모) : ( most_freq_pkt_uniq_cnts, cluster_all_pkts) |
| all_cs_len_sum | 모든 common_signatures 길이의 합 |
| all_pkt_len_mean | 모든 패킷 길이 평균 |
| most_freq_pkt_uniq_cnts | 클러스터 내 가장 많은 동일한 패킷의 수 |
| uniq_src_ip_list_topN | 클러스터 내 전체 패킷의 중복 제거된 SRC IP Top N |
| uniq_src_ip_list_cnts | 클러스터 내 전체 패킷의 중복 제거된 SRC IP 수 |
| uniq_src_port_list_topN | 클러스터 내 전체 패킷의 중복 제거된 SRC Port Top N |
| uniq_src_port_list_cnts | 클러스터 내 전체 패킷의 중복 제거된 SRC Port 수 |
| uniq_dst_ip_list_topN | 클러스터 내 전체 패킷의 중복 제거된 DST IP Top N |
| uniq_dst_ip_list_cnts | 클러스터 내 전체 패킷의 중복 제거된 DST IP 수 |
| uniq_dst_port_list_topN | 클러스터 내 전체 패킷의 중복 제거된 DST Port Top N |
| uniq_dst_port_list_cnts | 클러스터 내 전체 패킷의 중복 제거된 DST Port 수 |
| labels_names_list | 일치한 정규표현식이 들어있는 분류 (대분류.중분류.소분류) 리스트 |
| labels_hex_list | 정규표현식과 일치한 시그니처 리스트 |
| labels_feq_list | 정규표현식과 일치한 시그니처의 빈도 리스트 |
| labels_list_cnts | 정규표현식과 일치한 시그니처의 수 |
| cs_th_hex_list | 클러스터에서 `sig_th`이상의 패킷 비율에서 공통으로 나타나는 시그니처 |
| cs_th_str_list | cs_th_hex_list 를 utf8 베이스 hex2print 포맷으로 한 부분 |
| cs_th_list_cnts | cs_th_hex_list 에 대한 엘리먼트 수 |

```
match_ratio_sig = all_cs_len_sum / all_pkt_len_mean
match_ratio_pkt = most_freq_pkt_uniq_cnts / cluster_all_pkts
```
    
    
- `group_summary_graph.png` : 그룹의 총 패킷 수와 가장 큰 클러스터에 포함된 패킷 수, 최빈 시그니처의 횟수를 그룹별로 표현한 막대 그래프
- `<group type>_<group key>/` *card_th*만큼 생성된 그룹 별 클러스터 데이터를 저장한 폴더
  * `Clustering_result/`: 클러스터 별 common_string, 청킹된 패킷, payload원본을 저장한 파일들의 폴더
  * `pcaps/`: 클러스터에 속한 패킷들을 하나의 pcap으로 만든 파일들의 폴더
  * `DHH_result/`: 클러스터 별 시그니처와 등장 횟수가 적힌 파일들의 폴더
  * `Labels/`: 정규표현식을 통해 매칭된 시그니처를 각 라벨별로 저장한 파일들의 폴더
  * `result_data_merge.pkl`	: raid 실행 결과 dictionary를 저장한 pickle파일 
  * `Cluster_summary_graph.png` : 클러스터의 총 패킷 개수와 cardinality를 그룹별로 표현한 막대 그래프

*`Clustering_result/`, `pcaps/`, `DHH_result/` 에는 클러스터 index를 파일명으로 가지는 결과 파일들이 존재한다.

## 3. 모듈 설명 

### Experiment.py

`config.ini`에 작성된 *파라미터*를 적용하여 `Main.py`를 실행해주는 파일

### Main.py

1. 패킷 전처리 : Pcap파일에서 패킷별 데이터를 추출 (Preprocess)
2. 패킷 그룹핑 : 추출된 데이터를 key에 따라 그룹화 (Group)
3. 클러스터링 : 페이로드를 그룹별로 클러스터링 (Raid)
4. 시그니처 추출: 페이로드에서 클러스터별로 많이 등장한 시그니처를 추출 (Heavy_hitter)
5. 결과 출력 : 통계 엑셀 파일 생성, 요약 그래프 생성(SummaryGraph), 클러스터별 pcap 추출(Extract), 시그니처 라벨링(Match)

*통계 엑셀 파일 : `group_signatures.csv`, `all_cluster_signatures.csv`

### Preprocess.py

pcap파일에서 각 패킷 별 사용할 정보들(5-tuple, application payload, pcap data index, packet index)을 파싱하고 해당 정보를 사용해 그룹키를 미리 만들어 데이터를 구축하는 모듈

- 만들어진 데이터를 *result_path*에 `train_data.csv`파일로 저장한다. (optional)
- `make_pcap_payload()`: pcap파일을 읽어 각 패킷별 사용할 정보를 파싱하고 그룹키를 생성한 후 반환하는 함수
- `get_parsed_packets()`: `make_pcap_payload`를 호출하여 각 pcap파일을 멀티프로세스로 처리하는 함수

### Group.py
`preprocess` 에서 구축한 데이터를 key값이 같은 데이터들을 묶어 1 : N관계를 찾아 dictionary로 구축하는 모듈

```markdown
key 설명 (*group* 파라미터 값으로 가능한 key type)
- ip_dport : sip_dport와 dip_dport를 key로 사용한다.
- ip : sip와 dip를 key로 사용한다.
- all : key를 사용하지 않고 모든 페이로드에 대해 클러스터링한다.
```

- 입력받은 *card_th* 수 만큼 cardinality가 높은 데이터들 순으로 저장한다.
- `get_topn_key()` : key가 존재하는 경우 key값에 맞게 1:N관계를 찾아 그룹을 나누어 저장하는 함수
- `all_keys()` : key를 정하지 않고 모든 패킷을 하나의 그룹으로 만들어주는 함수

### Raid.py

payload 데이터를 입력받아 AE청킹과 피처 해싱(`contents2count()`)을 거쳐 프로토타입 클러스터링(`prototypeClustering()`)과 계층적 클러스터링(`hierarchicalClustering()`)을 실행한 후 클러스터 별로 분석할 payload 원본과 청킹된 payload들 및 index데이터들을 저장하는 모듈 

- 만들어진 데이터를 group의 directory에 pickle형태로 저장한다.
- *earlystop* : 일정 비율 이상의 클러스터가 존재하는지 확인 후 존재하지 않으면 False를 반환하는 파라미터

### SummaryGraph.py
각 그룹별 통계를 나타내는 그래프(1개)와 각 그룹의 클러스터별 통계를 나타내는 그래프(그룹 개수 만큼)를 그리는 모듈  

- `group_signatures.csv`를 읽어 그룹 별 클러스터링 결과를 cardinality가 높은 순으로 그래프를 그려 `group_summary_graph.png`로 저장한다. (`group_signatures.csv`는 그룹 그래프 막대를 *card_th*의 두 배 만큼 그린다. == 선정된 모든 그룹)
-  `all_cluster_signatures.csv`를 읽어 클러스터 별 패킷 수와 cardinality를 그래프로 만들어 `cluster_summary_graph.png`로 저장한다. (`cluster_summary_graph.png` 는 클러스터 그래프막대를 cardinality 상위 10개의 클러스터를 그린다.)

### Extract.py
입력으로 받은 pcap과 그룹핑 및 클러스터링 된 패킷을 비교하여 각 클러스터별로 pcap을 분리하여 추출하는 모듈

- `CustomPcapWriter()` : packet을 pcap에 작성하는 함수
- `write_to_file()` : packet을 하나씩 `CustomPcapWriter`에 전송하는 함수
- `extract()` : 클러스터 별로 일치했던 패킷들을 원본 pcap에서 추출하는 함수

### Match.py
라벨 및 정규표현식 목록을 입력하여, 각 그룹별 시그니처와 매칭 되는 식이 있는지 탐색하는 모듈 

- 라벨 및 정규표현식 목록 `config.yaml` 을 읽어 시그니처와 매칭 할 식을 불러온다. 
- `group_signatures.csv`를 읽어 시그니처를 추출한 그룹을 탐색하고, 각 그룹마다 `Labels` 폴더 내에 있는 클러스터 별 시그니처 추출 결과를 불러온다. 
- 각 그룹 별 시그니처와 매칭 되는 식이 있는지 탐색하여 라벨마다 클러스터 번호, 매칭 된 시그니처, 빈도수 정보를 `Labels` 폴더에 저장한다. 매칭 된 시그니처가 존재하지 않으면 결과 폴더 및 파일을 생성하지 않는다.
- 각 그룹의 클러스터 별 정규표현식과 일치한 시그니처들의 분류, 발생 빈도, 시그니처, 일치 수를 `all_cluster_signatures.csv`에 추가한다.

### RaidUtils
Raid 관련 모듈

- `AE2()` : payload를 AE청킹하는 함수
- `decode()` : hex로 표현된 payload 중 사람이 식별할 수 있는 범위인 0x20(space) ~ 0x7E(’~’)범위를 ASCII로 바꿔주는 함수
- `content2count()` : payload들을 AE청킹과 암호화 해싱을 이용하여 vector를 만드는 함수
- `prototypeClustering()` : PrototypeClustering을 실행하는 함수
- `hierarchicalClustering()` : hierarchicalClustering을 실행하는 함수
- `getCosinePairwise()` : Cosine similarity를 모든 페이로드에 대해 미리 계산한 matrix를 반환하는 함수
- `getCosineSimilarity()` : 두 vector의 Cosine-Similarity를 계산해주는 함수
- `getAverageVector()` : vector의 평균값을 계산해주는 함수
- `getProxyDistance()` : 모든 payload의 Cosine-Distance를 계산해주는 함수

### DHHUtils
DHH(Double Heavy-Hitter) 관련 모듈

- `doubleHeavyHitter()` : HeavyHitter를 사용하여 그룹화된 페이로드에서 시그니처를 추출하여 등장 빈도수가 높은 순으로 저장하여 시그니처를 반환해주는 함수
- `HeavyHitter` : 입력받은 문자열들의 등장횟수가 높은 Substring을 설정해 준 값(*hh1_size*, *hh2_size*)만큼 counting 해주는 클래스

### Utils.py

- `get_dir()` : 폴더의 경로를 찾고 폴더가 존재하지 않는다면 생성해주는 함수(폴더명 미지정시 현재 timestamp를 폴더명으로 생성)
- `write_csv()` : 입력받은 header와 data를 csv파일로 저장하는 함수
- `filter_null_payload()` : payload가 없는 데이터를 제거하는 함수
- `get_payloads_by_index()` : index위치에 존재하는 패킷의 payload를 return해주는 함수
- `decode_ascii()` : payload데이터(hex)를 decode(ascii) 해주는 함수
- `encode_hex()` : payload(ascii)를 encode(hex) 해주는 함수. *isrow*에 따라 0x20(space) ~ 0x7E(’~’)는 문자로 만들어준다.
