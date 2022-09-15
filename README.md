# RAID_v2

## How to Use

1. `config.ini` 에 *하이퍼 파라미터*를 넣어줍니다.
    
    ```markdown
    하이퍼 파라미터 목록
    pcap_dir (string) : pcap파일이나 done파일이 들어있는 directory의 경로
    result_path (string) : 결과 폴더를 생성할 directory 경로
    result_dir (string) : 실행 결과를 저장할 폴더 이름
    threshold (float) - 클러스터링에 사용할 threshold
    card_th (int) - group의 최대 개수
    group (string) - group의 type [ip_dport, ip, all]
    israw (bool) - ASCII encoding 적용 여부
    deduplication (bool) - DHH 수행 시 한 패킷 내의 중복 제거 적용 여부
    count (bool) - 시그니처의 실제 등장 횟수 출력 여부 
    earlystop (bool) - earlystop을 적용할지 여부
    vector_size (int) - RAID에서 사용할 vector의 크기
    window_size (int) - RAID에서 AE청킹할 때 윈도우의 사이즈
    hh1_size (int) - DHH에서 1번째 HeavyHitter의 크기
    hh2_size (int) - DHH에서 2번째 HeavyHitter의 크기
    ratio (float) - DHH에서 사용할 ratio
    ```
    
2. `Experiment.py`를 python으로 실행합니다.

```markdown
결과물 목록
train_data.csv : Pcap파일에서 추출한 데이터를 csv로 저장한 파일
group_signatures.csv : 그룹의 정보, Big One 클러스터 정보가 작성 된 파일
all_cluster_signatures.csv : 그룹의 클러스터들의 모든 클러스터들의 정보가 작성 된 파일
group_summary_graph.png : 그룹의 총 패킷 수와 가장 큰 클러스터에 포함된 패킷 수, 가장 많이 반복된 시그니처의 횟수를 히스토그램으로 표현한 그래프

{key}-{ip}directory (클러스터) : 각 클러스터 별 데이터를 저장한 directory
		- Clustering_result : 클러스터 별 common_string, 청킹된 패킷, payload원본을 저장한 파일의 directory
		- pcaps : 클러스터에 속한 패킷들을 하나의 pcap으로 만든 파일의 directory
		- ToN_result : 클러스터 별 시그니처와 등장 횟수가 적힌 파일의 directory
		- result_data_merge.pkl	: raid를 모두 수행한 후 생성된 dictionary를 저장한 pickle파일 
		- Cluster_summary_graph.png : 클러스터의 총 패킷 개수와 cardinality를 히스토그램으로 나타낸 그래프

		* 클러스터에 속하지 않은 패킷의 경우 파일명 -1에 저장
```

## Experiment.py

Config에 작성 된 *하이퍼 파라미터*를 적용하여 Main.py를 실행해주는 파일

## Main.py

Pcap파일에서 패킷 별 데이터를 추출 (preprocess)

추출된 데이터를 key에 따라 그룹화 (group)

클러스터링 적용 (raid)

시그니처 추출 (doubleheavyHitter)

요약 그래프 생성 순으로 진행하는 모듈

## Preprocess.py

pcap파일에서 각 패킷 별 사용할 정보들(5-tuple, application payload, pcap data index, packet index)을 파싱하고 해당 정보를 사용해 그룹키를 미리 만들어 데이터를 구축한다. 

만들어진 데이터를 *result_path*에 train.csv파일로 저장한다.

- `make_pcap_payload()`: pcap파일을 읽어 각 패킷별 사용할 정보를 파싱하고 그룹키를 생성한 후 반환하는 함수
- `get_parsed_packets()`: `make_pcap_payload`를 호출하여 각 pcap파일을 멀티프로세스로 처리하는 함수

## Group.py

```markdown
key 설명 (*group*)
- ip_dport : sip_dport와 dip_dport가 key
- ip : ip만을 key로 사용
- all : key를 사용하지 않음
```

`preprocess` 에서 구축한 데이터를 key값이 같은 데이터들을 묶어 1 : N관계를 찾아 dictionary로 구축하는 함수.

입력받은 *card_th* 수 만큼 cardinality가 높은 데이터들 순으로 저장한다.

- `get_topn_key()` : key가 존재하는 경우 key값에 맞게 1:N관계를 찾아 그룹을 나누어 저장하는 함수
- `all_keys()` : key를 정하지 않고 모든 패킷을 하나의 그룹으로 만들어주는 함수

## Raid.py

payload 데이터를 입력받아 `prototypeClustering`과 `hierarchicalClustering`을 실행한 후 클러스터 별로 분석할 payload 원본과 청킹된 payload들 및 index데이터들을 저장하는 함수 

만들어진 데이터를 group의 directory에 pickle형태로 저장한다.

*earlystop* : 일정 비율 이상의 클러스터가 존재하는지 확인 후 존재하지 않으면 False를 반환하는 함수

## SummaryGraph.py

`group_signatures.csv`를 읽어 그룹 별 클러스터링 결과를 cardinality가 높은 순으로 그래프를 그려 `group_summary_graph.png`로 저장하고 `group_signatures.csv`를 읽어 클러스터 별 패킷 수와 cardinality를 그래프로 만들어 `cluster_summary_graph.png`로 저장하는 함수

두 그래프 모두 최대 10개의 그래프를 그린다.

## Extract.py

- `get_editcap_path()` : tshark의 경로를 반환해주는 함수
- `CustomPcapWriter()` : packet을 pcab에 작성하는 함수
- `write_to_file_v3()` : packet을 하나씩 `CustomPcapWriter`에 전송하는 함수
- `extract_pcap_c1_v2()` : 클러스터 별로 일치했던 패킷들을 원본 pcap에서 추출하는 함수

## RaidUtils

Raid를 진행할 때 사용하는 Clustering과 청킹 및 계산을 위한 Cosine관련 함수들이 작성된 모듈

- `AE2()` : payload를 내용 기반으로 청킹하는 AE Chunking이 구현된 함수
- `decode()` : hex값으로 나와있는 payload중 0x20(space) ~ 0x7E(’~’)값을 문자로 바꿔주는 함수.
- `content2count()` : payload들을 AE청킹과 암호화 해싱을 이용하여 Vector를 만드는 함수
- `prototypeClustering()` : PrototypeClustering을 진행하는 함수
- `hierarchicalClustering()` : hierarchicalClustering을 실행하는 함수
- `getCosinePairwise()` : Cosine similarity를 모든 페이로드에 대해 미리 계산한 vector를 반환하는 함수
- `getCosineSimilarity()` : Cosine similarity를 계산해주는 함수
- `getAverageVector()` : Vector의 평균값을 계산해주는 함수
- `getProxyDistance()` : 모든 payload의 Cosine Distance를 구한 Vector를 반환 함수

## ToNUtils

1:N으로 그룹화된 payload들의 시그니처를 Double Heavy Hitter가 구현된 모듈

- `doubleHeavyHitter()` : HeavyHitter를 사용하여 그룹화된 페이로드에서 시그니처를 추출하여 등장 빈도수가 높은 순으로 저장하여 시그니처를 반환해주는 함수

HeavyHitter : 입력받은 문자열들의 등장횟수가 높은 Substring을 설정해 준 값(*hh1_size*, *hh2_size*)만큼 counting 해주는 클래스

## Utils.py

- `get_dir()` : directoy의 경로를 찾고 directory가 존재하지 않는다면 생성해주는 함수
- `write_csv()` : header와 data를 csv파일로 저장하는 함수
- `fillter_null_payload()` : payload가 없는 데이터를 제외해주는 함수
- `get_payloads_by_index()` : index 위치에 존재하는 패킷의 payload를 return해주는 함수
- `decode_ascii()` : payload 데이터(hex)를 decode(ascii) 해주는 함수
- `encode_hex()` : payload(ascii)를 encode(hex) 해주는 함수. *isrow*에 따라 0x20(space) ~ 0x7E(’~’)는 문자로 만들어준다.
