import os
import re
import csv
import yaml
import pandas as pd

def match(result_path, regex_path):

    with open(regex_path, 'r') as f:
        regex_dict = yaml.load(f, Loader=yaml.FullLoader)

    tmp_regex_dict = dict()
    for category1 in regex_dict.keys():
        for category2 in regex_dict[category1].keys():
            for category3 in regex_dict[category1][category2].keys():
                for regex in regex_dict[category1][category2][category3]:
                    if (category1, category2, category3) not in tmp_regex_dict.keys():
                        tmp_regex_dict[(category1, category2, category3)] = []
                    tmp_regex_dict[(category1, category2, category3)].append(regex)
    regex_dict = tmp_regex_dict

    main_df = pd.read_csv(os.path.join(result_path, 'group_signatures.csv'))

    for group in main_df.group.tolist():
        group_path = os.path.join(result_path, group)

        signature_dict = dict()
        for filename in os.listdir(os.path.join(group_path, 'DHH_result')):
            cluster_num = filename.split('_')[0]

            sign_list = []
            with open(os.path.join(group_path, 'DHH_result', filename), 'r') as f:
                reader = csv.reader(f)
                header = next(reader)
                for row in reader:
                    sign_list.append((str(row[0]), int(row[1])))

            for signature, frequency in sign_list:
                if cluster_num not in signature_dict.keys():
                    signature_dict[cluster_num] = []
                signature_dict[cluster_num].append((signature, frequency))

        for (category1, category2, category3), match_list in regex_dict.items():
            
            result = []
            for regex in match_list:
                pattern = re.compile(regex)

                for cluster_num in signature_dict.keys():
                    for signature, frequency in signature_dict[cluster_num]:
                        if pattern.search(signature) != None:
                            result.append((cluster_num, signature, frequency))
            
            if len(result)==0:
                continue

            cur_path = group_path
            for append_name in ['Match_result', category1, category2]:
                cur_path = os.path.join(cur_path, append_name)
                if not os.path.exists(cur_path):
                    os.mkdir(cur_path)

            writer = open(os.path.join(cur_path, f'{category3}.tsv'), 'w')
            writer.write('cluster_num\tsignature\tfrequency\n')
            for cluster_num, signature, frequency in result:
                writer.write(f'{cluster_num}\t{signature}\t{frequency}\n')
            writer.close()