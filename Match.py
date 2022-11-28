import os
import re
import csv
import yaml
import pandas as pd
import pickle

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

    total = dict()

    main_df = pd.read_csv(os.path.join(result_path, 'group_signatures.csv'))

    for group in main_df.group.tolist():
        total[group] = dict()
        group_path = os.path.join(result_path, group)

        signature_dict = dict()
        for filename in os.listdir(os.path.join(group_path, 'DHH_result')):
            cluster_num = filename.split('_')[0]
            total[group][cluster_num] = [[], [], []]

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
                            total[group][cluster_num][0].append('.'.join([category1, category2, category3]))
                            total[group][cluster_num][1].append(signature)
                            total[group][cluster_num][2].append(frequency)
                            result.append((cluster_num, signature, frequency))
            
            if len(result)==0:
                continue

            cur_path = group_path
            for append_name in ['Labels', category1, category2]:
                cur_path = os.path.join(cur_path, append_name)
                if not os.path.exists(cur_path):
                    os.mkdir(cur_path)

            writer = open(os.path.join(cur_path, f'{category3}.csv'), 'w')
            writer.write('cluster_num,signature,frequency\n')
            for cluster_num, signature, frequency in result:
                writer.write(f'{cluster_num},{signature},{frequency}\n')
            writer.close()

    all_cluster = pd.read_csv(f'{result_path}/all_cluster_signatures.csv')
    
    all_cluster = all_cluster.to_dict('list')

    all_cluster['labels_names'] = []
    all_cluster['labels_hex'] = []
    all_cluster['labels_feq'] = []
    all_cluster['Num_labels'] = []

    for idx in range(len(all_cluster['group'])):
        g = all_cluster['group'][idx]
        c = str(all_cluster['cluster'][idx])
        
        if c == '-1' or g==-1:
            
            all_cluster['labels_names'].append(None)
            all_cluster['labels_hex'].append(None)
            all_cluster['labels_feq'].append(None)
            all_cluster['Num_labels'].append(None)
            continue
        
        all_cluster['labels_names'].append(str(total[g][c][0]))
        all_cluster['labels_hex'].append(str(total[g][c][1]))
        all_cluster['labels_feq'].append(str(total[g][c][2]))
        all_cluster['Num_labels'].append(len(total[g][c][0]))

    all_cluster = pd.DataFrame(all_cluster)

    all_cluster.to_csv(f'{result_path}/all_cluster_signatures.csv', index=False)