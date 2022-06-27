import os
import base64
import random
import string
import sys
if os.path.dirname(os.path.abspath(__file__)) not in sys.path:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.generator import generator
import time
import pandas as pd
import pickle
from tqdm import tqdm
import numpy
from multiprocessing import Process, Pool
from pathlib import Path
import glob

if __name__ == '__main__':
    if len(sys.argv) < 7 and '-h' not in sys.argv:
    	print("try '-h' for more information")
    	sys.exit()
    else:
        if '-h' in sys.argv:
            print('''Usage: <option> <input_file> <cluster_col> <centroid_dis_col> <payload_col> <output_file>''')
        else:
            option, input_file, cluster_col, centroid_dis_col, payload_col, output_file = sys.argv[1:]
            start = time.time() # execution time
            data = pd.read_pickle(sys.argv[2])
            cluster_set = data[cluster_col].unique()
            cluster_max  = data[cluster_col].max(0)
            
            testcase = {}
            threshold_dict = {}
            for c in cluster_set:
                fliter = (data[cluster_col] == c)
                ### centroid threshold ###
                threshold_max = data[fliter][centroid_dis_col].max()
                threshold_min = data[fliter][centroid_dis_col].min()
                threshold = threshold_max - (threshold_max - threshold_min)*0.3 #去掉 3 成邊緣資料
                filter_df = data[fliter][[centroid_dis_col, payload_col]]    # 每個 cluster 的 dist, preprocessed_payload 的 df
                filter_df = filter_df[filter_df.centroid_dis <= threshold].reset_index()     # 只留離中心 80% 的數據，reset_index 方便 for loop 遍歷
                ### centroid threshold ###
                if option == '-p':
                    testcase[int(c)] = list(filter_df[payload_col].apply(lambda x: str(bytes(x, 'utf-8'))[2:-1]).unique())
                elif option == '-s':
                    payload_list = []
                    for i in filter_df[payload_col]:
                        payload_list += i
                    testcase[int(c)] = list(set(payload_list))
            testcase # dict with same cluster's payloads ({0:[payload1,payload2...]...})
            
            if -1 in testcase.keys(): # Cluster by DBSCAN contains -1, rename to cluster_max
                testcase[cluster_max+1] = testcase[-1]
                del testcase[-1]
            
            cluster_max = len(testcase.keys())
            
            # testset = { # test case
            #     1 :['kakbb', 'e3new','aadmm'],
            #     2 :['ASH1P', 'ASH1P', 'ASHR1P', "BSH1P"],
            #     3 :['ASHIPEA', 'ASH1PEB', 'ASHRIMPEC', "BSHIPED", "PEBSHI_SHI"]
            # }
            
            def handle_escape(regex_str):
                # regex_str = regex_str.replace("\\", "\\\\")
                regex_str = regex_str.replace("\r\n\r\n", "\\R\\R") # actual packet payload \r\n is CRLF not '\r\n' string, so replace it as newline sequence in pcre format 
                regex_str = regex_str.replace("\r\n", "\\R")
                regex_str = regex_str.replace("/", "\/")
                regex_str = regex_str.replace(";", "\;")
                regex_str = regex_str.replace("IP", ".*")
                regex_str = regex_str.replace("VERSION", ".*")
                return regex_str
            
            POPULATION = 100
            GENERATION = 10
            
            ssid_cnt = 1000 #initial value of snort rules ssid
            pool = Pool(2) # multi processing
            rule_num = 10 # multi processing
            
            for i in tqdm(range(cluster_max)): # iterate all cluster
                target = testcase[i] # a list of all payload under the cluster
                tmp = numpy.array_split(target, rule_num) # multi processing, split all payload to <rule_num> equal part
                target = []
                for j in range(len(tmp)):
                    if tmp[j].tolist():
                        target.append((tmp[j].tolist(), POPULATION, GENERATION)) # make the generator input
                        
                result = []
                
                TEST = False
                
                if TEST :
                
                    gene = [0x12,0x9]
                    g_res, fitness = parser(target, gene)
                    result.append((fitness, ''.join(g_res)))
                
                else :
                    # result = generator(target, POPULATION, GENERATION)
                    result = pool.starmap(generator, target) # multi processing
                    
            ############################
            #     multi-processing     #
            ############################
                regex_list = [] 
                for e in result:
                    for fit, regex in  sorted( set(e),key=lambda x : -x[0] )[:1]:
                        # print(f'{fit}\t\t{regex}')
                        result_regex = handle_escape(regex)
                        regex_list.append(f'alert tcp any any -> $HOME_NET any (sid:{ssid_cnt}; msg:\"Cluster_id {i}\"; pcre:\"/{result_regex}/s\"; rev:1;)') # snort rule replace regex rule
                    ssid_cnt += 1
                testcase[i] = regex_list
                # with open(f"generate_file_test/http_snort.rules_{i}.txt", "w") as f: # save single cluster's snort rule
                #     for value in regex_list:
                #         f.write(f"{value}\n")
                
            # snort_list = [] # append snort rule to input packet table
            # for i in data["sess_cluster"]:
            #     snort_list.append(testcase[i])
            # data['regex'] = snort_list
            # print(data['regex'])
            
            # .txt
            with open(f"generate_file/{output_file}", "w") as f: # save all cluster snort rule as a file
            #     for value in testcase.values():
            #         f.write(f"{value}\n")
                for testcase_value in testcase.values(): #multi processing
                    for value in testcase_value:
                        f.write(f"{value}\n")
                
            # with open(f"generate_file_test/{output_name}_snort_rule_with_AT.pkl", "wb") as f: # save packet table with snort rule column 
            #     pickle.dump(data, f)
            
            end = time.time() # execution time
            print(f"Total Execution Time: {end - start}")