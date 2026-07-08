root='./data/final datasets/'
dataset_files=['hbos_gnb_rec_dataset.csv',
               'hbos_xgb_rec_dataset.csv',
               'iforest_gnb_rec_dataset.csv',
               'iforest_xgb_rec_dataset.csv',
               'logistic_regression_gnb_rec_dataset.csv',
               'logistic_regression_xgb_rec_dataset.csv',
               'naive_bayes_gnb_rec_dataset.csv',
               'naive_bayes_xgb_rec_dataset.csv',
               'qda_gnb_rec_dataset.csv',
               'qda_xgb_rec_dataset.csv',
               'sampling_gnb_rec_dataset.csv',
               'sampling_xgb_rec_dataset.csv',
               'xgb_gnb_rec_dataset.csv',
               'xgb_xgb_rec_dataset.csv']
out_root='./data/result logs/'

N_SCENARIOS=100
ANOMALY_THRESHOLDS=[0.3, 0.6, 0.9]
SUSPECT_THRESHOLDS=[0.2, 0.8]
TYPE_THRESHOLD=0.1
TORELANCE=2000

output_log_prefixes=[out_root + '_'.join(name.split('_')[:-2]) for name in dataset_files]
file_dict={}
for file in dataset_files:
    for a_v in ANOMALY_THRESHOLDS:
        for s_v in SUSPECT_THRESHOLDS:
            output_file=out_root+"u_"+file.removesuffix(".csv")+f"_av_{a_v}_sv_{s_v}.txt"
            input_file=root+file
            file_dict[output_file]=(input_file, a_v, s_v)

import os
for out_file, p in file_dict.items():
    if p[1] > p[2]:
        print(f"evaluating reconstruction mechanism for {p[0]} with anomaly threshold {p[1]}, suspect threshold {p[2]}, type threshold {TYPE_THRESHOLD} and torelance {TORELANCE}")
        code=os.system(f"python3 -m scenario_reconstructor.reconstruct_cAPTure -f \"{p[0]}\" -t {N_SCENARIOS} --anomaly-threshold {p[1]} --suspect-threshold {p[2]} --type-threshold {TYPE_THRESHOLD} --torelance {TORELANCE} -l \"{out_file}\"")
        if code != 0:
            print(f"FAILED (exit {code}): {out_file}")