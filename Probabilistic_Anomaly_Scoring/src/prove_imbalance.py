"""Does class imbalance explain the paper autoencoder's results? Tested on all three datasets.

Same model as the paper (src/replicate_khalid.py), 3 seeds. The 20:1 malware set is a random
subset of the 1:1 set, so B differs from A only in imbalance, not in malware composition.
  A  paper protocol: unscaled, test = all benign + malware at 5% of benign (20:1)
  B  model A, test rebalanced 1:1 with REAL malware             (test imbalance removed)
  C  model A, test rebalanced 1:1 with SMOTE-synthesised malware (SMOTE)
  D  retrained on as many benign rows as 20:1 malware (training undersampling), tested as A
  E  retrained on StandardScaler-scaled features (fit on benign training data), tested as A
  F  model E, threshold = 99th / 95th percentile of benign training error (1% / 5% FP budget)

Data: MalMem all 29,298 benign; CICIoT2023 50,000 sampled benign flows; Dumpware10 all 608
benign images (224/224 rendering, raw RGB pixels flattened); BODMAS 50,000 sampled benign
executables and 50,000 sampled malware (2,381 unnormalised EMBER features).

Usage: python src/prove_imbalance.py {malmem,ciciot23,dumpware10,bodmas} [--seeds 42 1 2]
"""
import argparse
import glob
import json
import math
import os

import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.preprocessing import StandardScaler

from replicate_khalid import ROOT, fit_paper_autoencoder, reconstruction_mse

DATASETS = os.path.join(ROOT, '..', 'Datasets')
RESULTS = os.path.join(ROOT, 'results', 'prove_imbalance')
CICIOT_N_BENIGN = 50_000
BODMAS_N = 50_000


def small_set(benign, mal_all):
    return mal_all[:math.ceil(0.05 * len(benign))]


def load_malmem():
    df = pd.read_csv(os.path.join(DATASETS, 'cicmalmem22', 'CSV', 'Obfuscated-MalMem2022.csv'))
    X = df.drop(columns=['Category', 'Class']).to_numpy(np.float32)
    benign, mal = X[df['Class'] == 'Benign'], X[df['Class'] == 'Malware']
    return benign, mal[np.random.default_rng(0).permutation(len(mal))]


def load_ciciot23():
    base = os.path.join(DATASETS, 'ciciot23', 'CSV')
    benign = pd.concat([pd.read_csv(f) for f in sorted(glob.glob(os.path.join(base, 'CSV', 'Benign_Final', '*.csv')))])
    merged = pd.read_csv(os.path.join(base, 'MERGED_CSV', 'MERGED_CSV', 'Merged01.csv'))
    attacks = merged[merged['Label'] != 'BENIGN'].drop(columns=['Label'])
    b = benign.to_numpy(np.float32)
    a = attacks.to_numpy(np.float32)
    b = b[np.isfinite(b).all(axis=1)]
    a = a[np.isfinite(a).all(axis=1)]
    b = b[np.random.default_rng(0).choice(len(b), CICIOT_N_BENIGN, replace=False)]
    return b, a[:CICIOT_N_BENIGN]  # Merged01 is already shuffled by CIC


def load_dumpware10():
    from PIL import Image

    paths = sorted(glob.glob(os.path.join(DATASETS, 'dumpware10', '224', '224', '*', '*', '*.png')))
    benign_p = [p for p in paths if os.path.basename(os.path.dirname(p)) == 'Other']
    mal_p = [p for p in paths if os.path.basename(os.path.dirname(p)) != 'Other']
    mal_p = [mal_p[i] for i in np.random.default_rng(0).choice(len(mal_p), len(benign_p), replace=False)]

    def load(ps):
        return np.stack([np.asarray(Image.open(p).convert('RGB'), dtype=np.float32).ravel() for p in ps])

    return load(benign_p), load(mal_p)


def load_bodmas():
    z = np.load(os.path.join(DATASETS, 'bodmas', 'bodmas.npz'), allow_pickle=False)
    X, y = z['X'], z['y']
    b, a = X[y == 0], X[y == 1]
    b = b[np.random.default_rng(0).choice(len(b), BODMAS_N, replace=False)]
    return b, a[np.random.default_rng(0).permutation(len(a))[:BODMAS_N]]


LOADERS = {'malmem': load_malmem, 'ciciot23': load_ciciot23, 'dumpware10': load_dumpware10,
           'bodmas': load_bodmas}


def score(y, pred):
    return {'precision': round(precision_score(y, pred, zero_division=0), 4),
            'recall': round(recall_score(y, pred), 4),
            'f1': round(f1_score(y, pred), 4),
            'confusion_matrix': confusion_matrix(y, pred).tolist()}


def evaluate(err_benign, err_mal, threshold):
    y = np.r_[np.zeros(len(err_benign), int), np.ones(len(err_mal), int)]
    return score(y, (np.r_[err_benign, err_mal] > threshold).astype(int))


def paper_threshold(train_err):
    return float(np.mean(train_err) + 3 * np.std(train_err))


def run_seed(benign, mal_all, seed):
    mal = small_set(benign, mal_all)
    out = {}

    # A, B, C: one unscaled model, three test sets
    model, _, _ = fit_paper_autoencoder(benign, seed, verbose=0)
    eb, em, em_all = (reconstruction_mse(model, x) for x in (benign, mal, mal_all))
    thr = paper_threshold(eb)
    out['A_paper_20to1'] = evaluate(eb, em, thr)
    out['B_same_model_1to1_real'] = evaluate(eb, em_all, thr)
    X_sm, _ = SMOTE(sampling_strategy=1.0, random_state=seed, k_neighbors=min(5, len(mal) - 1)).fit_resample(
        np.r_[benign, mal], np.r_[np.zeros(len(benign), int), np.ones(len(mal), int)])
    es = reconstruction_mse(model, X_sm[len(benign) + len(mal):])  # imblearn appends synthetic rows
    out['C_same_model_1to1_SMOTE'] = evaluate(eb, np.r_[em, es], thr)
    out['C_same_model_1to1_SMOTE']['recall_on_real_malware_only'] = round(float((em > thr).mean()), 4)
    del X_sm, es

    # D: undersample benign for training (1:1 with malware), same test set as A
    small = benign[np.random.default_rng(seed).choice(len(benign), len(mal), replace=False)]
    model_d, _, _ = fit_paper_autoencoder(small, seed, verbose=0)
    thr_d = paper_threshold(reconstruction_mse(model_d, small))
    out['D_undersampled_training_1to1'] = evaluate(reconstruction_mse(model_d, benign),
                                                   reconstruction_mse(model_d, mal), thr_d)

    # E, F: StandardScaler fitted on benign training data only, imbalance unchanged (20:1)
    scaler = StandardScaler().fit(benign)
    bs, ms = scaler.transform(benign).astype(np.float32), scaler.transform(mal).astype(np.float32)
    model_e, _, _ = fit_paper_autoencoder(bs, seed, verbose=0)
    ebs, ems = reconstruction_mse(model_e, bs), reconstruction_mse(model_e, ms)
    out['E_scaled_20to1'] = evaluate(ebs, ems, paper_threshold(ebs))
    out['F_scaled_FP_budget_1pct'] = evaluate(ebs, ems, float(np.percentile(ebs, 99)))
    out['F_scaled_FP_budget_5pct'] = evaluate(ebs, ems, float(np.percentile(ebs, 95)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dataset', choices=sorted(LOADERS))
    ap.add_argument('--seeds', type=int, nargs='+', default=[42, 1, 2])
    args = ap.parse_args()
    os.makedirs(RESULTS, exist_ok=True)

    benign, mal_all = LOADERS[args.dataset]()
    print(f'{args.dataset}: benign={len(benign):,}  malware(20:1)={len(small_set(benign, mal_all)):,}  '
          f'malware(1:1)={len(mal_all):,}  inputs={benign.shape[1]:,}', flush=True)
    results = {}
    for seed in args.seeds:
        results[seed] = run_seed(benign, mal_all, seed)
        for k, v in results[seed].items():
            print(f'seed {seed} {k}: {json.dumps(v)}', flush=True)

    summary = {}
    for k in results[args.seeds[0]]:
        summary[k] = {m: [results[s][k][m] for s in args.seeds] for m in ('precision', 'recall', 'f1')}
    with open(os.path.join(RESULTS, f'{args.dataset}.json'), 'w') as f:
        json.dump({'runs': results, 'summary': summary}, f, indent=2)
    print('SUMMARY ' + json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
