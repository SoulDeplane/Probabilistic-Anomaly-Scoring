"""Apply the Khalid et al. (2025) autoencoder protocol, unchanged, to CICIoT2023 and Dumpware10.

Same model, hyperparameters, seeds, no-scaling, benign-only training, test-on-all and
mean + 3*std threshold as src/replicate_khalid.py. Adaptations forced by the datasets:
  * Anomaly ratio: malicious rows = 5% of the benign count (on the balanced MalMem data this is
    identical to the paper's "initial 5% of malicious instances"; taken literally on CICIoT2023
    it would yield more attacks than benign rows).
  * CICIoT2023: benign = all Benign_Final rows; malicious = first rows of Merged01.csv (CIC
    already shuffled it); the 76 rows containing inf/NaN are dropped.
  * Dumpware10: 224/224 rendering, raw RGB pixels flattened (150,528 inputs); benign = all
    'Other' images; malicious = seeded random sample (images have no file order).

Usage: python src/khalid_ae_other_datasets.py {ciciot23,dumpware10} [--seeds 42 ...]
"""
import argparse
import glob
import json
import math
import os

import numpy as np
import pandas as pd

from replicate_khalid import ROOT, train_paper_autoencoder

DATASETS = os.path.join(ROOT, '..', 'Datasets')
RESULTS = os.path.join(ROOT, 'results', 'replication')
RATIO = 0.05


def load_ciciot23():
    base = os.path.join(DATASETS, 'ciciot23', 'CSV')
    benign = pd.concat([pd.read_csv(f) for f in sorted(glob.glob(os.path.join(base, 'CSV', 'Benign_Final', '*.csv')))])
    merged = pd.read_csv(os.path.join(base, 'MERGED_CSV', 'MERGED_CSV', 'Merged01.csv'))
    attacks = merged[merged['Label'] != 'BENIGN'].drop(columns=['Label'])
    assert list(benign.columns) == list(attacks.columns)

    def finite(df):
        arr = df.to_numpy(np.float32)
        return arr[np.isfinite(arr).all(axis=1)]

    b, a = finite(benign), finite(attacks)
    a = a[:math.ceil(RATIO * len(b))]
    info = {'benign_rows': len(b), 'malicious_rows': len(a),
            'dropped_non_finite': int(len(benign) + len(attacks) - len(finite(benign)) - len(finite(attacks)))}
    return b, a, info


def load_dumpware10():
    from PIL import Image

    base = os.path.join(DATASETS, 'dumpware10', '224', '224')
    paths = sorted(glob.glob(os.path.join(base, '*', '*', '*.png')))
    benign_p = [p for p in paths if os.path.basename(os.path.dirname(p)) == 'Other']
    mal_p = [p for p in paths if os.path.basename(os.path.dirname(p)) != 'Other']
    rng = np.random.default_rng(42)
    mal_p = [mal_p[i] for i in sorted(rng.choice(len(mal_p), math.ceil(RATIO * len(benign_p)), replace=False))]

    def load(ps):
        return np.stack([np.asarray(Image.open(p).convert('RGB'), dtype=np.float32).ravel() for p in ps])

    families = pd.Series([os.path.basename(os.path.dirname(p)) for p in mal_p]).value_counts().to_dict()
    info = {'benign_rows': len(benign_p), 'malicious_rows': len(mal_p), 'malicious_families': families}
    return load(benign_p), load(mal_p), info


def plot_confusion(cm, title, path):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import seaborn as sns

    plt.figure(figsize=(5, 4))
    sns.heatmap(np.array(cm), annot=True, fmt='d', cmap='Blues',
                xticklabels=['Benign', 'Anomaly'], yticklabels=['Benign', 'Malicious'])
    plt.title(title)
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dataset', choices=['ciciot23', 'dumpware10'])
    ap.add_argument('--seeds', type=int, nargs='+', default=[42])
    args = ap.parse_args()
    os.makedirs(RESULTS, exist_ok=True)

    benign, malicious, info = (load_ciciot23 if args.dataset == 'ciciot23' else load_dumpware10)()
    X_test = np.concatenate([benign, malicious])
    y_test = np.concatenate([np.zeros(len(benign), int), np.ones(len(malicious), int)])
    majority = len(benign) / len(X_test)
    print(f'{args.dataset}: {json.dumps(info)} | inputs={X_test.shape[1]:,} | '
          f'majority-class accuracy={majority:.4f}', flush=True)

    runs = []
    for seed in args.seeds:
        r = train_paper_autoencoder(benign, X_test, y_test, seed)
        runs.append(r)
        print(f'Autoencoder (tf seed {seed}): {json.dumps(r)}', flush=True)
        plot_confusion(r['confusion_matrix'], f'Autoencoder: {args.dataset} (seed {seed})',
                       os.path.join(RESULTS, f'confusion_{args.dataset}_seed{seed}.png'))

    with open(os.path.join(RESULTS, f'{args.dataset}.json'), 'w') as f:
        json.dump({'data': info, 'majority_class_accuracy': majority, 'autoencoder': runs}, f, indent=2)


if __name__ == '__main__':
    main()
