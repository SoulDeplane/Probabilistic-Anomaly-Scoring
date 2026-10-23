"""Audit of CICIoT2023 (Neto et al., Sensors 2023): duplicates across all 63 merged files, and trivial baselines.

  * duplicates: flows whose 39 features and label repeat an earlier flow, within one file and across all 63
    merged files; feature vectors that appear under more than one label; the duplicate share of each class.
    Rows are compared through a 64-bit hash of their feature values (collision odds ~1e-4 over 47 M rows).
  * the packet-window confound: the mean of 'Number' per class (the window size set from the class label)
  * trivial baselines on Merged01.csv (CIC shuffled it), benign vs attack: majority class and the
    single-feature stump of every feature, as accuracy and as balanced accuracy

Usage: python src/audit_ciciot23.py
"""
import glob
import json
import os
import re
import time

import numpy as np
import pandas as pd
from sklearn.metrics import balanced_accuracy_score
from sklearn.tree import DecisionTreeClassifier

from replicate_khalid import ROOT

MERGED = os.path.join(ROOT, '..', 'Datasets', 'ciciot23', 'CSV', 'MERGED_CSV', 'MERGED_CSV')
OUT = os.path.join(ROOT, 'results', 'audit')


def natural_key(s):
    return [int(t) if t.isdigit() else t for t in re.split(r'(\d+)', s)]


def scan(files):
    """One pass over the merged files: per-row feature hash, label code and file index."""
    hashes, labels, file_ix, labels_seen = [], [], [], {}
    number_sum, rows, non_finite = {}, {}, 0
    for i, path in enumerate(files):
        t0 = time.time()
        df = pd.read_csv(path)
        feats = [c for c in df.columns if c != 'Label']
        non_finite += int((~np.isfinite(df[feats].to_numpy(np.float64))).any(axis=1).sum())
        hashes.append(pd.util.hash_pandas_object(df[feats], index=False).to_numpy())
        codes = df['Label'].map(lambda l: labels_seen.setdefault(l, len(labels_seen))).to_numpy(np.int16)
        labels.append(codes)
        file_ix.append(np.full(len(df), i, np.int16))
        g = df.groupby('Label')['Number']
        for lab, s in g.sum().items():
            number_sum[lab] = number_sum.get(lab, 0.0) + float(s)
        for lab, n in g.size().items():
            rows[lab] = rows.get(lab, 0) + int(n)
        print(f'{os.path.basename(path)}: {len(df):,} rows in {time.time() - t0:.0f}s', flush=True)
    names = np.array(sorted(labels_seen, key=labels_seen.get), dtype=object)
    return (np.concatenate(hashes), np.concatenate(labels), np.concatenate(file_ix), names,
            {lab: number_sum[lab] / rows[lab] for lab in rows}, rows, non_finite)


def repeats(*keys):
    """True for every row whose key tuple already occurred earlier (in sort order)."""
    order = np.lexsort(keys[::-1])
    sorted_keys = [k[order] for k in keys]
    same = np.ones(len(order) - 1, bool)
    for k in sorted_keys:
        same &= k[1:] == k[:-1]
    out = np.zeros(len(order), bool)
    out[order[1:][same]] = True
    return out


def stumps(path):
    df = pd.read_csv(path)
    feats = [c for c in df.columns if c != 'Label']
    df = df[np.isfinite(df[feats].to_numpy(np.float64)).all(axis=1)]
    y = (df['Label'] != 'BENIGN').to_numpy(int)
    res = {}
    for c in feats:
        x = df[[c]].to_numpy()
        pred = DecisionTreeClassifier(max_depth=1).fit(x, y).predict(x)
        bal = DecisionTreeClassifier(max_depth=1, class_weight='balanced').fit(x, y).predict(x)
        res[c] = {'accuracy': round(float((pred == y).mean()), 4),
                  'balanced_accuracy': round(float(balanced_accuracy_score(y, bal)), 4)}
    by_acc = sorted(res.items(), key=lambda kv: -kv[1]['accuracy'])
    by_bal = sorted(res.items(), key=lambda kv: -kv[1]['balanced_accuracy'])
    return {'file': os.path.basename(path), 'rows': len(df), 'attack_share': float(y.mean()),
            'majority_class_accuracy': float(max(y.mean(), 1 - y.mean())),
            'best_stumps_by_accuracy': dict(by_acc[:5]), 'best_stumps_by_balanced_accuracy': dict(by_bal[:5])}


def main():
    files = sorted(glob.glob(os.path.join(MERGED, 'Merged*.csv')), key=natural_key)
    h, lab, fi, names, number_mean, rows, non_finite = scan(files)
    dup = repeats(h, lab)                  # same features and label as an earlier flow
    dup_in_file = repeats(h, lab, fi)      # ... earlier in the same file
    repeat_vec = repeats(h)
    order = np.argsort(h, kind='stable')
    starts = np.r_[0, np.flatnonzero(np.diff(h[order])) + 1]
    mixed = np.minimum.reduceat(lab[order], starts) != np.maximum.reduceat(lab[order], starts)

    per_class = pd.DataFrame({'label': names[lab], 'dup': dup}).groupby('label')['dup'].agg(['size', 'sum'])
    a = {
        'files': len(files), 'rows': int(len(h)), 'rows_with_non_finite_values': non_finite,
        'duplicates': {
            'rows_repeating_an_earlier_flow': int(dup.sum()), 'share': float(dup.mean()),
            'of_which_within_the_same_file': int(dup_in_file.sum()),
            'of_which_only_across_files': int((dup & ~dup_in_file).sum()),
            'repeated_feature_vectors_ignoring_label': int(repeat_vec.sum()),
            'feature_vectors_under_more_than_one_label': int(mixed.sum()),
            'share_by_class': (per_class['sum'] / per_class['size']).round(4).sort_values(ascending=False).to_dict(),
        },
        'packet_window_number_mean_by_class': {k: round(v, 2) for k, v in
                                               sorted(number_mean.items(), key=lambda kv: -kv[1])},
        'rows_by_class': dict(sorted(rows.items(), key=lambda kv: -kv[1])),
        'trivial_baselines': stumps(files[0]),
    }
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, 'ciciot23.json'), 'w') as f:
        json.dump(a, f, indent=2)
    print(json.dumps({k: v for k, v in a.items() if k != 'rows_by_class'}, indent=2))


if __name__ == '__main__':
    main()
