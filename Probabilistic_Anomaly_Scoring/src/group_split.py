"""Hash-grouped versus random splits on CIC MalMemAnalysis-2022 for supervised models (study guide, 4.4).

Each malware binary contributes about ten memory dumps taken 15 seconds apart. A random split puts dumps of
the same binary on both sides of the train/test boundary; a split grouped on the SHA-256 in the file name does
not. Models trained on clean rows only are unaffected (they never see malware in training), but supervised
baselines, and any tuning that uses malware, are.

Duplicate feature vectors (569) are dropped first (src/protocol.py). A Random Forest (100 trees) is scored with
5-fold cross-validation, stratified, either at random or grouped by binary (StratifiedGroupKFold; each clean
row is its own group), on three tasks: binary, 4-class (benign / ransomware / spyware / trojan) and 16-class
(benign + 15 families). Reported: accuracy and macro-F1 per fold, their means and the random-minus-grouped gap.

Usage: python src/group_split.py
"""
import json
import os

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold

import protocol as P
from replicate_khalid import ROOT

OUT = os.path.join(ROOT, 'results', 'group_split')


def main():
    ds = P.load_malmem()
    groups = ds.extra['groups']
    tasks = {'binary': ds.y,
             '4-class': np.array([f.split('-')[0] for f in ds.family]),
             '16-class': ds.family.astype(str)}
    splitters = {'random': StratifiedKFold(5, shuffle=True, random_state=0),
                 'grouped_by_binary': StratifiedGroupKFold(5, shuffle=True, random_state=0)}
    results = {'data': {'rows': len(ds.y), 'duplicates_dropped': ds.info['duplicates_dropped'],
                        'malware_binaries': ds.info['malware_binaries']}}
    for task, y in tasks.items():
        results[task] = {}
        for split, cv in splitters.items():
            folds = []
            for tr, te in cv.split(ds.X, y, groups if split == 'grouped_by_binary' else None):
                leak = len(set(groups[tr][ds.y[tr] == 1]) & set(groups[te][ds.y[te] == 1]))
                rf = RandomForestClassifier(n_estimators=100, random_state=0, n_jobs=-1).fit(ds.X[tr], y[tr])
                pred = rf.predict(ds.X[te])
                folds.append({'accuracy': accuracy_score(y[te], pred), 'macro_f1': f1_score(y[te], pred, average='macro'),
                              'binaries_on_both_sides': leak})
            results[task][split] = {'folds': folds, **{m: float(np.mean([f[m] for f in folds]))
                                                       for m in ('accuracy', 'macro_f1')}}
            print(f'{task:8s} {split:18s} accuracy {results[task][split]["accuracy"]:.4f}  '
                  f'macro-F1 {results[task][split]["macro_f1"]:.4f}  binaries on both sides per fold: '
                  f'{[f["binaries_on_both_sides"] for f in folds]}', flush=True)
        results[task]['gap_random_minus_grouped'] = {
            m: results[task]['random'][m] - results[task]['grouped_by_binary'][m] for m in ('accuracy', 'macro_f1')}

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, 'malmem.json'), 'w') as f:
        json.dump(results, f, indent=2)


if __name__ == '__main__':
    main()
