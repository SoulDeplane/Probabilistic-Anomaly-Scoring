"""Leave-one-family-out (LOFO) test on CIC MalMem-2022 (synopsis Phase 5 / section 6.3).

For each of the 15 malware families, supervised comparators are trained on the clean training rows plus every
malware row of the other 14 families, then tested on all rows of the held-out family and on the held-out clean
test rows. This asks whether what separates the classes carries over to a family never seen in training.

  models     best one-feature stump (depth-1 tree) and a Random Forest (100 trees), both with labels
  reference  the clean-only autoencoder's per-family recall at p <= 0.01 from results/heldout/malmem.json: it
             never sees malware, so every family is already unseen for it
  variants   all 55 features, and without the svcscan plugin (--drop svcscan in heldout_eval.py)

Partitions and duplicate removal come from protocol.load_malmem(), so the clean rows match the other experiments.

Usage: python src/leave_one_family_out.py
"""
import json
import os

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from protocol import DROP_GROUPS, ROOT, load_malmem

RESULTS = os.path.join(ROOT, 'results', 'lofo')
HELDOUT = os.path.join(ROOT, 'results', 'heldout')


def stump_rule(tree, features):
    t = tree.tree_
    j, thr = t.feature[0], t.threshold[0]
    left_malware = np.argmax(t.value[t.children_left[0]][0]) == 1
    return features[j], f'malware if {features[j]} {"<=" if left_malware else ">"} {thr:g}'


def lofo(X, y, part, family, features):
    clean_train = (y == 0) & (part == 'train')
    clean_test = (y == 0) & (part == 'test')
    folds = []
    for fam in sorted(set(family[y == 1])):
        held = family == fam
        train = clean_train | ((y == 1) & ~held)
        fold = {'family': fam, 'n_test_malware': int(held.sum())}
        stump = DecisionTreeClassifier(max_depth=1, random_state=0).fit(X[train], y[train])
        rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=0).fit(X[train], y[train])
        for name, model in (('stump', stump), ('random_forest', rf)):
            fold[name] = {'recall': round(float(model.predict(X[held]).mean()), 4),
                          'false_alarm_rate': round(float(model.predict(X[clean_test]).mean()), 4)}
        fold['stump']['feature'], fold['stump']['rule'] = stump_rule(stump, features)
        folds.append(fold)
        print(f"  {fam:24s} stump {fold['stump']['recall']:.3f} ({fold['stump']['feature']})  "
              f"RF {fold['random_forest']['recall']:.3f}", flush=True)
    summary = {}
    for name in ('stump', 'random_forest'):
        r = [f[name]['recall'] for f in folds]
        fa = [f[name]['false_alarm_rate'] for f in folds]
        summary[name] = {'recall_mean': round(float(np.mean(r)), 4), 'recall_min': min(r),
                         'false_alarm_rate_max': max(fa)}
    feats = [f['stump']['feature'] for f in folds]
    summary['stump']['features_chosen'] = {k: feats.count(k) for k in sorted(set(feats))}
    return {'folds': folds, 'summary': summary}


def autoencoder_reference(tag):
    path = os.path.join(HELDOUT, f'{tag}.json')
    if not os.path.exists(path):
        return None
    runs = json.load(open(path))['runs']['autoencoder'].values()
    per_seed = [r['test']['recall_by_family_conformal_1pct'] for r in runs]
    fams = per_seed[0].keys()
    return {f: round(float(np.mean([s[f]['recall'] for s in per_seed])), 4) for f in fams}


def main():
    os.makedirs(RESULTS, exist_ok=True)
    out = {}
    for variant, tag in (('all_features', 'malmem'), ('no_svcscan', 'malmem_no-svcscan')):
        ds = load_malmem()
        if variant == 'no_svcscan':
            ds.drop('svcscan')
        print(variant, flush=True)
        res = lofo(ds.X, ds.y, ds.part, ds.family, ds.features)
        res['autoencoder_clean_only_recall_by_family'] = autoencoder_reference(tag)
        res['dropped_features'] = ds.info.get('dropped_features', [])
        out[variant] = res
        print('  summary', res['summary'], flush=True)
    with open(os.path.join(RESULTS, 'malmem.json'), 'w') as f:
        json.dump(out, f, indent=2)
    print('saved results/lofo/malmem.json')


if __name__ == '__main__':
    main()
