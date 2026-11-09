"""Held-out evaluation of the clean-only detectors (study guide, section 5, steps 1-3; section 4, items 1-2).

Fixes the circularity of src/prove_imbalance.py test F, whose 1% false-alarm threshold was set and tested on
the same clean rows. The protocol is in src/protocol.py: duplicate rows dropped; clean rows split 60/20/20
into train / calibrate / test; scaler and models fitted on the training rows only; every number is measured
on clean rows that no model or threshold has seen.

Detectors, 5 seeds: the base paper's autoencoder (input-64-32-64-input, scaled features), the VAE of src/vae.py
(score = negative ELBO) and Isolation Forest.
Flag lines, all tested on the same unseen rows:
  paper_mean_plus_3std   mean + 3 std of training error (the base paper)
  train_99th_percentile  99th percentile of training error (the old '1% budget', set on training rows)
  conformal_1pct / 5pct  p <= 0.01 / 0.05, with p computed from the held-out calibration rows
Baselines: always clean, and the best single-feature stump (supervised: it also sees the malware 'fit' rows).
Recall per family (MalMem), attack class (CICIoT2023) or category (BODMAS) is given at conformal_1pct; on
MalMem also for the base paper's own 1,465 test malware (Conti and Ako only), as test set 'paper_malware'.

Options:
  --drop svcscan  retrain without MalMem's svcscan.* features (the one-feature shortcut)
  --drop window   retrain without CICIoT2023's Number, Tot sum, IAT, Variance and Rate (window-sensitive)
  --detectors ... train only these; their results are merged into the existing JSON, the others kept
  --temporal      BODMAS: train and calibrate on files first seen before March 2020; test on held-out older
                  files (test_old) and on everything first seen later (test_new)

Usage: python src/heldout_eval.py {malmem,ciciot23,bodmas} [--drop svcscan|window] [--temporal] [--detectors ...] [--seeds ...]
"""
import argparse
import json
import os
import time

import numpy as np
from sklearn.preprocessing import StandardScaler

import protocol as P
from replicate_khalid import ROOT

RESULTS = os.path.join(ROOT, 'results', 'heldout')
DETECTORS = ('autoencoder', 'vae', 'isolation_forest')


def test_sets(ds):
    clean = lambda p: (ds.y == 0) & (ds.part == p)
    mal = lambda p: (ds.y == 1) & (ds.part == p)
    if 'test_new' in ds.part:
        return {p: (clean(p), mal(p)) for p in ('test_old', 'test_new')}
    sets = {'test': (clean('test'), mal('test'))}
    if 'paper_test' in ds.extra:
        sets['paper_malware'] = (clean('test'), ds.extra['paper_test'])
    return sets


def evaluate(score, X, ds, sets, train_scores, cal_scores):
    out = {}
    lines = P.thresholds(train_scores, cal_scores)
    for name, (clean, mal) in sets.items():
        sc, sm = score(X[clean]), score(X[mal])
        r = P.ranking(sc, sm)
        for t, line in lines.items():
            r[t] = P.at_flags(P.flags(t, line, sc, cal_scores), P.flags(t, line, sm, cal_scores))
        r['recall_by_family_conformal_1pct'] = P.per_family(P.flags('conformal_1pct', 0.01, sm, cal_scores),
                                                            ds.family[mal])
        out[name] = r
    return out


def stump_baseline(ds, sets):
    fit = ((ds.y == 0) & (ds.part == 'train')) | ((ds.y == 1) & (ds.part == 'fit'))
    info, proba = P.best_stump(ds.X[fit], ds.y[fit], ds.features)
    for name, (clean, mal) in sets.items():
        pc, pm = proba(ds.X[clean]), proba(ds.X[mal])
        info[name] = {**P.ranking(pc, pm), **P.at_flags(pc > 0.5, pm > 0.5),
                      'recall_by_family': P.per_family(pm > 0.5, ds.family[mal])}
    return info


def line(name, r):
    c = r['conformal_1pct']
    return (f'{name:14s} ROC-AUC {r["roc_auc"]:.3f}  PR-AUC {r["pr_auc_20to1"]:.3f} | p<=0.01: false alarms '
            f'{c["false_alarm_rate"]:.2%}  recall {c["recall"]:.3f}  F1 {c["f1_20to1"]:.3f} | paper line: '
            f'false alarms {r["paper_mean_plus_3std"]["false_alarm_rate"]:.2%}  recall '
            f'{r["paper_mean_plus_3std"]["recall"]:.3f}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dataset', choices=sorted(P.LOADERS))
    ap.add_argument('--drop', choices=sorted(P.DROP_GROUPS))
    ap.add_argument('--temporal', action='store_true')
    ap.add_argument('--detectors', nargs='+', choices=DETECTORS, default=list(DETECTORS))
    ap.add_argument('--seeds', type=int, nargs='+', default=[42, 1, 2, 3, 4])
    args = ap.parse_args()
    if args.temporal and args.dataset != 'bodmas':
        ap.error('--temporal needs first-seen dates, which only BODMAS has')

    ds = P.load_bodmas(temporal=True) if args.temporal else P.LOADERS[args.dataset]()
    if args.drop:
        ds.drop(args.drop)
    sets = test_sets(ds)
    print(f'{args.dataset}: {json.dumps(ds.info)}', flush=True)

    train, cal = (ds.y == 0) & (ds.part == 'train'), (ds.y == 0) & (ds.part == 'cal')
    Xs = StandardScaler().fit(ds.X[train]).transform(ds.X).astype(np.float32)
    results = {'data': ds.info, 'baselines': {'always_clean': P.majority_baseline(),
                                              'best_stump': stump_baseline(ds, sets)}, 'runs': {}, 'summary': {}}
    stump = results['baselines']['best_stump']
    print('best stump:', stump['rule'], flush=True)
    for name in sets:
        r = stump[name]
        print(f'stump {name:14s} ROC-AUC {r["roc_auc"]:.3f}  PR-AUC {r["pr_auc_20to1"]:.3f} | false alarms '
              f'{r["false_alarm_rate"]:.2%}  recall {r["recall"]:.3f}  F1 {r["f1_20to1"]:.3f}', flush=True)

    for det in args.detectors:
        runs = {}
        for seed in args.seeds:
            t0 = time.time()
            score, _ = P.fit_detector(det, Xs[train], seed)
            runs[seed] = evaluate(score, Xs, ds, sets, score(Xs[train]), score(Xs[cal]))
            runs[seed]['seconds'] = round(time.time() - t0, 1)
            for name in sets:
                print(f'{det} seed {seed}: ' + line(name, runs[seed][name]), flush=True)
        results['runs'][det] = runs
        results['summary'][det] = P.summarise(list(runs.values()))

    os.makedirs(RESULTS, exist_ok=True)
    tag = args.dataset + ('_temporal' if args.temporal else '') + (f'_no-{args.drop}' if args.drop else '')
    path = os.path.join(RESULTS, f'{tag}.json')
    if set(args.detectors) != set(DETECTORS) and os.path.exists(path):
        with open(path) as f:
            old = json.load(f)
        for key in ('runs', 'summary'):
            results[key] = {**old[key], **results[key]}
    with open(path, 'w') as f:
        json.dump(results, f, indent=2)


if __name__ == '__main__':
    main()
