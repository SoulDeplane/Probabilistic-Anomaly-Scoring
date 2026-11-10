"""Replication and audit of the clustering half of Khalid, Iqbal & Saqib (2025), FSI: DI 53, 301924.

Mirrors the authors' Colab notebooks (links in github.com/znbkhld/Unupervised-XAI-DF):
  * data: all 58,596 rows of the official Obfuscated-MalMem2022.csv, in file order. 'Cat' (Benign +
    3 malware types) and 'Sub Cat' (Benign + 15 families) are parsed from 'Category'; all labels are
    dropped before clustering and used only to score the clusters with the Adjusted Rand Index (ARI).
  * StandardScaler on all rows.
  * K-means: n_clusters=2, random_state=42, scored against 'Class'. The K-means notebook alone also
    drops the 9 columns in KMEANS_DROP.
  * GMM: n_components=2 against 'Class' and 4 against 'Cat', random_state=42.
  * DBSCAN: eps=2.3, min_samples=190 against 'Sub Cat'.
Paper-reported ARIs: K-means 0.7544, DBSCAN 0.5690, GMM-2 0.9592, GMM-4 0.6449.

The audit adds: five seeds; a label-free one-feature baseline (the same models on svcscan.nservices
alone); reference ARIs of a perfect benign-vs-malware split scored against the 4- and 16-way labels;
reruns without the svcscan plugin and without duplicate rows; and a DBSCAN eps/min_samples grid.

DBSCAN is computed by `dbscan_labels`, a chunked implementation that returns the same labels as
sklearn.cluster.DBSCAN (checked by --check-dbscan) without holding every neighbourhood in memory:
at eps=2.3 the full data has about 370 million neighbour pairs.

Usage: python src/replicate_khalid_clustering.py [--check-dbscan] [--no-grid]
"""
import argparse
import json
import os
import time

import numpy as np
import pandas as pd
from scipy.sparse import coo_matrix
from scipy.sparse.csgraph import connected_components
from sklearn.cluster import DBSCAN, KMeans
from sklearn.metrics import adjusted_rand_score, confusion_matrix
from sklearn.mixture import GaussianMixture
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, '..', 'Datasets', 'cicmalmem22', 'CSV', 'Obfuscated-MalMem2022.csv')
RESULTS = os.path.join(ROOT, 'results', 'clustering')

KMEANS_DROP = ['ldrmodules.not_in_init_avg', 'psxview.not_in_eprocess_pool',
               'psxview.not_in_eprocess_pool_false_avg', 'callbacks.nanonymous', 'svcscan.fs_drivers',
               'callbacks.ngeneric', 'handles.nport', 'pslist.nprocs64bit',
               'svcscan.interactive_process_services']
SHORTCUT = 'svcscan.nservices'
SEEDS = [42, 1, 2, 3, 4]
PAPER = {'kmeans_2': 0.7544, 'dbscan_16': 0.5690, 'gmm_2': 0.9592, 'gmm_4': 0.6449}
GRID_EPS = [1.5, 2.0, 2.3, 2.6, 3.0]
GRID_MIN_SAMPLES = [50, 100, 190, 300]


def load():
    df = pd.read_csv(DATA)
    parts = df['Category'].str.split('-')
    labels = pd.DataFrame({
        'Class': df['Class'],
        'Cat': parts.str[0],
        'Sub Cat': parts.str[1].where(parts.str[0] != 'Benign', 'Benign'),
    })
    X = df.drop(columns=['Category', 'Class'])
    assert X.shape == (58596, 55) and labels['Cat'].nunique() == 4 and labels['Sub Cat'].nunique() == 16
    return df, X, labels


def scale(X):
    return StandardScaler().fit_transform(X)


def ari(y, clusters):
    return round(float(adjusted_rand_score(y, clusters)), 4)


# ---------------------------------------------------------------- DBSCAN

def _neighbours(nn, Q, eps, chunk):
    for s in range(0, len(Q), chunk):
        yield s, nn.radius_neighbors(Q[s:s + chunk], eps, return_distance=False)


def neighbour_counts(X, eps, chunk=1000):
    nn = NearestNeighbors().fit(X)
    counts = np.empty(len(X), np.int64)
    for s, nbrs in _neighbours(nn, X, eps, chunk):
        counts[s:s + len(nbrs)] = [len(a) for a in nbrs]
    return counts


def dbscan_labels(X, eps, min_samples, counts=None, chunk=1000):
    """Same labels as sklearn DBSCAN(eps, min_samples).fit_predict(X), computed in chunks.

    sklearn's DBSCAN visits points in index order and grows one cluster at a time, so cluster k is the
    connected component of core points whose lowest index is the k-th smallest, and a border point
    takes the earliest-numbered cluster among its core neighbours.
    """
    if counts is None:
        counts = neighbour_counts(X, eps, chunk)
    core = np.flatnonzero(counts >= min_samples)
    labels = np.full(len(X), -1, np.int64)
    if len(core) == 0:
        return labels
    nn = NearestNeighbors().fit(X[core])

    comp = np.arange(len(core))  # component of each core point; merged chunk by chunk
    for s, nbrs in _neighbours(nn, X[core], eps, chunk):
        rows = np.repeat(np.arange(s, s + len(nbrs)), [len(a) for a in nbrs])
        cols = np.concatenate(nbrs)
        a, b = comp[rows], comp[cols]
        keep = a != b
        if not keep.any():
            continue
        pairs = np.unique(np.stack([a[keep], b[keep]], 1), axis=0)
        g = coo_matrix((np.ones(len(pairs)), (pairs[:, 0], pairs[:, 1])), shape=(len(core), len(core)))
        _, merged = connected_components(g, directed=False)
        comp = merged[comp]

    first = pd.Series(core).groupby(comp).min()  # lowest index in each component
    rank = pd.Series(np.argsort(np.argsort(first.to_numpy())), index=first.index)
    core_label = rank.loc[comp].to_numpy()
    labels[core] = core_label

    border = np.flatnonzero((counts < min_samples) & (counts > 1))
    for s, nbrs in _neighbours(nn, X[border], eps, chunk):
        for i, a in zip(border[s:s + len(nbrs)], nbrs):
            if len(a):
                labels[i] = core_label[a].min()
    return labels


def check_dbscan(X, n=6000, seed=0):
    """Compare dbscan_labels with sklearn on a random subsample, for several settings."""
    idx = np.sort(np.random.default_rng(seed).choice(len(X), n, replace=False))
    Xs = X[idx]
    out = []
    for eps, ms in [(1.5, 20), (2.3, 30), (2.3, 190), (3.0, 60)]:
        ref = DBSCAN(eps=eps, min_samples=ms).fit_predict(Xs)
        ours = dbscan_labels(Xs, eps, ms, chunk=500)
        out.append({'eps': eps, 'min_samples': ms, 'n_clusters': int(ref.max() + 1),
                    'identical': bool(np.array_equal(ref, ours))})
        print('  dbscan check', out[-1], flush=True)
    assert all(o['identical'] for o in out), out
    return out


def dbscan_summary(y, labels):
    return {'ari': ari(y, labels), 'n_clusters': int(labels.max() + 1),
            'noise_fraction': round(float(np.mean(labels == -1)), 4)}


# ---------------------------------------------------------------- K-means / GMM

def kmeans(Xs, k, seed):
    return KMeans(n_clusters=k, random_state=seed).fit_predict(Xs)


def gmm(Xs, k, seed):
    return GaussianMixture(n_components=k, random_state=seed).fit_predict(Xs)


def model_suite(X_full, X_kmeans, labels, seeds):
    """K-means-2, GMM-2 and GMM-4 over seeds, as in the paper's notebooks."""
    Xf, Xk = scale(X_full), scale(X_kmeans)
    out = {}
    for name, fn, Xs, k, target in [('kmeans_2', kmeans, Xk, 2, 'Class'), ('gmm_2', gmm, Xf, 2, 'Class'),
                                    ('gmm_4', gmm, Xf, 4, 'Cat')]:
        scores = [ari(labels[target], fn(Xs, k, s)) for s in seeds]
        out[name] = {'target': target, 'seeds': seeds, 'ari': scores,
                     'mean': round(float(np.mean(scores)), 4), 'min': min(scores), 'max': max(scores)}
        print(f'  {name}: ARI {scores}', flush=True)
    return out


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--check-dbscan', action='store_true', help='verify dbscan_labels against sklearn first')
    ap.add_argument('--no-grid', action='store_true', help='skip the DBSCAN eps/min_samples grid')
    args = ap.parse_args()
    os.makedirs(RESULTS, exist_ok=True)
    t0 = time.time()

    df, X, labels = load()
    y = (labels['Class'] == 'Malware').astype(int).to_numpy()
    Xs = scale(X)
    results = {'data': {'rows': len(X), 'features': X.shape[1],
                        'class_counts': labels['Class'].value_counts().to_dict(),
                        'cat_counts': labels['Cat'].value_counts().to_dict(),
                        'sub_cat_counts': labels['Sub Cat'].value_counts().to_dict()}}

    # Context for the paper's "balanced using the SMOTE algorithm": how many malware rows carry their own
    # dump name. Recorded only; 953 names occur twice, about half of them as exact duplicate rows.
    mal = df[df['Class'] == 'Malware']
    results['smote_check'] = {
        'malware_rows': len(mal),
        'distinct_malware_dump_names': int(mal['Category'].nunique()),
        'duplicate_feature_rows_all': int(X.duplicated().sum()),
    }
    print('SMOTE check:', results['smote_check'], flush=True)

    if args.check_dbscan:
        results['dbscan_equivalence_check'] = check_dbscan(Xs)

    # 1. Replication (paper settings, seed 42)
    print('Replication', flush=True)
    rep = {}
    km = kmeans(scale(X.drop(columns=KMEANS_DROP)), 2, 42)
    g2, g4 = gmm(Xs, 2, 42), gmm(Xs, 4, 42)
    counts_23 = neighbour_counts(Xs, 2.3)
    db = dbscan_labels(Xs, 2.3, 190, counts_23)
    for name, cl, target in [('kmeans_2', km, 'Class'), ('gmm_2', g2, 'Class'), ('gmm_4', g4, 'Cat'),
                             ('dbscan_16', db, 'Sub Cat')]:
        rep[name] = {'target': target, 'paper_ari': PAPER[name], 'ari': ari(labels[target], cl),
                     'n_clusters': int(cl.max() + 1), 'noise_points': int(np.sum(cl == -1)),
                     'confusion_matrix': pd.crosstab(labels[target], cl).rename(columns=str).to_dict(orient='index')}
        print(f'  {name}: ARI {rep[name]["ari"]} (paper {PAPER[name]}), {rep[name]["n_clusters"]} clusters',
              flush=True)
    results['replication'] = rep

    # 2. Seed stability
    print('Seeds', flush=True)
    results['seeds'] = model_suite(X, X.drop(columns=KMEANS_DROP), labels, SEEDS)

    # 3. Reference points: how much of each ARI a benign-vs-malware split already explains
    stump_split = (X[SHORTCUT] < X.loc[labels['Class'] == 'Malware', SHORTCUT].min()).astype(int)
    one = scale(X[[SHORTCUT]])
    km1, g1 = kmeans(one, 2, 42), gmm(one, 2, 42)
    results['reference'] = {
        'perfect_binary_split_vs_cat': ari(labels['Cat'], y),
        'perfect_binary_split_vs_sub_cat': ari(labels['Sub Cat'], y),
        f'kmeans_2_on_{SHORTCUT}_only': ari(y, km1),
        f'gmm_2_on_{SHORTCUT}_only': ari(y, g1),
        f'gmm_2_paper_vs_gmm_2_on_{SHORTCUT}_only': ari(g1, g2),
        f'kmeans_2_paper_vs_kmeans_2_on_{SHORTCUT}_only': ari(km1, km),
        'gmm_4_paper_vs_true_class': ari(y, g4),
        'dbscan_paper_vs_true_class': ari(y, db),
    }
    print('Reference:', results['reference'], flush=True)

    # 4. Without the svcscan plugin
    print('Without svcscan', flush=True)
    svc = [c for c in X.columns if c.startswith('svcscan.')]
    Xn = X.drop(columns=svc)
    no_svc = model_suite(Xn, Xn.drop(columns=[c for c in KMEANS_DROP if c in Xn.columns]), labels, SEEDS)
    Xns = scale(Xn)
    no_svc['dbscan_16'] = dbscan_summary(labels['Sub Cat'], dbscan_labels(Xns, 2.3, 190))
    print('  dbscan_16:', no_svc['dbscan_16'], flush=True)
    results['no_svcscan'] = {'dropped': svc, **no_svc}

    # 5. Without duplicate rows
    print('Without duplicates', flush=True)
    keep = ~X.duplicated().to_numpy()
    Xd, ld = X[keep].reset_index(drop=True), labels[keep].reset_index(drop=True)
    dedup = model_suite(Xd, Xd.drop(columns=KMEANS_DROP), ld, SEEDS)
    dedup['dbscan_16'] = dbscan_summary(ld['Sub Cat'], dbscan_labels(scale(Xd), 2.3, 190))
    print('  dbscan_16:', dedup['dbscan_16'], flush=True)
    results['deduplicated'] = {'rows': int(keep.sum()), **dedup}

    # 6. DBSCAN sensitivity
    if not args.no_grid:
        print('DBSCAN grid', flush=True)
        grid = []
        for eps in GRID_EPS:
            counts = counts_23 if eps == 2.3 else neighbour_counts(Xs, eps)
            for ms in GRID_MIN_SAMPLES:
                lab = dbscan_labels(Xs, eps, ms, counts)
                grid.append({'eps': eps, 'min_samples': ms, **dbscan_summary(labels['Sub Cat'], lab),
                             'ari_vs_class': ari(y, lab)})
                print('  ', grid[-1], flush=True)
        results['dbscan_grid'] = grid

    results['seconds'] = round(time.time() - t0, 1)
    with open(os.path.join(RESULTS, 'malmem.json'), 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f'saved results/clustering/malmem.json ({results["seconds"]} s)', flush=True)


if __name__ == '__main__':
    main()
