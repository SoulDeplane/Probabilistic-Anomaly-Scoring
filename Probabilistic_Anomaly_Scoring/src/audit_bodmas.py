"""Audit of BODMAS (Yang et al., DLS 2021) before any model is trained.

Mirrors the audits of the other datasets (Datasets/README.md):
  * integrity: feature file, labels, metadata and category file agree row for row; counts match the paper
  * non-finite values, constant features, exact-duplicate feature vectors (within and across classes)
  * first-seen time span of each class, malware family and category composition
  * feature scale (the features are unnormalised)
  * trivial baselines: majority class and the best single-feature decision stump

Usage: python src/audit_bodmas.py
"""
import json
import os

import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier

from replicate_khalid import ROOT

DATA = os.path.join(ROOT, '..', 'Datasets', 'bodmas')
OUT = os.path.join(ROOT, 'results', 'audit')

# EMBER feature layout (LIEF 0.9.0) used by BODMAS: 2,381 columns in this order
GROUPS = [('byte_histogram', 256), ('byte_entropy_histogram', 256), ('strings', 104), ('general', 10),
          ('header', 62), ('section', 255), ('imports', 1280), ('exports', 128), ('data_directories', 30)]
NAMED = {
    'strings': {0: 'numstrings', 1: 'avlength', 2: 'printables', 99: 'entropy', 100: 'paths', 101: 'urls',
                102: 'registry', 103: 'MZ'},
    'general': dict(enumerate(['size', 'vsize', 'has_debug', 'exports', 'imports', 'has_relocations',
                               'has_resources', 'has_signature', 'has_tls', 'symbols'])),
    'header': {0: 'coff_timestamp', **dict(zip(range(51, 62), [
        'major_image_version', 'minor_image_version', 'major_linker_version', 'minor_linker_version',
        'major_operating_system_version', 'minor_operating_system_version', 'major_subsystem_version',
        'minor_subsystem_version', 'sizeof_code', 'sizeof_headers', 'sizeof_heap_commit']))},
}


def feature_names():
    names = [f'{g}.{NAMED.get(g, {}).get(i, i)}' for g, n in GROUPS for i in range(n)]
    assert len(names) == 2381
    return names


def load():
    z = np.load(os.path.join(DATA, 'bodmas.npz'), allow_pickle=False)
    meta = pd.read_csv(os.path.join(DATA, 'bodmas_metadata.csv'))
    cat = pd.read_csv(os.path.join(DATA, 'bodmas_malware_category.csv'))
    return z['X'], z['y'], meta, cat


def main():
    X, y, meta, cat = load()
    names = feature_names()
    col = {n: i for i, n in enumerate(names)}
    a = {'timestamps_without_timezone': int((~meta['timestamp'].str.contains(r'[+-]\d\d:\d\d$')).sum())}
    meta['timestamp'] = pd.to_datetime(meta['timestamp'], utc=True, format='ISO8601')  # tz-less ones taken as UTC

    # integrity
    a['shape'] = list(X.shape)
    a['class_counts'] = {'benign': int((y == 0).sum()), 'malware': int((y == 1).sum())}
    a['matches_paper'] = bool(X.shape == (134435, 2381) and (y == 0).sum() == 77142 and (y == 1).sum() == 57293)
    a['label_matches_metadata_family'] = bool(((y == 1) == meta['family'].notna().to_numpy()).all())
    a['category_file_matches_malware'] = bool(set(cat['sha256']) == set(meta.loc[y == 1, 'sha']))
    a['unique_sha256'] = int(meta['sha'].nunique())
    a['metadata_sorted_by_time'] = bool(meta['timestamp'].is_monotonic_increasing)

    # layout sanity checks for the named EMBER features
    bh = X[:, :256].sum(1)
    a['layout_checks'] = {
        'byte_histogram_rows_sum_to_1': float(np.mean(np.abs(bh - 1) < 1e-3)),
        'general_flags_binary': bool(np.isin(X[:, [col['general.has_debug'], col['general.has_signature'],
                                                   col['general.has_tls']]], [0, 1]).all()),
        'coff_timestamp_median_as_date': str(pd.to_datetime(float(np.median(X[:, col['header.coff_timestamp']])),
                                                             unit='s').date()),
    }

    # data quality
    a['non_finite_values'] = int((~np.isfinite(X)).sum())
    a['constant_features'] = int((X.min(0) == X.max(0)).sum())
    rows = np.ascontiguousarray(X).view(np.dtype((np.void, X.dtype.itemsize * X.shape[1]))).ravel()
    _, inverse, counts = np.unique(rows, return_inverse=True, return_counts=True)
    dup = counts[inverse] > 1
    first = np.zeros(len(rows), bool)
    first[np.unique(inverse, return_index=True)[1]] = True
    mixed = pd.Series(y).groupby(inverse).nunique()
    a['duplicates'] = {
        'rows_beyond_first_copy': int((~first).sum()),
        'benign_rows_beyond_first_copy': int((~first & (y == 0)).sum()),
        'malware_rows_beyond_first_copy': int((~first & (y == 1)).sum()),
        'feature_vectors_labelled_both_benign_and_malware': int((mixed > 1).sum()),
        'rows_in_any_duplicate_group': int(dup.sum()),
    }

    # time, families, categories
    a['first_seen'] = {c: [str(meta.loc[y == k, 'timestamp'].min()), str(meta.loc[y == k, 'timestamp'].max())]
                       for c, k in [('benign', 0), ('malware', 1)]}
    a['benign_first_seen_by_year'] = meta.loc[y == 0, 'timestamp'].dt.year.value_counts().sort_index().to_dict()
    a['malware_first_seen_by_month'] = (meta.loc[y == 1, 'timestamp'].dt.strftime('%Y-%m')
                                        .value_counts().sort_index().to_dict())
    fam = meta.loc[y == 1, 'family'].value_counts()
    a['families'] = {'count': int(len(fam)), 'count_ignoring_case': int(fam.index.str.lower().nunique()),
                     'unknown_family_labels': int(fam[fam.index.str.lower() == 'unknown'].sum()),
                     'top10': fam.head(10).to_dict(),
                     'singletons': int((fam == 1).sum()), 'with_at_least_100_samples': int((fam >= 100).sum())}
    a['categories'] = cat['category'].value_counts().to_dict()

    # feature scale (unnormalised)
    mx = np.abs(X).max(0)
    a['feature_scale'] = {'features_with_max_above_1e6': int((mx > 1e6).sum()),
                          'largest': {names[i]: float(mx[i]) for i in np.argsort(-mx)[:10]}}

    # trivial baselines on the full dataset
    a['majority_class_accuracy'] = float(max((y == 0).mean(), (y == 1).mean()))
    acc = np.zeros(X.shape[1])
    for j in range(X.shape[1]):
        if mx[j] == 0 or X[:, j].min() == X[:, j].max():
            continue
        stump = DecisionTreeClassifier(max_depth=1).fit(X[:, [j]], y)
        acc[j] = stump.score(X[:, [j]], y)
    best = np.argsort(-acc)[:10]
    a['best_single_feature_stumps'] = {names[j]: round(float(acc[j]), 4) for j in best}
    group_of = np.repeat([g for g, _ in GROUPS], [n for _, n in GROUPS])
    a['best_stump_per_group'] = {g: round(float(acc[group_of == g].max()), 4) for g, _ in GROUPS}

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, 'bodmas.json'), 'w') as f:
        json.dump(a, f, indent=2, default=str)
    print(json.dumps(a, indent=2, default=str))


if __name__ == '__main__':
    main()
