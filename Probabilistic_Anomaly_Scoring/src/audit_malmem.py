"""Audit of CIC MalMemAnalysis-2022 (Carrier et al., ICISSP 2022) before any model is trained.

Mirrors src/audit_bodmas.py:
  * integrity: rows, classes, families, malware binaries (the SHA-256 inside each 'Category' file name) and
    dumps per binary
  * duplicates: exact duplicate records (all columns, file name included) and duplicate feature vectors
  * the base paper's test set: which families the first 5% of malware rows (file order) come from
  * signs of synthetic balancing: SMOTE interpolates between rows, so unrounded synthetic rows would carry
    fractional values in features that are whole-number counts in every real malware dump
  * feature scale, constant features and non-finite values
  * trivial baselines: majority class and the single-feature decision stump of every feature (full ranking,
    for comparison with any later feature attribution), on all rows and on the base paper's 30,763 rows

Usage: python src/audit_malmem.py
"""
import json
import os

import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier

from replicate_khalid import DATA, ROOT, load_paper_subset

OUT = os.path.join(ROOT, 'results', 'audit')


def stump(x, y):
    s = DecisionTreeClassifier(max_depth=1).fit(x.to_numpy().reshape(-1, 1), y)
    t = s.tree_
    side = '>' if s.classes_[t.value[t.children_right[0]].argmax()] == 1 else '<='
    return {'accuracy': round(float(s.score(x.to_numpy().reshape(-1, 1), y)), 4),
            'rule': f'malware if {x.name} {side} {t.threshold[0]:g}'}


def main():
    df = pd.read_csv(DATA)
    feats = [c for c in df.columns if c not in ('Category', 'Class')]
    X, y = df[feats], (df['Class'] == 'Malware').to_numpy(int)
    mal = df[y == 1]
    parts = mal['Category'].str.split('-')
    family, sha = parts.str[:2].str.join('-'), parts.str[2]
    a = {'shape': list(df.shape), 'class_counts': df['Class'].value_counts().to_dict(),
         'families': family.value_counts().to_dict()}

    per_binary = sha.value_counts()
    a['malware_binaries'] = {
        'count': int(len(per_binary)),
        'binaries_by_dumps': per_binary.value_counts().sort_index().to_dict(),
        'binaries_listed_under_two_families': int((family.groupby(sha).nunique() > 1).sum()),
    }

    # duplicates
    vec = df.duplicated(subset=feats + ['Class'])
    groups = pd.util.hash_pandas_object(X, index=False)
    spans = mal.assign(g=groups[y == 1], sha=sha).groupby('g')['sha'].nunique()
    a['duplicates'] = {
        'exact_duplicate_records_all_columns': int(df.duplicated().sum()),
        'duplicate_feature_vectors_beyond_first': int(vec.sum()),
        'by_class': df.loc[vec, 'Class'].value_counts().to_dict(),
        'feature_vectors_labelled_both_classes': int((df.groupby(groups)['Class'].nunique() > 1).sum()),
        'malware_vectors_shared_by_different_binaries': int((spans > 1).sum()),
    }

    paper = mal.iloc[:1465]
    a['paper_test_malware'] = {'rows': len(paper), 'families': family.iloc[:1465].value_counts().to_dict(),
                               'binaries': int(sha.iloc[:1465].nunique())}

    # SMOTE check: features that are whole numbers in every malware dump
    whole = [c for c in feats if (np.mod(mal[c], 1) == 0).all()]
    frac = lambda d: int((np.mod(d[whole], 1) != 0).any(axis=1).sum())
    a['synthetic_balancing_check'] = {
        'whole_number_features': len(whole),
        'benign_rows_with_a_fractional_value_in_them': frac(df[y == 0]),
        'malware_rows_with_a_fractional_value_in_them': frac(mal),
    }
    a['svcscan.nservices_values'] = {c: df.loc[df['Class'] == c, 'svcscan.nservices'].value_counts().to_dict()
                                     for c in ('Benign', 'Malware')}

    # data quality and scale
    a['non_finite_values'] = int((~np.isfinite(X.to_numpy(float))).sum())
    a['constant_features'] = [c for c in feats if X[c].nunique() == 1]
    mx = X.abs().max()
    a['largest_feature_values'] = mx.sort_values(ascending=False).head(5).to_dict()

    # trivial baselines
    a['majority_class_accuracy'] = float(max(y.mean(), 1 - y.mean()))
    ranking = sorted(((c, stump(X[c], y)) for c in feats if c not in a['constant_features']),
                     key=lambda kv: -kv[1]['accuracy'])
    a['single_feature_stumps'] = dict(ranking)
    a['best_stump_per_plugin'] = {}
    for c, r in ranking:
        a['best_stump_per_plugin'].setdefault(c.split('.')[0], {'feature': c, **r})
    sub = load_paper_subset()
    ys = (sub['Class'] == 'Malware').to_numpy(int)
    a['paper_subset'] = {'majority_class_accuracy': float(1 - ys.mean()),
                         'best_stump': stump(sub[ranking[0][0]], ys) | {'feature': ranking[0][0]}}

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, 'malmem.json'), 'w') as f:
        json.dump(a, f, indent=2, default=str)
    print(json.dumps({k: v for k, v in a.items() if k != 'single_feature_stumps'}, indent=2, default=str))


if __name__ == '__main__':
    main()
