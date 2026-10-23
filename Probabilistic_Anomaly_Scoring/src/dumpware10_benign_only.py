"""Dumpware10 decision test: can any detector trained on benign images only separate malware from benign?

Representations: ImageNet EfficientNetV2-B0 features (transfer learning, 224x224 rendering) and raw 64x64
grayscale pixels. Detectors fitted on benign images only: 5-NN distance, and Mahalanobis distance (Ledoit-Wolf)
on 50 principal components. The 608 benign images are split 5-fold; every fold scores its held-out benign
images and all 3,686 malware images, with thresholds at the 99th / 95th percentile of the held-out benign
scores. A supervised logistic regression (5-fold CV) gives the upper bound on separability.

The EfficientNet features are cached in cache/ (git-ignored) after the first run.

Usage: python src/dumpware10_benign_only.py
"""
import json
import os
import time

import numpy as np
import pandas as pd
from PIL import Image
from sklearn.covariance import LedoitWolf
from sklearn.decomposition import PCA
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import KFold, cross_val_predict
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler, normalize

from replicate_khalid import ROOT

DATASETS = os.path.join(ROOT, '..', 'Datasets')
CACHE = os.path.join(ROOT, 'cache')
OUT = os.path.join(ROOT, 'results', 'dumpware10')


def efficientnet_features(paths):
    cached = os.path.join(CACHE, 'dumpware10_effnetv2b0_224.npy')
    if os.path.exists(cached):
        return np.load(cached)
    import keras

    model = keras.applications.EfficientNetV2B0(include_top=False, weights='imagenet', pooling='avg',
                                                input_shape=(224, 224, 3))
    t0, parts = time.time(), []
    for i in range(0, len(paths), 64):
        batch = np.stack([np.asarray(Image.open(os.path.join(DATASETS, p)).convert('RGB'), dtype=np.float32)
                          for p in paths[i:i + 64]])
        parts.append(model.predict(batch, verbose=0))
    F = np.concatenate(parts)
    os.makedirs(CACHE, exist_ok=True)
    np.save(cached, F)
    print(f'EfficientNet features {F.shape} in {time.time() - t0:.0f}s', flush=True)
    return F


def knn_score(Xtr, Xte):
    return NearestNeighbors(n_neighbors=5).fit(Xtr).kneighbors(Xte)[0].mean(1)


def maha_score(Xtr, Xte):
    pca = PCA(50, random_state=0).fit(Xtr)
    return LedoitWolf().fit(pca.transform(Xtr)).mahalanobis(pca.transform(Xte))


def main():
    inv = pd.read_csv(os.path.join(DATASETS, 'inventory', 'dumpware10_files.csv'))
    v = inv[inv['variant'] == '224/224'].reset_index(drop=True)
    is_mal = (v['class'] != 'Other').to_numpy()
    fam = v['class'].to_numpy()
    reps = {'EfficientNetV2 features': efficientnet_features(list(v['path'])),
            'raw 64x64 pixels': np.stack([np.asarray(Image.open(os.path.join(DATASETS, p)).convert('L').resize(
                (64, 64), Image.BILINEAR), dtype=np.float32).ravel() for p in v['path']])}

    rows, families = [], {}
    for rep, X in reps.items():
        B, M = X[~is_mal], X[is_mal]
        for det, fn in (('5-NN distance', knn_score), ('Mahalanobis', maha_score)):
            aucs, c1, c5, hits = [], [], [], {}
            for tr, te in KFold(5, shuffle=True, random_state=0).split(B):
                sc = StandardScaler().fit(B[tr])
                prep = (lambda Z: normalize(sc.transform(Z))) if rep.startswith('Eff') else sc.transform
                sb, sm = fn(prep(B[tr]), prep(B[te])), fn(prep(B[tr]), prep(M))
                aucs.append(roc_auc_score(np.r_[np.zeros(len(sb)), np.ones(len(sm))], np.r_[sb, sm]))
                c1.append((sm > np.quantile(sb, 0.99)).mean())
                c5.append((sm > np.quantile(sb, 0.95)).mean())
                for f in np.unique(fam[is_mal]):
                    hits.setdefault(f, []).append((sm[fam[is_mal] == f] > np.quantile(sb, 0.95)).mean())
            rows.append({'representation': rep, 'detector': det, 'roc_auc': float(np.mean(aucs)),
                         'malware_caught_at_1pct_false_alarms': float(np.mean(c1)),
                         'malware_caught_at_5pct_false_alarms': float(np.mean(c5))})
            families[f'{rep} / {det}'] = {f: round(float(np.mean(h)), 3) for f, h in hits.items()}

    for rep, X in reps.items():  # supervised upper bound: a classifier that sees malware labels
        p = cross_val_predict(LogisticRegression(max_iter=3000, C=0.1), StandardScaler().fit_transform(X),
                              is_mal.astype(int), cv=KFold(5, shuffle=True, random_state=0), method='predict_proba')[:, 1]
        rows.append({'representation': rep, 'detector': 'supervised logistic regression (upper bound)',
                     'roc_auc': float(roc_auc_score(is_mal, p))})

    print(pd.DataFrame(rows).round(3).to_string(index=False))
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, 'benign_only.json'), 'w') as f:
        json.dump({'results': rows, 'recall_by_family_at_5pct_false_alarms': families}, f, indent=2)


if __name__ == '__main__':
    main()
