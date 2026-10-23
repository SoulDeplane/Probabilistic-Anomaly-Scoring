"""Duplicate audit of Dumpware10 (Bozkir et al., Computers & Security 2021), 224x224 rendering.

  * exact copies: distinct SHA-256 per class (Datasets/inventory/dumpware10_files.csv), and identical files
    under two classes or on both sides of the official TRAINING / TEST split
  * near-copies: average hashes (A-Hash: grayscale, resize to 16x16 or 8x8, threshold at the mean), distinct
    hashes per class
  * near-twin leakage: Hamming distance from every test image to its nearest training image (256-bit A-Hash);
    share of test images with an identical hash and within 5 of 256 bits, per class
  * a rule with no learning at all: give each test image the class of its nearest training image by A-Hash
    distance (1-NN); its accuracy is the floor a published classifier has to beat

Usage: python src/audit_dumpware10.py
"""
import json
import os

import numpy as np
import pandas as pd
from PIL import Image

from replicate_khalid import ROOT

DATASETS = os.path.join(ROOT, '..', 'Datasets')
OUT = os.path.join(ROOT, 'results', 'audit')
NEAR = 5  # bits out of 256


def ahash(path, n):
    img = Image.open(os.path.join(DATASETS, path)).convert('L').resize((n, n), Image.BILINEAR)
    a = np.asarray(img, dtype=np.float32)
    return (a >= a.mean()).ravel()


def main():
    inv = pd.read_csv(os.path.join(DATASETS, 'inventory', 'dumpware10_files.csv'))
    v = inv[inv['variant'] == '224/224'].reset_index(drop=True)
    H16 = np.stack([ahash(p, 16) for p in v['path']])
    H8 = np.stack([ahash(p, 8) for p in v['path']])
    key = lambda H: [h.tobytes() for h in H]
    v['a16'], v['a8'] = key(H16), key(H8)

    per_class = v.groupby('class').agg(images=('path', 'size'), distinct_files=('sha256', 'nunique'),
                                       distinct_ahash_16x16=('a16', 'nunique'), distinct_ahash_8x8=('a8', 'nunique'))
    a = {'images': len(v), 'distinct_files': int(v['sha256'].nunique()),
         'distinct_ahash_16x16': int(v['a16'].nunique()), 'distinct_ahash_8x8': int(v['a8'].nunique()),
         'per_class': per_class.to_dict(orient='index'),
         'identical_files_under_two_classes': int((v.groupby('sha256')['class'].nunique() > 1).sum()),
         'identical_files_in_training_and_test': int((v.groupby('sha256')['split'].nunique() > 1).sum())}

    tr, te = np.flatnonzero(v['split'] == 'TRAINING'), np.flatnonzero(v['split'] == 'TEST')
    D = (H16[te][:, None, :] != H16[tr][None, :, :]).sum(2)
    t = v.iloc[te].assign(dmin=D.min(1), nn_class=v['class'].to_numpy()[tr[D.argmin(1)]])
    t['hit'] = t['nn_class'] == t['class']
    near = t.groupby('class').agg(test_images=('dmin', 'size'), identical_hash_in_training=('dmin', lambda s: (s == 0).mean()),
                                  within_5_bits_of_training=('dmin', lambda s: (s <= NEAR).mean()),
                                  nearest_training_image_same_class=('hit', 'mean'))
    a['near_twins'] = {'test_images': len(t), 'identical_hash_in_training': float((t['dmin'] == 0).mean()),
                       'within_5_bits_of_training': float((t['dmin'] <= NEAR).mean()),
                       'per_class': near.round(3).to_dict(orient='index')}
    a['no_learning_1nn_ahash_accuracy'] = float(t['hit'].mean())
    a['majority_class_accuracy_on_test'] = float(t['class'].value_counts(normalize=True).iloc[0])

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, 'dumpware10.json'), 'w') as f:
        json.dump(a, f, indent=2)
    print(json.dumps({k: v for k, v in a.items() if k != 'per_class'}, indent=2))


if __name__ == '__main__':
    main()
