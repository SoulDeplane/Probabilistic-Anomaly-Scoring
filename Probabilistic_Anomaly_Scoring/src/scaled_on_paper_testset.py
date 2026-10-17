"""Scaled-feature autoencoder on the base paper's exact MalMem test set (apples-to-apples).

Identical to src/replicate_khalid.py (same 30,763 rows, model, training, benign-only fit,
test-on-all) except: StandardScaler fitted on the benign training rows, and thresholds at
mean + 3*std (paper) and at the 99th / 95th percentile of benign training error (1% / 5%
false-alarm budget).

Usage: python src/scaled_on_paper_testset.py [--seeds 42 1 2]
"""
import argparse
import json
import os

import numpy as np
from sklearn.preprocessing import StandardScaler

from replicate_khalid import RESULTS, fit_paper_autoencoder, load_paper_subset, metrics, reconstruction_mse


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--seeds', type=int, nargs='+', default=[42, 1, 2])
    args = ap.parse_args()

    data = load_paper_subset()
    X = data.drop(columns=['Class']).to_numpy(np.float32)
    y = (data['Class'] == 'Malware').astype(int).to_numpy()
    benign = X[y == 0]
    scaler = StandardScaler().fit(benign)
    Xs, bs = scaler.transform(X).astype(np.float32), scaler.transform(benign).astype(np.float32)

    results = {}
    for seed in args.seeds:
        model, _, _ = fit_paper_autoencoder(bs, seed, verbose=0)
        err, err_train = reconstruction_mse(model, Xs), reconstruction_mse(model, bs)
        thresholds = {'mean_plus_3std': float(np.mean(err_train) + 3 * np.std(err_train)),
                      'fp_budget_1pct': float(np.percentile(err_train, 99)),
                      'fp_budget_5pct': float(np.percentile(err_train, 95))}
        results[seed] = {name: metrics(y, (err > t).astype(int)) for name, t in thresholds.items()}
        for name, r in results[seed].items():
            print(f'seed {seed} {name}: {json.dumps(r)}', flush=True)

    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, 'scaled_paper_testset.json'), 'w') as f:
        json.dump(results, f, indent=2)


if __name__ == '__main__':
    main()
