"""Faithful replication of Khalid, Iqbal & Saqib (2025), FSI: Digital Investigation 53, 301924.

Mirrors the authors' published Colab notebooks (github.com/znbkhld/Unupervised-XAI-DF):
  * data: official Obfuscated-MalMem2022.csv, all 29,298 benign rows + the initial 5% (1,465)
    malicious rows in file order -> 30,763 rows; 'Category' dropped, 'Class' kept for evaluation.
  * no feature scaling (the StandardScaler lines are commented out in the AE notebook).
  * Isolation Forest: n_estimators=100, max_samples='auto', max_features=55,
    contamination='auto', random_state=42, fit_predict on all rows.
  * Autoencoder: 55-64-32-64-55 (ReLU, linear output), Adam, MSE, epochs=50, batch_size=32,
    validation_split=0.1, trained on benign rows only, tested on all rows,
    threshold = mean + 3*std of training reconstruction error.
  * seeds: np.random.seed(1), tf.random.set_seed(42).

Paper-reported targets: IF accuracy 0.8595; AE accuracy 0.9759 (notebook: 0.97598,
precision 0.6682, recall 0.9843, F1 0.7960).

Usage: python src/replicate_khalid.py [--ae-seeds 42 1 2 3 4]
"""
import argparse
import json
import math
import os
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, '..', 'Datasets', 'cicmalmem22', 'CSV', 'Obfuscated-MalMem2022.csv')
RESULTS = os.path.join(ROOT, 'results', 'replication')


def load_paper_subset():
    df = pd.read_csv(DATA)
    benign = df[df['Class'] == 'Benign']
    malware = df[df['Class'] == 'Malware']
    n_mal = math.ceil(0.05 * len(malware))  # 1,465 rows, as in the authors' data.csv
    data = pd.concat([benign, malware.iloc[:n_mal]]).drop(columns=['Category']).reset_index(drop=True)
    assert data.shape == (30763, 56), data.shape
    return data


def metrics(y_true, y_pred):
    return {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision': precision_score(y_true, y_pred),
        'recall': recall_score(y_true, y_pred),
        'f1': f1_score(y_true, y_pred),
        'confusion_matrix': confusion_matrix(y_true, y_pred).tolist(),
    }


def run_isolation_forest(data):
    X = data.drop(columns=['Class'])
    y_true = (data['Class'] == 'Malware').astype(int)
    iso = IsolationForest(n_estimators=100, max_samples='auto', max_features=55,
                          contamination='auto', random_state=42)
    y_pred = (iso.fit_predict(X) == -1).astype(int)
    return metrics(y_true, y_pred)


def run_autoencoder(data, tf_seed):
    labels = data['Class']
    X = data.drop(columns=['Class'])  # unscaled, as in the authors' notebook
    y_test = (labels == 'Malware').astype(int).to_numpy()  # LabelEncoder: Benign=0, Malware=1
    return train_paper_autoencoder(X[labels == 'Benign'], X, y_test, tf_seed)


def fit_paper_autoencoder(X_train, tf_seed, verbose=2):
    """The authors' architecture and training settings; returns (model, history, seconds)."""
    import tensorflow as tf

    np.random.seed(1)
    tf.random.set_seed(tf_seed)

    input_dim = X_train.shape[1]
    autoencoder = tf.keras.models.Sequential([
        tf.keras.layers.Input(shape=(input_dim,)),
        tf.keras.layers.Dense(64, activation='relu'),
        tf.keras.layers.Dense(32, activation='relu'),
        tf.keras.layers.Dense(64, activation='relu'),
        tf.keras.layers.Dense(input_dim, activation='linear'),
    ])
    autoencoder.compile(optimizer='adam', loss='mse')
    t0 = time.time()
    history = autoencoder.fit(X_train, X_train, epochs=50, batch_size=32, validation_split=0.1, verbose=verbose)
    return autoencoder, history, time.time() - t0


def reconstruction_mse(model, X):
    return np.mean(np.square(X - model.predict(X, verbose=0)), axis=1)


def train_paper_autoencoder(X_train, X_test, y_test, tf_seed, verbose=2):
    """The authors' autoencoder: trained on benign rows only, evaluated on all rows."""
    autoencoder, history, train_seconds = fit_paper_autoencoder(X_train, tf_seed, verbose)

    mse = reconstruction_mse(autoencoder, X_test)
    train_mse = reconstruction_mse(autoencoder, X_train)
    threshold = float(np.mean(train_mse) + 3 * np.std(train_mse))
    y_pred = (mse > threshold).astype(int)

    out = metrics(y_test, y_pred)
    out.update({'tf_seed': tf_seed, 'threshold': threshold, 'train_seconds': round(train_seconds, 1),
                'final_loss': history.history['loss'][-1], 'final_val_loss': history.history['val_loss'][-1]})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ae-seeds', type=int, nargs='+', default=[42])
    args = ap.parse_args()
    os.makedirs(RESULTS, exist_ok=True)

    data = load_paper_subset()
    print(f'data: {data.shape[0]:,} rows ({(data.Class == "Benign").sum():,} benign, '
          f'{(data.Class == "Malware").sum():,} malware)', flush=True)

    results = {'isolation_forest': run_isolation_forest(data), 'autoencoder': []}
    print('Isolation Forest:', json.dumps(results['isolation_forest']), flush=True)
    for seed in args.ae_seeds:
        r = run_autoencoder(data, seed)
        results['autoencoder'].append(r)
        print(f'Autoencoder (tf seed {seed}):', json.dumps(r), flush=True)

    with open(os.path.join(RESULTS, 'results.json'), 'w') as f:
        json.dump(results, f, indent=2)


if __name__ == '__main__':
    main()
