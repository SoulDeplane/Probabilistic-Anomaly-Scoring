"""Held-out evaluation protocol shared by the newer experiments (study guide, section 5, steps 1-3).

  split      duplicate feature vectors dropped; clean rows split 60/20/20 into train / cal(ibrate) / test with
             a fixed seed, so every model (including the VAE still to come) sees identical partitions; malware
             split 50/50 into 'fit' (used only by the supervised stump baseline) and 'test'. On MalMem the
             malware split is grouped by the sample's SHA-256, so all dumps of one binary fall on one side.
  scaling    StandardScaler fitted on the clean training rows only
  conformal  p = (1 + #calibration scores >= s) / (n + 1); an artefact is flagged when p <= alpha, which keeps
             the false-alarm rate on unseen clean data at or below alpha
  metrics    false-alarm rate and recall at the flag line, ROC-AUC, and precision, F1, accuracy and PR-AUC at
             the base paper's 20:1 clean:malware ratio: each test malware row is weighted so malware carries
             1/21 of the test weight (recall, false-alarm rate and ROC-AUC do not depend on the ratio)
  baselines  majority class ('always clean') and the best single-feature decision stump, fitted on the clean
             training rows plus the malware 'fit' rows
"""
import glob
import os
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, balanced_accuracy_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.tree import DecisionTreeClassifier

from replicate_khalid import ROOT, fit_paper_autoencoder, reconstruction_mse

DATASETS = os.path.join(ROOT, '..', 'Datasets')
SPLIT_SEED = 0
RATIO = 20                      # clean rows per malware row in the base paper's test set
CICIOT_N_BENIGN = 100_000       # clean flows sampled from the 1.1 M in Benign_Final
BODMAS_CUTOFF = '2020-03-01'    # temporal split: train on files first seen before this date
DROP_GROUPS = {
    'svcscan': lambda f: [c for c in f if c.startswith('svcscan.')],
    'window': lambda f: [c for c in f if c in ('Number', 'Tot sum', 'IAT', 'Variance', 'Rate')],
}


@dataclass
class Dataset:
    name: str
    X: np.ndarray          # float32, duplicate feature vectors removed
    y: np.ndarray          # 0 clean, 1 malware
    part: np.ndarray       # clean: train / cal / test; malware: fit / test
    family: np.ndarray     # malware family, attack class or category; 'Benign' for clean rows
    features: list
    row_id: np.ndarray     # where the row came from in the source file(s)
    info: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)

    def drop(self, group):
        cols = DROP_GROUPS[group](self.features)
        keep = [i for i, c in enumerate(self.features) if c not in cols]
        self.X, self.features = self.X[:, keep], [self.features[i] for i in keep]
        self.info['dropped_features'] = cols


def split_clean(n, rng):
    part = np.empty(n, dtype='<U5')
    perm = rng.permutation(n)
    part[perm[:int(0.6 * n)]] = 'train'
    part[perm[int(0.6 * n):int(0.8 * n)]] = 'cal'
    part[perm[int(0.8 * n):]] = 'test'
    return part


def split_malware(n, rng, groups=None):
    part = np.full(n, 'fit', dtype='<U5')
    if groups is None:
        part[rng.permutation(n)[n // 2:]] = 'test'
    else:
        _, test = next(GroupShuffleSplit(1, test_size=0.5, random_state=SPLIT_SEED).split(np.zeros(n), groups=groups))
        part[test] = 'test'
    return part


def assemble(name, X, y, family, features, row_id, groups=None, **info):
    rng = np.random.default_rng(SPLIT_SEED)
    part = np.empty(len(y), dtype='<U8')
    part[y == 0] = split_clean(int((y == 0).sum()), rng)
    part[y == 1] = split_malware(int((y == 1).sum()), rng, None if groups is None else groups[y == 1])
    info.update({'features': len(features), 'clean_rows': int((y == 0).sum()), 'malware_rows': int((y == 1).sum())})
    info.update(partition_counts(y, part))
    return Dataset(name, X.astype(np.float32, copy=False), y, part, np.asarray(family, dtype=object),
                   list(features), np.asarray(row_id), info)


def partition_counts(y, part):
    return {f'{k}_{p}': int(((y == v) & (part == p)).sum())
            for k, v in (('clean', 0), ('malware', 1)) for p in np.unique(part[y == v])}


def first_occurrence(X):
    """Mask keeping the first copy of every distinct row of a numeric array."""
    rows = np.ascontiguousarray(X).view(np.dtype((np.void, X.dtype.itemsize * X.shape[1]))).ravel()
    keep = np.zeros(len(rows), bool)
    keep[np.unique(rows, return_index=True)[1]] = True
    return keep


def load_malmem():
    df = pd.read_csv(os.path.join(DATASETS, 'cicmalmem22', 'CSV', 'Obfuscated-MalMem2022.csv'))
    feats = [c for c in df.columns if c not in ('Category', 'Class')]
    paper_test = np.zeros(len(df), bool)  # the base paper's 1,465 test malware: first 5% of malware rows
    paper_test[np.flatnonzero(df['Class'] == 'Malware')[:1465]] = True
    keep = ~df.duplicated(subset=feats + ['Class']).to_numpy()
    df, paper_test = df[keep], paper_test[keep]
    y = (df['Class'] == 'Malware').to_numpy(int)
    parts = df['Category'].str.split('-')
    family = np.where(y == 1, parts.str[:2].str.join('-'), 'Benign')
    groups = np.where(y == 1, parts.str[2], df.index.astype(str))  # SHA-256 of the binary; clean rows alone
    ds = assemble('malmem', df[feats].to_numpy(np.float32), y, family, feats, df.index.to_numpy(), groups,
                  duplicates_dropped=int((~keep).sum()), malware_binaries=int(pd.Series(groups[y == 1]).nunique()))
    ds.extra.update({'paper_test': paper_test, 'groups': groups})
    return ds


def load_ciciot23():
    base = os.path.join(DATASETS, 'ciciot23', 'CSV')
    files = sorted(glob.glob(os.path.join(base, 'CSV', 'Benign_Final', '*.csv')))
    benign = pd.concat([pd.read_csv(f).assign(_id=lambda d, f=f: os.path.basename(f) + ':' + d.index.astype(str))
                        for f in files], ignore_index=True)
    merged = pd.read_csv(os.path.join(base, 'MERGED_CSV', 'MERGED_CSV', 'Merged01.csv'))
    attacks = merged[merged['Label'] != 'BENIGN'].assign(_id=lambda d: 'Merged01.csv:' + d.index.astype(str))
    feats = [c for c in merged.columns if c != 'Label']
    benign['Label'] = 'BENIGN'
    df = pd.concat([benign, attacks], ignore_index=True)
    finite = np.isfinite(df[feats].to_numpy(np.float64)).all(axis=1)
    dup = df.duplicated(subset=feats + ['Label']).to_numpy()
    info = {'non_finite_rows_dropped': int((~finite).sum()), 'duplicates_dropped': int((dup & finite).sum()),
            'clean_rows_available': int(((df['Label'] == 'BENIGN') & finite & ~dup).sum())}
    df = df[finite & ~dup]
    clean = np.flatnonzero((df['Label'] == 'BENIGN').to_numpy())
    pick = np.random.default_rng(SPLIT_SEED).choice(clean, CICIOT_N_BENIGN, replace=False)
    df = df.iloc[np.sort(np.r_[pick, np.flatnonzero((df['Label'] != 'BENIGN').to_numpy())])]
    y = (df['Label'] != 'BENIGN').to_numpy(int)
    family = np.where(y == 1, df['Label'], 'Benign')
    return assemble('ciciot23', df[feats].to_numpy(np.float32), y, family, feats, df['_id'].to_numpy(), **info)


def load_bodmas(temporal=False):
    from audit_bodmas import feature_names

    base = os.path.join(DATASETS, 'bodmas')
    z = np.load(os.path.join(base, 'bodmas.npz'), allow_pickle=False)
    meta = pd.read_csv(os.path.join(base, 'bodmas_metadata.csv'))
    cat = pd.read_csv(os.path.join(base, 'bodmas_malware_category.csv'))
    X, y = z['X'], z['y'].astype(int)
    keep = first_occurrence(X)
    X, y, meta = X[keep], y[keep], meta[keep].reset_index(drop=True)
    # first-seen time in UTC (the 3,712 timestamps without a zone are taken as UTC, as in audit_bodmas.py)
    when = pd.to_datetime(meta['timestamp'], utc=True, format='ISO8601').dt.tz_localize(None).to_numpy()
    family = np.where(y == 1, meta['sha'].map(cat.set_index('sha256')['category']), 'Benign')
    ds = assemble('bodmas', X, y, family, feature_names(), np.flatnonzero(keep), duplicates_dropped=int((~keep).sum()))
    ds.extra['first_seen'] = when
    if temporal:
        retime(ds, np.datetime64(BODMAS_CUTOFF))
    return ds


def retime(ds, cutoff):
    """BODMAS by first-seen date: clean files before the cutoff split 60/20/20 into train / cal / test_old;
    malware before it split 50/50 into fit / test_old; everything first seen on or after it is test_new."""
    old = ds.extra['first_seen'] < cutoff
    rng = np.random.default_rng(SPLIT_SEED)
    part = np.full(len(ds.y), 'test_new', dtype='<U8')
    for k, split in ((0, split_clean), (1, split_malware)):
        p = split(int(((ds.y == k) & old).sum()), rng)
        part[(ds.y == k) & old] = np.where(p == 'test', 'test_old', p)
    ds.part = part
    ds.info = {k: v for k, v in ds.info.items() if not k.startswith(('clean_', 'malware_'))}
    ds.info.update({'cutoff': BODMAS_CUTOFF, 'clean_rows': int((ds.y == 0).sum()),
                    'malware_rows': int((ds.y == 1).sum())} | partition_counts(ds.y, part))


LOADERS = {'malmem': load_malmem, 'ciciot23': load_ciciot23, 'bodmas': load_bodmas}


# ----- detectors (fitted on scaled clean training rows only) -----

def fit_detector(name, X_train, seed):
    """Returns (score function, fitted model); the function maps rows to anomaly scores, higher = more unusual."""
    if name == 'autoencoder':
        model, _, _ = fit_paper_autoencoder(X_train, seed, verbose=0)
        return lambda X: finite(reconstruction_mse(model, X)), model
    if name == 'isolation_forest':
        iso = IsolationForest(n_estimators=100, max_samples='auto', max_features=1.0, random_state=seed,
                              n_jobs=-1).fit(X_train)
        return lambda X: -iso.score_samples(X), iso
    raise ValueError(name)


def finite(s):
    return np.nan_to_num(np.asarray(s, np.float64), nan=np.finfo(np.float64).max, posinf=np.finfo(np.float64).max)


# ----- conformal p-values and metrics -----

def conformal_p(cal_scores, s):
    cal = np.sort(cal_scores)
    return (1 + len(cal) - np.searchsorted(cal, s)) / (len(cal) + 1)


def malware_weight(n_clean, n_mal, ratio=RATIO):
    return n_clean / ratio / n_mal


def at_flags(flag_clean, flag_mal, ratio=RATIO):
    n_clean, n_mal = len(flag_clean), len(flag_mal)
    fp, tp = int(flag_clean.sum()), int(flag_mal.sum())
    w = malware_weight(n_clean, n_mal, ratio)
    precision = tp * w / (tp * w + fp) if tp + fp else 0.0
    recall = tp / n_mal
    return {'false_alarms': fp, 'false_alarm_rate': fp / n_clean, 'caught': tp, 'recall': recall,
            'precision_20to1': precision,
            'f1_20to1': 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
            'accuracy_20to1': (n_clean - fp + tp * w) / (n_clean + n_mal * w)}


def ranking(s_clean, s_mal, ratio=RATIO):
    y = np.r_[np.zeros(len(s_clean)), np.ones(len(s_mal))]
    w = np.r_[np.ones(len(s_clean)), np.full(len(s_mal), malware_weight(len(s_clean), len(s_mal), ratio))]
    s = np.r_[s_clean, s_mal]
    return {'roc_auc': roc_auc_score(y, s), 'pr_auc_20to1': average_precision_score(y, s, sample_weight=w)}


def per_family(flag_mal, family_mal):
    s = pd.Series(flag_mal).groupby(np.asarray(family_mal))
    return {f: {'recall': float(r), 'n': int(n)} for (f, r), n in zip(s.mean().items(), s.size())}


def thresholds(train_scores, cal_scores):
    """Flag lines compared on the unseen test rows; the conformal ones are p <= alpha."""
    return {'paper_mean_plus_3std': float(np.mean(train_scores) + 3 * np.std(train_scores)),
            'train_99th_percentile': float(np.percentile(train_scores, 99)),
            'conformal_1pct': 0.01, 'conformal_5pct': 0.05}


def flags(name, line, s, cal_scores):
    return conformal_p(cal_scores, s) <= line if name.startswith('conformal') else s > line


# ----- baselines -----

def majority_baseline():
    return {**at_flags(np.zeros(RATIO, bool), np.zeros(1, bool)), 'roc_auc': 0.5, 'pr_auc_20to1': 1 / (RATIO + 1)}


def best_stump(X_fit, y_fit, features):
    """Best single-feature decision stump on the labelled fit rows (balanced accuracy)."""
    best = (-1.0, None, None)
    for j in range(X_fit.shape[1]):
        if X_fit[:, j].min() == X_fit[:, j].max():
            continue
        stump = DecisionTreeClassifier(max_depth=1, class_weight='balanced').fit(X_fit[:, [j]], y_fit)
        acc = balanced_accuracy_score(y_fit, stump.predict(X_fit[:, [j]]))
        if acc > best[0]:
            best = (acc, j, stump)
    acc, j, stump = best
    tree = stump.tree_
    side = 'above' if stump.classes_[tree.value[tree.children_right[0]].argmax()] == 1 else 'at or below'
    return {'feature': features[j], 'rule': f'malware if {features[j]} {side} {tree.threshold[0]:g}',
            'fit_balanced_accuracy': acc}, lambda X: stump.predict_proba(X[:, [j]])[:, 1]


def summarise(runs):
    """Mean / min / max over seeds of every numeric leaf of the per-seed result dicts."""
    first = runs[0]
    if isinstance(first, dict):
        return {k: summarise([r[k] for r in runs]) for k in first}
    if isinstance(first, (int, float, np.floating, np.integer)) and not isinstance(first, bool):
        v = np.asarray(runs, float)
        return {'mean': round(float(v.mean()), 4), 'min': round(float(v.min()), 4), 'max': round(float(v.max()), 4)}
    return first
