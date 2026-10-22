"""Build a verifiable inventory and small samples of the local datasets for the repository.

The full datasets (~24 GB) cannot be hosted on GitHub. This script writes, under Datasets/:
  inventory/<dataset>_files.csv  every file: relative path, size, SHA-256, rows (CSV) or class/split (PNG)
  inventory/summary.json         per-dataset totals and class counts
  samples/ciciot23_sample.csv    up to 300 rows per class (39 features + Label), from each class's first capture
  samples/dumpware10/<class>/    5 images per class from the 224/224 TRAINING split
No BODMAS sample is written: its terms of use forbid sharing the data beyond the project's co-authors.

Usage: python src/build_dataset_inventory.py
"""
import csv
import glob
import hashlib
import json
import os
import re
import shutil

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS = os.path.normpath(os.path.join(ROOT, '..', 'Datasets'))
INVENTORY = os.path.join(DATASETS, 'inventory')
SAMPLES = os.path.join(DATASETS, 'samples')
DATASET_DIRS = ['cicmalmem22', 'ciciot23', 'dumpware10', 'bodmas']
CICIOT_ROWS_PER_CLASS = 300
DUMPWARE_IMAGES_PER_CLASS = 5


def natural_key(s):
    return [int(t) if t.isdigit() else t for t in re.split(r'(\d+)', s)]


def hash_and_count(path):
    """SHA-256 of the file and its number of newline characters, in one read."""
    h, lines = hashlib.sha256(), 0
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8 << 20), b''):
            h.update(chunk)
            lines += chunk.count(b'\n')
    return h.hexdigest(), lines


def ciciot_label(folder):
    return 'BENIGN' if folder == 'Benign_Final' else folder.upper()


def build_inventory():
    os.makedirs(INVENTORY, exist_ok=True)
    summary = {}
    for name in DATASET_DIRS:
        base = os.path.join(DATASETS, name)
        files = sorted((os.path.join(r, f) for r, _, fs in os.walk(base) for f in fs), key=natural_key)
        rows, total_bytes, total_rows = [], 0, 0
        for p in files:
            rel = os.path.relpath(p, DATASETS).replace(os.sep, '/')
            digest, lines = hash_and_count(p)
            size = os.path.getsize(p)
            total_bytes += size
            entry = {'path': rel, 'size_bytes': size, 'sha256': digest}
            if p.lower().endswith('.csv'):
                entry['data_rows'] = max(lines - 1, 0)  # minus header; every file ends with a newline
                total_rows += entry['data_rows']
            if name == 'dumpware10' and p.lower().endswith('.png'):
                parts = rel.split('/')  # dumpware10/<width>/<size>/<split>/<class>/<file>
                entry.update({'variant': f'{parts[1]}/{parts[2]}', 'split': parts[3], 'class': parts[4]})
            rows.append(entry)
        fields = sorted({k for r in rows for k in r}, key=['path', 'size_bytes', 'data_rows', 'variant',
                                                             'split', 'class', 'sha256'].index)
        with open(os.path.join(INVENTORY, f'{name}_files.csv'), 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
        summary[name] = {'files': len(rows), 'size_bytes': total_bytes, 'csv_data_rows': total_rows}
        print(f'{name}: {len(rows):,} files, {total_bytes / 1e9:.2f} GB, {total_rows:,} CSV rows', flush=True)
    return summary


def class_counts(summary):
    mm = pd.read_csv(os.path.join(DATASETS, 'cicmalmem22', 'CSV', 'Obfuscated-MalMem2022.csv'),
                     usecols=['Category', 'Class'])
    family = mm['Category'].where(mm['Class'] == 'Benign',
                                  mm['Category'].str.split('-').str[:2].str.join('-'))
    summary['cicmalmem22']['class_counts'] = family.value_counts().to_dict()

    inv = pd.read_csv(os.path.join(INVENTORY, 'ciciot23_files.csv'))
    per_class = inv[inv['path'].str.startswith('ciciot23/CSV/CSV/') & inv['path'].str.endswith('.csv')]
    labels = per_class['path'].str.split('/').str[3].map(ciciot_label)
    summary['ciciot23']['class_counts'] = per_class.groupby(labels)['data_rows'].sum().sort_values(
        ascending=False).astype(int).to_dict()

    inv = pd.read_csv(os.path.join(INVENTORY, 'dumpware10_files.csv'))
    one = inv[inv['variant'] == '224/224']
    summary['dumpware10']['class_counts_per_variant'] = (
        one.groupby(['class', 'split']).size().unstack(fill_value=0).astype(int).to_dict(orient='index'))
    summary['dumpware10']['variants'] = sorted(inv['variant'].dropna().unique().tolist())

    meta = pd.read_csv(os.path.join(DATASETS, 'bodmas', 'bodmas_metadata.csv'), usecols=['family'])
    cat = pd.read_csv(os.path.join(DATASETS, 'bodmas', 'bodmas_malware_category.csv'))
    summary['bodmas']['class_counts'] = {'benign': int(meta['family'].isna().sum()),
                                         'malware': int(meta['family'].notna().sum())}
    summary['bodmas']['malware_category_counts'] = cat['category'].value_counts().astype(int).to_dict()
    summary['bodmas']['malware_families'] = int(meta['family'].dropna().str.lower().nunique())


def build_samples():
    if os.path.isdir(SAMPLES):
        shutil.rmtree(SAMPLES)
    os.makedirs(SAMPLES)

    parts = []
    for folder in sorted(os.listdir(os.path.join(DATASETS, 'ciciot23', 'CSV', 'CSV'))):
        files = sorted(glob.glob(os.path.join(DATASETS, 'ciciot23', 'CSV', 'CSV', folder, '*.csv')), key=natural_key)
        if not files:
            continue
        df = pd.read_csv(files[0])
        df = df.sample(n=min(CICIOT_ROWS_PER_CLASS, len(df)), random_state=42)
        parts.append(df.assign(Label=ciciot_label(folder)))
    sample = pd.concat(parts, ignore_index=True)
    sample.to_csv(os.path.join(SAMPLES, 'ciciot23_sample.csv'), index=False)
    print(f'ciciot23 sample: {len(sample):,} rows, {sample["Label"].nunique()} classes', flush=True)

    rng = np.random.default_rng(42)
    base = os.path.join(DATASETS, 'dumpware10', '224', '224', 'TRAINING')
    n = 0
    for cls in sorted(os.listdir(base)):
        imgs = sorted(os.listdir(os.path.join(base, cls)))
        pick = sorted(rng.choice(len(imgs), DUMPWARE_IMAGES_PER_CLASS, replace=False))
        os.makedirs(os.path.join(SAMPLES, 'dumpware10', cls))
        for i in pick:
            shutil.copy2(os.path.join(base, cls, imgs[i]), os.path.join(SAMPLES, 'dumpware10', cls, imgs[i]))
            n += 1
    print(f'dumpware10 sample: {n} images', flush=True)


def main():
    summary = build_inventory()
    class_counts(summary)
    with open(os.path.join(INVENTORY, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    build_samples()


if __name__ == '__main__':
    main()
