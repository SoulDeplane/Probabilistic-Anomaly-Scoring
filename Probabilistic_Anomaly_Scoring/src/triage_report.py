"""Triage report (study guide, section 5, step 7): evidence ranked by how unusual it looks next to clean data.

The base paper's autoencoder (scaled features, trained on the clean training rows only; src/protocol.py) scores
a 'seized batch': the held-out clean test rows plus test malware at the base paper's 20:1 ratio. Per artefact:
  score              reconstruction error (mean squared error over the scaled features)
  p_value            conformal p-value from the held-out calibration rows: the share of clean data that looks at
                     least this unusual, i.e. the false-alarm rate of flagging everything down to this row
  flagged            p <= 0.01
  top_features       the three features with the largest share of the reconstruction error, with the artefact's
                     value and the clean training median. This is the autoencoder's own exact split of its score,
                     not a SHAP attribution, and says which features are unusual, not why
  label, family      ground truth, for evaluation only (an examiner would not have it)
  precision_so_far,  what flagging everything down to this rank achieves (evaluation only)
  recall_so_far
Outputs in results/triage/: <dataset>_ranked.csv, <dataset>_pr_curve.png and <dataset>_report.md (summary, the
25 highest-ranked artefacts and the protocol's known limitations). The BODMAS outputs list per-file feature values,
so they are git-ignored: the dataset's terms forbid sharing its data beyond the project's co-authors.

Usage: python src/triage_report.py [malmem|ciciot23|bodmas] [--seed 42]
"""
import argparse
import os

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_curve
from sklearn.preprocessing import StandardScaler

import protocol as P
from replicate_khalid import ROOT

OUT = os.path.join(ROOT, 'results', 'triage')
ALPHA = 0.01
LIMITATIONS = {
    'common': [
        'The model learns clean data only, so it flags anything unusual, not only malware: new but legitimate '
        'software, unusual configurations and rare user activity are flagged too.',
        'The p-value holds only while new clean data resembles the calibration data. On BODMAS, clean files first '
        'seen up to seven months after the training period kept the false-alarm rate at about 1% '
        '(results/heldout/bodmas_temporal.json), but no longer horizon has been tested.',
        'top_features names the features the autoencoder could not reconstruct. It is not a causal explanation: '
        'a feature can be unusual because of how the evidence was captured rather than because of malware, and a '
        'feature whose value is ordinary can still appear when one extreme feature throws off the whole '
        'reconstruction.',
        'Ground truth columns are included only to evaluate the ranking; they are not available at seizure.',
    ],
    'malmem': [
        'CIC MalMemAnalysis-2022 comes from one Windows 10 virtual machine. Clean dumps show 392 or 395 running '
        'services and malware dumps mostly 389, so svcscan.nservices separates the classes almost perfectly '
        '(99.66% for a one-feature rule): a property of the lab setup, not of malware.',
        'Each malware binary contributes about ten dumps taken 15 seconds apart, so the batch holds near-repeats.',
        'The dataset authors state that the clean class was balanced with SMOTE; how many clean rows are '
        'synthetic is not reported.',
    ],
    'ciciot23': [
        'CICIoT2023 rows are fixed-size packet windows, not artefacts: 100 packets for floods and 10 for all other '
        'traffic, so window-dependent features (Number, Tot sum, IAT, Variance, Rate) partly encode the label.',
        'More than half of the released rows (53.5% across the 63 merged files) exactly repeat an earlier row, '
        'mostly DDoS floods (results/audit/ciciot23.json).',
        'Recall is dominated by floods, which make up most of the attack rows; spoofing, scanning and web attacks '
        'are mostly missed (per-class recall in results/heldout/ciciot23.json).',
    ],
    'bodmas': [
        'BODMAS detection is weak: most malware looks like ordinary clean executables in these static features, '
        'so a low p-value is evidence of unusualness, and a high p-value is not evidence of innocence.',
    ],
}


def seized_batch(ds):
    clean = np.flatnonzero((ds.y == 0) & (ds.part == 'test'))
    mal = np.flatnonzero((ds.y == 1) & (ds.part == 'test'))
    pick = np.random.default_rng(P.SPLIT_SEED).choice(mal, round(len(clean) / P.RATIO), replace=False)
    return np.sort(np.r_[clean, pick])


def reasons(err, X_raw, median, features, k=3):
    share = err / err.sum(axis=1, keepdims=True)
    top = np.argsort(-share, axis=1)[:, :k]
    return ['; '.join(f'{features[j]} {X_raw[i, j]:g} vs clean median {median[j]:g} ({share[i, j]:.0%})'
                      for j in top[i]) for i in range(len(top))]


def pr_chart(y, score, flags, path, title):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    ink, muted, blue, surface = '#0b0b0b', '#52514e', '#2a78d6', '#fcfcfb'
    precision, recall, _ = precision_recall_curve(y, score)
    fig, ax = plt.subplots(figsize=(6.4, 4.6), facecolor=surface)
    ax.set_facecolor(surface)
    ax.plot(recall, precision, color=blue, lw=2, label=f'autoencoder (PR-AUC {average_precision_score(y, score):.3f})')
    ax.axhline(y.mean(), color=muted, lw=1, ls='--', label=f'always clean ({y.mean():.3f})')
    for name, f in flags.items():
        p, r = (y[f].mean() if f.any() else 0.0), y[f].sum() / y.sum()
        ax.plot(r, p, 'o', ms=9, color=blue, mec=surface, mew=2, zorder=3)
        ax.annotate(f'{name}: precision {p:.2f}, recall {r:.2f}', (r, p), xytext=(-12, 0),
                    textcoords='offset points', ha='right', va='center', fontsize=9, color=ink)
    ax.set(xlim=(0, 1.02), ylim=(0, 1.04), xlabel='Recall (share of malware flagged)',
           ylabel='Precision (share of flags that are malware)')
    ax.set_title(title, fontsize=11, color=ink, loc='left')
    ax.grid(color='#e6e5e1', lw=0.8)
    for s in ('top', 'right'):
        ax.spines[s].set_visible(False)
    for s in ('left', 'bottom'):
        ax.spines[s].set_color('#b5b4ad')
    ax.tick_params(colors=muted)
    ax.legend(frameon=False, loc='lower left', bbox_to_anchor=(0.01, 0.12), fontsize=9, labelcolor=ink)
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=surface)
    plt.close(fig)


def markdown(name, table, summary, path):
    cols = ['rank', 'artefact', 'score', 'p_value', 'flagged', 'top_features', 'label', 'family']
    top = table.head(25)[cols].copy()
    top['score'] = top['score'].map(lambda v: f'{v:.3g}')
    top['p_value'] = top['p_value'].map(lambda v: f'{v:.4f}')
    rows = ['| ' + ' | '.join(cols) + ' |', '|' + '---|' * len(cols)]
    rows += ['| ' + ' | '.join(str(v).replace('|', '/') for v in r) + ' |' for r in top.itertuples(index=False)]
    lines = [f'# Triage report: {name}', '', f'Generated by `src/triage_report.py {name}`. Full ranked list: '
             f'`{name}_ranked.csv`; precision-recall curve: `{name}_pr_curve.png`.', '', '## Summary', '']
    lines += [f'- {k}: {v}' for k, v in summary.items()]
    lines += ['', f'![Precision-recall curve]({name}_pr_curve.png)', '', '## The 25 most unusual artefacts', '',
              '`label` and `family` are ground truth, shown for evaluation only.', ''] + rows
    lines += ['', '## Known limitations', ''] + [f'- {t}' for t in LIMITATIONS[name] + LIMITATIONS['common']]
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dataset', nargs='?', default='malmem', choices=sorted(P.LOADERS))
    ap.add_argument('--seed', type=int, default=42)
    args = ap.parse_args()

    ds = P.LOADERS[args.dataset]()
    train, cal = (ds.y == 0) & (ds.part == 'train'), (ds.y == 0) & (ds.part == 'cal')
    scaler = StandardScaler().fit(ds.X[train])
    Xs = scaler.transform(ds.X).astype(np.float32)
    score, model = P.fit_detector('autoencoder', Xs[train], args.seed)
    cal_scores = score(Xs[cal])

    batch = seized_batch(ds)
    Xb = Xs[batch]
    err = np.square(Xb - model.predict(Xb, verbose=0)).astype(np.float64)
    s = P.finite(err.mean(axis=1))
    p = P.conformal_p(cal_scores, s)
    y = ds.y[batch]
    table = pd.DataFrame({'artefact': ds.row_id[batch], 'score': s, 'p_value': p, 'flagged': p <= ALPHA,
                          'top_features': reasons(err, ds.X[batch], np.median(ds.X[train], axis=0), ds.features),
                          'label': np.where(y == 1, 'malware', 'clean'), 'family': ds.family[batch]})
    table = table.sort_values('score', ascending=False, kind='stable').reset_index(drop=True)
    table.insert(0, 'rank', np.arange(1, len(table) + 1))
    hits = (table['label'] == 'malware').to_numpy()
    table['precision_so_far'] = np.round(np.cumsum(hits) / table['rank'], 4)
    table['recall_so_far'] = np.round(np.cumsum(hits) / hits.sum(), 4)

    flagged = table['flagged'].to_numpy()
    f5 = (table['p_value'] <= 0.05).to_numpy()
    summary = {
        'Seized batch': f'{len(table):,} artefacts: {int((~hits).sum()):,} held-out clean, {int(hits.sum()):,} '
                        f'malware (20:1, the base paper\'s ratio)',
        'Model': f'base-paper autoencoder on {len(ds.features)} scaled features, trained on '
                 f'{int(train.sum()):,} clean rows (seed {args.seed}); p-values from {int(cal.sum()):,} held-out '
                 f'clean rows',
        'Flagged at p <= 0.01': f'{int(flagged.sum()):,}: {int((flagged & hits).sum()):,} malware, '
                                f'{int((flagged & ~hits).sum()):,} clean '
                                f'(false-alarm rate {(flagged & ~hits).sum() / (~hits).sum():.2%}; '
                                f'recall {(flagged & hits).sum() / hits.sum():.3f}; '
                                f'precision {(flagged & hits).sum() / max(flagged.sum(), 1):.3f})',
        'Flagged at p <= 0.05': f'{int(f5.sum()):,}: {int((f5 & hits).sum()):,} malware, {int((f5 & ~hits).sum()):,} clean',
        'PR-AUC': f'{average_precision_score(hits, table["score"]):.3f} (always clean: {hits.mean():.3f})',
    }
    os.makedirs(OUT, exist_ok=True)
    table.to_csv(os.path.join(OUT, f'{args.dataset}_ranked.csv'), index=False)
    pr_chart(hits.astype(int), table['score'].to_numpy(), {'p <= 0.01': flagged, 'p <= 0.05': f5},
             os.path.join(OUT, f'{args.dataset}_pr_curve.png'),
             f'Triage ranking, {args.dataset}: held-out clean data plus malware at 20:1')
    markdown(args.dataset, table, summary, os.path.join(OUT, f'{args.dataset}_report.md'))
    for k, v in summary.items():
        print(f'{k}: {v}')


if __name__ == '__main__':
    main()
