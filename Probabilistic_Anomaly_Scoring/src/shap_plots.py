"""Standard SHAP plots of the autoencoder score (synopsis Phase 5): waterfall and force plots for one flagged
artefact (local), beeswarm summary and bar plots across flagged artefacts (global).

Same setup as shap_audit.py: protocol splits, scaler fitted on clean training rows, autoencoder seed 42, 100 clean
calibration rows as the SHAP reference, test malware flagged at p <= 0.01. The local plots explain the flagged
artefact with the median score, a typical case (the highest-scoring ones are extreme outliers driven by a single
feature, e.g. malfind.commitCharge on MalMem). The beeswarm and bar plots scale each artefact's SHAP values by
its total |SHAP| (as shap_audit.row_share does), because raw values are dominated by those few extreme rows.

MalMem and CICIoT2023 are explained per feature, with raw (unscaled) feature values shown. BODMAS is explained per
EMBER feature group (exact Shapley, 9 groups) and shows no per-file feature values, as its terms forbid sharing.

Usage: python src/shap_plots.py malmem [--n 200]
Output: results/shap/plots/<dataset>_{waterfall,force,beeswarm,bar}.png
"""
import argparse
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from sklearn.preprocessing import StandardScaler

import protocol as P
from shap_audit import ALPHA, N_BACKGROUND, OUT, MAX_PER_FEATURE, fast_score, feature_groups, feature_shap, group_shapley

SEED = 42


def save(path):
    plt.tight_layout()
    plt.savefig(path, dpi=130, bbox_inches='tight')
    plt.close('all')
    print('  saved', os.path.relpath(path, P.ROOT), flush=True)


def main():
    import shap

    ap = argparse.ArgumentParser()
    ap.add_argument('dataset', choices=sorted(P.LOADERS))
    ap.add_argument('--n', type=int, default=200, help='flagged test malware rows in the global plots')
    args = ap.parse_args()

    ds = P.LOADERS[args.dataset]()
    train, cal = (ds.y == 0) & (ds.part == 'train'), (ds.y == 0) & (ds.part == 'cal')
    mal = (ds.y == 1) & (ds.part == 'test')
    Xs = StandardScaler().fit(ds.X[train]).transform(ds.X).astype(np.float32)
    background = Xs[cal][np.random.default_rng(0).choice(int(cal.sum()), N_BACKGROUND, replace=False)]

    score, model = P.fit_detector('autoencoder', Xs[train], SEED)
    s_mal = score(Xs[mal])
    flagged = np.flatnonzero((P.conformal_p(score(Xs[cal]), s_mal) <= ALPHA) & (s_mal < 1e300))
    pick = np.random.default_rng(0).choice(flagged, min(args.n, len(flagged)), replace=False)
    typical = flagged[np.argsort(s_mal[flagged])[len(flagged) // 2]]  # flagged artefact with the median score
    pick = np.unique(np.append(pick, typical))
    top = int(np.flatnonzero(pick == typical)[0])
    X = Xs[mal][pick]
    score = fast_score('autoencoder', score, model, Xs[cal])
    print(f'{args.dataset}: {len(flagged)} of {int(mal.sum())} test malware flagged; explaining {len(pick)}', flush=True)

    if len(ds.features) <= MAX_PER_FEATURE:
        phi, base = feature_shap(score, X, background, SEED)
        names, data = ds.features, ds.X[mal][pick]
    else:
        groups = feature_groups(ds.features)
        phi = group_shapley(score, X, background, groups)
        base = np.full(len(X), score(background).mean())
        names, data = list(groups), None
    exp = shap.Explanation(values=phi, base_values=base, data=data, feature_names=names)

    out = os.path.join(OUT, 'plots')
    os.makedirs(out, exist_ok=True)
    stem = os.path.join(out, args.dataset)
    title = f'{args.dataset}, autoencoder (seed {SEED})'

    shap.plots.waterfall(exp[top], max_display=12, show=False)
    plt.title(f'{title}: median-scoring flagged artefact')
    save(f'{stem}_waterfall.png')

    keep = np.argsort(-np.abs(phi[top]))[:8]  # the force plot is unreadable with every feature labelled
    rest = np.setdiff1d(np.arange(phi.shape[1]), keep)
    fv = np.append(phi[top, keep], phi[top, rest].sum())
    fn = [names[i] if data is None else f'{names[i]} = {data[top, i]:g}' for i in keep]
    fn.append(f'{len(rest)} other features' if data is None or len(rest) else '')
    shap.plots.force(base[top], fv, feature_names=fn, matplotlib=True, show=False, text_rotation=20)
    save(f'{stem}_force.png')

    total = np.abs(phi).sum(1, keepdims=True)
    signed = phi / np.where(total > 0, total, 1)  # each artefact's SHAP values as shares of its total |SHAP|
    shap.plots.beeswarm(shap.Explanation(values=signed, data=data, feature_names=names), max_display=15, show=False)
    plt.xlabel('SHAP value as a share of the artefact\'s total |SHAP|')
    plt.title(f'{title}: {len(pick)} flagged test malware')
    save(f'{stem}_beeswarm.png')

    shap.plots.bar(shap.Explanation(values=np.abs(signed), feature_names=names), max_display=15, show=False)
    plt.xlabel('mean share of an artefact\'s total |SHAP|')
    plt.title(f'{title}: {len(pick)} flagged test malware')
    save(f'{stem}_bar.png')


if __name__ == '__main__':
    main()
