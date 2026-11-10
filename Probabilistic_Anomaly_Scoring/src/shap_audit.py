"""SHAP audit (study guide, section 5, step 5): what do explanations of the anomaly score point at?

For an artefact x the score is split into contributions phi_j with
    score(x) = mean score of the clean reference rows + sum_j phi_j
so phi_j is how much feature j makes x look less like clean data. The reference rows are 100 clean calibration
rows (fixed seed), the clean data the p-values come from. The scores explained are the autoencoder's
reconstruction MSE and the VAE's negative ELBO (z = mean): exactly the functions protocol.fit_detector returns
in src/heldout_eval.py, on the same splits, scaler and seeds. Isolation Forest is not explained: at the 1%
line it catches little (recall 0.00-0.37). Nothing here changes the detectors or the held-out results.

  per feature  shap's Permutation explainer, Independent masker, 10 antithetic permutations (MalMem, CICIoT2023)
  per group    exact Shapley values with feature groups as players: MalMem's 9 Volatility plugins and BODMAS's
               9 EMBER feature groups (2,381 features are too many for per-feature SHAP); 2^9 coalitions
  check        the distance baseline sum_j z_j^2 is additive, so its exact SHAP values are known
               (z_j^2 - mean over the reference rows); both methods must reproduce them

Audit, on up to --n test malware rows flagged at p <= 0.01, per detector and seed:
  row_share             each artefact's |phi| shares, averaged (every artefact weighs the same); used for rankings
  share                 share of the pooled mean |phi| (artefacts with large scores weigh more), for comparison
  top_reason_frequency  how often each feature is an artefact's largest contribution
  shortcut_share        share going to the known shortcut (MalMem svcscan.*, CICIoT2023 window features)
  best_stump_feature    the feature with the best single-feature stump: its SHAP rank and share
  stump_spearman        Spearman correlation between feature (or group) importance and the best stump balanced
                        accuracy, stumps fitted on the clean training rows plus the malware 'fit' rows
  error_split           overlap of SHAP's top 3 with the top 3 of the per-feature squared reconstruction error,
                        the triage report's 'error_reasons'
  stability             Spearman correlation and top-5 overlap between seeds and between autoencoder and VAE

Outputs: results/shap/<dataset>[_no-<group>].json and .png. Only aggregates are saved (no per-file values),
so the BODMAS outputs respect its terms.

Usage: python src/shap_audit.py {malmem,ciciot23,bodmas} [--drop svcscan|window] [--seeds 42 1] [--n 300]
"""
import argparse
import json
import os
import time
from math import factorial

import numpy as np
from scipy.stats import spearmanr
from sklearn.metrics import balanced_accuracy_score
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

import protocol as P
from replicate_khalid import ROOT

OUT = os.path.join(ROOT, 'results', 'shap')
DETECTORS = ('autoencoder', 'vae')
SHORTCUTS = {'malmem': P.DROP_GROUPS['svcscan'], 'ciciot23': P.DROP_GROUPS['window']}
N_BACKGROUND = 100
ALPHA = 0.01
MAX_PER_FEATURE = 100     # above this many features only group Shapley values are computed


# ----- attribution -----

def feature_shap(score_fn, X, background, seed):
    """Per-feature SHAP values (n, d) and base values (n,) of a score function."""
    import shap

    masker = shap.maskers.Independent(background, max_samples=len(background))
    f = lambda Z: score_fn(np.asarray(Z, np.float32))                   # shap passes float64; the models take float32
    e = shap.explainers.Permutation(f, masker, seed=seed)(X, max_evals=10 * (2 * X.shape[1] + 1), silent=True)
    return np.asarray(e.values, np.float64), np.asarray(e.base_values, np.float64)


def group_shapley(score_fn, X, background, groups):
    """Exact Shapley values (n, G) with feature groups as players; a group outside the coalition takes the
    reference rows' values. Each row sums to score(x) - mean score of the reference rows."""
    cols = list(groups.values())
    G, (B, D) = len(cols), background.shape
    member = (np.arange(2 ** G)[:, None] >> np.arange(G)) & 1          # coalition c holds group g if bit g is set
    keep = np.zeros((2 ** G, D), bool)
    for g, c in enumerate(cols):
        keep[:, c] = member[:, [g]].astype(bool)
    size = member.sum(1)
    weight = np.array([factorial(k) * factorial(G - k - 1) / factorial(G) for k in range(G)])
    chunk = int(min(2 ** G, max(1, 16e6 // (B * D))))                    # about 64 MB of masked rows at a time
    out = np.zeros((len(X), G))
    for r, x in enumerate(X):
        v = np.empty(2 ** G)
        for c0 in range(0, 2 ** G, chunk):
            k = keep[c0:c0 + chunk]
            Xm = np.where(k[:, None, :], x[None, None, :], background[None]).reshape(-1, D)
            v[c0:c0 + chunk] = score_fn(Xm).reshape(len(k), B).mean(1)
        for g in range(G):
            without = np.flatnonzero(member[:, g] == 0)
            out[r, g] = (weight[size[without]] * (v[without | (1 << g)] - v[without])).sum()
    return out


def feature_groups(features):
    """Volatility plugin (MalMem) or EMBER group (BODMAS): the name before the first dot; None without dots."""
    if not all('.' in f for f in features):
        return None
    names = list(dict.fromkeys(f.split('.')[0] for f in features))
    return {g: np.array([i for i, f in enumerate(features) if f.split('.')[0] == g]) for g in names}


def fast_score(det, score, model, X_check):
    """The same score as protocol.fit_detector's, without Keras predict()'s fixed cost per call (shap calls the
    score thousands of times; predict() made the autoencoder about 5 s per explained row). Checked against the
    original score on X_check; flags still use the original."""
    if det != 'autoencoder':
        return score

    def f(X, batch=65536):
        return P.finite(np.concatenate([np.mean(np.square(X[i:i + batch] - model(X[i:i + batch], training=False)
                                                          .numpy()), axis=1) for i in range(0, len(X), batch)]))
    a, b = f(X_check), score(X_check)
    assert np.allclose(a, b, rtol=1e-4, atol=1e-6), float(np.abs(a - b).max())
    return f


def error_split(det, model, X):
    """Per-feature squared reconstruction error (the triage report's 'error_reasons')."""
    if det == 'autoencoder':
        return np.square(X - model.predict(X, verbose=0))
    encoder, decoder = model
    return np.square(X - decoder(encoder(X)[0]).numpy())


def stump_scores(X_fit, y_fit):
    """Balanced accuracy of the best single-feature stump on every feature (0.5 for constant features)."""
    out = np.full(X_fit.shape[1], 0.5)
    for j in range(X_fit.shape[1]):
        col = X_fit[:, [j]]
        if col.min() < col.max():
            stump = DecisionTreeClassifier(max_depth=1, class_weight='balanced').fit(col, y_fit)
            out[j] = balanced_accuracy_score(y_fit, stump.predict(col))
    return out


# ----- summaries -----

def share(phi):
    """Share of mean |phi|: artefacts with large scores weigh more."""
    imp = np.abs(phi).mean(0)
    return imp / imp.sum()


def row_share(phi):
    """Mean of each artefact's own |phi| shares: every artefact weighs the same, as for an examiner reading
    one explanation at a time."""
    a = np.abs(phi)
    return (a / np.maximum(a.sum(1, keepdims=True), 1e-300)).mean(0)


def rho(a, b):
    r = spearmanr(a, b).statistic
    return None if np.isnan(r) else round(float(r), 3)


def topk(v, k):
    return [int(i) for i in np.argsort(-np.asarray(v))[:k]]


def top3_agreement(phi, err):
    """Mean overlap (0-1) of the top 3 by |phi| and by error, and how often the top feature is the same."""
    a, b = np.argsort(-np.abs(phi), 1)[:, :3], np.argsort(-err, 1)[:, :3]
    overlap = np.mean([len(set(x) & set(y)) / 3 for x, y in zip(a, b)])
    return {'top3_overlap': round(float(overlap), 3), 'top1_match': round(float(np.mean(a[:, 0] == b[:, 0])), 3)}


def attribution_summary(phi, names, stumps, err, k=10):
    """Rankings use row_share (per artefact); 'share' (pooled mean |phi|) is kept for comparison."""
    rs, sh = row_share(phi), share(phi)
    order = topk(rs, len(rs))
    best = int(np.argmax(stumps))
    top1 = np.bincount(np.argmax(np.abs(phi), 1), minlength=len(names)) / len(phi)
    return {'row_share': {names[i]: round(float(rs[i]), 4) for i in order},
            'share': {names[i]: round(float(sh[i]), 4) for i in topk(sh, len(sh))},
            'top': [names[i] for i in order[:k]],
            'top_reason_frequency': {names[i]: round(float(top1[i]), 3) for i in topk(top1, k) if top1[i] > 0},
            'best_stump_feature': {'name': names[best], 'stump_balanced_accuracy': round(float(stumps[best]), 4),
                                   'shap_rank': order.index(best) + 1, 'row_share': round(float(rs[best]), 4),
                                   'top_reason_frequency': round(float(top1[best]), 3)},
            'stump_spearman': {'row_share': rho(rs, stumps), 'share': rho(sh, stumps)},
            'error_split': top3_agreement(phi, err)}


def stability(a, b):
    return {'spearman': rho(a, b), 'top5_overlap': len(set(topk(a, 5)) & set(topk(b, 5)))}


def check_distance(X, background, groups, per_feature):
    """Max error relative to the largest exact value, for the distance baseline's known SHAP values."""
    exact = np.square(X.astype(np.float64)) - np.square(background.astype(np.float64)).mean(0)
    out = {}
    if per_feature:
        phi, _ = feature_shap(P.distance_score, X, background, 0)
        out['per_feature'] = float(np.abs(phi - exact).max() / np.abs(exact).max())
    if groups:
        ex_g = np.stack([exact[:, c].sum(1) for c in groups.values()], 1)
        out['per_group'] = float(np.abs(group_shapley(P.distance_score, X, background, groups) - ex_g).max()
                                 / np.abs(ex_g).max())
    return out


def chart(results, names, path, title):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    panels = [k for k in ('feature', 'group') if k in names]
    fig, axes = plt.subplots(1, len(panels), figsize=(6.5 * len(panels), 6), squeeze=False)
    for ax, kind in zip(axes[0], panels):
        runs = {d: results['runs'][d][str(results['settings']['seeds'][0])][kind]['row_share'] for d in DETECTORS}
        show = list(runs['autoencoder'])[:15][::-1]
        y = np.arange(len(show))
        for off, d in ((-0.2, 'autoencoder'), (0.2, 'vae')):
            ax.barh(y + off, [runs[d].get(f, 0) for f in show], height=0.4, label=d)
        ax.set_yticks(y, show, fontsize=8)
        ax.set_xlabel('mean per-artefact share of |SHAP|, flagged test malware')
        ax.set_title(f'per {kind}')
        ax.legend(loc='lower right')
    fig.suptitle(title)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dataset', choices=sorted(P.LOADERS))
    ap.add_argument('--drop', choices=sorted(P.DROP_GROUPS))
    ap.add_argument('--seeds', type=int, nargs='+', default=[42, 1])
    ap.add_argument('--n', type=int, default=300, help='flagged test malware rows explained per detector and seed')
    args = ap.parse_args()

    ds = P.LOADERS[args.dataset]()
    if args.drop:
        ds.drop(args.drop)
    train, cal = (ds.y == 0) & (ds.part == 'train'), (ds.y == 0) & (ds.part == 'cal')
    mal = (ds.y == 1) & (ds.part == 'test')
    fit = train | ((ds.y == 1) & (ds.part == 'fit'))
    Xs = StandardScaler().fit(ds.X[train]).transform(ds.X).astype(np.float32)
    background = Xs[cal][np.random.default_rng(0).choice(int(cal.sum()), N_BACKGROUND, replace=False)]
    groups = feature_groups(ds.features)
    per_feature = len(ds.features) <= MAX_PER_FEATURE
    names = {}
    if per_feature:
        names['feature'] = ds.features
    if groups:
        names['group'] = list(groups)
    stumps = stump_scores(ds.X[fit], ds.y[fit])
    stumps_by = {'feature': stumps, 'group': np.array([stumps[c].max() for c in groups.values()]) if groups else None}
    shortcut = [ds.features.index(f) for f in SHORTCUTS[args.dataset](ds.features)] if args.dataset in SHORTCUTS else []

    t0 = time.time()
    results = {'data': ds.info,
               'settings': {'seeds': args.seeds, 'n_max': args.n, 'n_background': N_BACKGROUND, 'alpha': ALPHA,
                            'per_feature': per_feature, 'groups': {g: len(c) for g, c in (groups or {}).items()}},
               'distance_check_max_relative_error': check_distance(Xs[mal][:20], background, groups, per_feature),
               'runs': {d: {} for d in DETECTORS}}
    print(f'{args.dataset}: distance check {results["distance_check_max_relative_error"]} '
          f'({time.time() - t0:.0f}s)', flush=True)

    shares = {}
    for det in DETECTORS:
        for seed in args.seeds:
            t0 = time.time()
            score, model = P.fit_detector(det, Xs[train], seed)
            s_mal = score(Xs[mal])
            finite = s_mal < 1e300
            flagged = np.flatnonzero((P.conformal_p(score(Xs[cal]), s_mal) <= ALPHA) & finite)
            pick = np.sort(np.random.default_rng(0).choice(flagged, min(args.n, len(flagged)), replace=False))
            X = Xs[mal][pick]
            s, err = score(X), error_split(det, model, X)
            score = fast_score(det, score, model, Xs[cal])
            r = {'test_malware': int(mal.sum()), 'flagged': len(flagged), 'explained': len(pick),
                 'excluded_non_finite_score': int((~finite).sum())}
            if per_feature:
                phi, base = feature_shap(score, X, background, seed)
                r['feature'] = attribution_summary(phi, ds.features, stumps, err)
                r['feature']['efficiency_max_relative_error'] = float(np.abs(base + phi.sum(1) - s).max() / s.max())
                if shortcut:
                    r['feature']['shortcut_share'] = {'row_share': round(float(row_share(phi)[shortcut].sum()), 4),
                                                      'share': round(float(share(phi)[shortcut].sum()), 4)}
                shares[det, seed, 'feature'] = row_share(phi)
            if groups:
                phi_g = group_shapley(score, X, background, groups)
                err_g = np.stack([err[:, c].sum(1) for c in groups.values()], 1)
                r['group'] = attribution_summary(phi_g, list(groups), stumps_by['group'], err_g, k=5)
                base_g = score(background).mean()
                r['group']['efficiency_max_relative_error'] = float(np.abs(base_g + phi_g.sum(1) - s).max() / s.max())
                shares[det, seed, 'group'] = row_share(phi_g)
            r['seconds'] = round(time.time() - t0, 1)
            results['runs'][det][str(seed)] = r
            main_kind = 'feature' if per_feature else 'group'
            print(f'{det} seed {seed}: explained {len(pick)} of {len(flagged)} flagged; top {main_kind}s '
                  f'{r[main_kind]["top"][:5]}; best stump {r[main_kind]["best_stump_feature"]}; '
                  f'stump rho {r[main_kind]["stump_spearman"]}; error split {r[main_kind]["error_split"]} '
                  f'({r["seconds"]}s)', flush=True)

    results['stability'] = {}
    for kind in names:
        st = {}
        if len(args.seeds) > 1:
            st['between_seeds'] = {d: stability(shares[d, args.seeds[0], kind], shares[d, args.seeds[1], kind])
                                   for d in DETECTORS}
        st['autoencoder_vs_vae'] = {str(s): stability(shares['autoencoder', s, kind], shares['vae', s, kind])
                                    for s in args.seeds}
        results['stability'][kind] = st
    print('stability', json.dumps(results['stability']), flush=True)

    os.makedirs(OUT, exist_ok=True)
    tag = args.dataset + (f'_no-{args.drop}' if args.drop else '')
    with open(os.path.join(OUT, f'{tag}.json'), 'w') as f:
        json.dump(results, f, indent=2)
    chart(results, names, os.path.join(OUT, f'{tag}.png'), f'SHAP share, {tag}, seed {args.seeds[0]}')


if __name__ == '__main__':
    main()
