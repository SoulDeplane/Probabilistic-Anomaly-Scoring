# Probabilistic Anomaly Scoring for Explainable Digital Forensic Triage

B.Tech major project MP2026CSE75, Dept. of CSE, Graphic Era Deemed to be University (guide: Dr. Rehan).

Examiners seize more evidence than they can read, so they have to decide what to examine first (triage). This project scores every artefact (memory dump, executable, network flow) by how unusual it is compared with **clean data only**, turns the score into a p-value with a false-alarm rate fixed in advance, and audits what the score is really picking up. The base paper is Khalid, Iqbal & Saqib (2025), *Forensic Sci. Int.: Digital Investigation* 53, 301924.

Status: the base paper is replicated, both its anomaly detection and its clustering. Its autoencoder, a variational autoencoder (VAE) and Isolation Forest are tested on three datasets with held-out, conformal and time-ordered evaluation, against a no-model distance-from-the-mean baseline. A SHAP audit checks what the explanations of their scores point at.

## Repository layout

| Path | Contents |
|---|---|
| `Probabilistic_Anomaly_Scoring/src/` | All experiment scripts (below) |
| `Probabilistic_Anomaly_Scoring/results/` | Their JSON / CSV / PNG outputs, committed |
| `Datasets/` | MalMem CSV, checksummed inventory and samples of the other datasets; see `Datasets/README.md` |
| `Writeup/` | Synopsis, slides, project updates |
| `Research Papers/` | Papers reviewed |

## Setup

Python 3.12, CPU only.

```bash
python -m venv .venv && .venv/Scripts/activate      # Windows; source .venv/bin/activate elsewhere
pip install -r requirements.txt
```

CIC MalMemAnalysis-2022 is included. CICIoT2023, BODMAS and Dumpware10 must be downloaded from their publishers into `Datasets/` (sources and expected layout in `Datasets/README.md`); BODMAS may not be redistributed. TensorFlow on CPU is not bit-for-bit deterministic, so reruns of the autoencoder and VAE vary slightly. The VAE and SHAP results were produced in WSL2 (Ubuntu 24.04, Python 3.12) with the same `requirements.txt`, because Windows Smart App Control blocked TensorFlow on the development machine.

## Scripts

Run from any directory, e.g. `python Probabilistic_Anomaly_Scoring/src/heldout_eval.py malmem`.

| Script | What it does | Output (`results/`) |
|---|---|---|
| `replicate_khalid.py` | Base paper's Isolation Forest and autoencoder on its exact MalMem subset | `replication/results.json` |
| `replicate_khalid_clustering.py` | Base paper's K-means, GMM and DBSCAN on all MalMem rows, then an audit: 5 seeds, one-feature and benign-vs-malware reference ARIs, no `svcscan.*`, no duplicates, DBSCAN parameter grid | `clustering/malmem.json` |
| `khalid_ae_other_datasets.py` | Same pipeline, unchanged, on CICIoT2023, Dumpware10, BODMAS | `replication/<dataset>.json` |
| `prove_imbalance.py` | Tests A–F: is class imbalance the problem? (no; scaling is) | `prove_imbalance/` |
| `scaled_on_paper_testset.py` | Scaled autoencoder on the paper's own test set | `replication/scaled_paper_testset.json` |
| `audit_malmem.py`, `audit_ciciot23.py`, `audit_bodmas.py`, `audit_dumpware10.py` | Dataset audits: duplicates, one-feature stumps, scale, time span, near-twin images | `audit/` |
| `protocol.py` | Shared protocol: de-duplication, 60/20/20 clean split, conformal p-values, metrics, baselines | (library) |
| `vae.py` | VAE (64-32-8-32-64) trained on clean rows; score = negative ELBO with z = mean | (library) |
| `heldout_eval.py` | Held-out evaluation of the autoencoder, VAE and Isolation Forest with conformal thresholds, baselines, per-family recall; `--drop svcscan`, `--drop window`, `--temporal`; `--detectors` retrains only the named detectors (none: baselines only) and keeps the rest | `heldout/` |
| `shap_audit.py` | SHAP of the autoencoder and VAE scores on flagged test malware: per feature (permutation SHAP) and per Volatility plugin / EMBER group (exact Shapley); shortcut share, agreement with the stump ranking, stability, agreement with the reconstruction-error reasons; `--drop svcscan`, `--drop window` | `shap/` |
| `shap_plots.py` | Standard SHAP plots of the autoencoder score: waterfall and force plots for a typical flagged artefact, beeswarm summary and bar plots over 200 flagged test malware | `shap/plots/` |
| `leave_one_family_out.py` | MalMem: supervised stump and Random Forest trained without one malware family, tested on it; with and without `svcscan.*` | `lofo/malmem.json` |
| `group_split.py` | Random vs hash-grouped splits for a supervised Random Forest on MalMem | `group_split/malmem.json` |
| `dumpware10_benign_only.py` | Can any benign-only detector separate Dumpware10 malware images? | `dumpware10/benign_only.json` |
| `triage_report.py` | Ranked triage list with score, p-value, SHAP reasons for flagged artefacts (reconstruction-error reasons kept for comparison), PR curve | `triage/` |
| `build_dataset_inventory.py` | Rebuilds `Datasets/inventory` and `Datasets/samples` | `Datasets/` |

## Evaluation protocol (`protocol.py`)

1. **Split.** Duplicate feature vectors are dropped. Clean rows are split 60/20/20 into train / calibrate / test with a fixed seed, so every model sees the same partitions. Malware is split 50/50 into rows that only the supervised stump baseline may see and test rows; on MalMem this split is grouped by the binary's SHA-256.
2. **Scaling and training.** A StandardScaler and the detectors are fitted on the clean training rows only.
3. **Conformal p-value.** For a score `s`, `p = (1 + #calibration scores ≥ s) / (n + 1)`. An artefact is flagged when `p ≤ 0.01`, which keeps false alarms on unseen clean data at about 1%.
4. **Metrics.** False-alarm rate and recall at that line, ROC-AUC, and precision / F1 / PR-AUC at the base paper's 20:1 clean:malware ratio (test malware is weighted to make up 1/21 of the test set). Baselines are "always clean", the best single-feature decision stump, and the squared distance from the clean training mean (no model, no labels), which is flagged with the same conformal line as the detectors.

## Results

### Held-out test, flagged at p ≤ 0.01

Autoencoder (AE) and VAE: mean of 5 seeds. Distance: the no-model baseline (squared distance from the clean training mean), which is deterministic.

| Dataset | Detector | False alarms on unseen clean | Recall | Precision (20:1) | F1 | ROC-AUC | PR-AUC | Best one-feature stump (F1) |
|---|---|---|---|---|---|---|---|---|
| CIC MalMem-2022 | AE | 0.92% | 1.000 | 0.845 | 0.916 | 0.999 | 0.977 | `svcscan.nservices` ≤ 390.5 (0.961) |
| | VAE | 0.88% | 0.991 | 0.850 | 0.915 | 0.998 | 0.952 | |
| | Distance | 0.84% | 0.523 | 0.757 | 0.619 | 0.990 | 0.756 | |
| MalMem without `svcscan.*` | AE | 0.87% | 0.991 | 0.851 | 0.916 | 0.999 | 0.959 | `handles.nmutant` ≤ 294.5 (0.847) |
| | VAE | 0.79% | 0.992 | 0.862 | 0.923 | 0.999 | 0.967 | |
| | Distance | 0.86% | 0.198 | 0.536 | 0.289 | 0.965 | 0.501 | |
| CICIoT2023 | AE | 0.89% | 0.971 | 0.845 | 0.903 | 0.993 | 0.979 | `Number` > 10.5 (0.983) |
| | VAE | 0.89% | 0.971 | 0.846 | 0.904 | 0.992 | 0.979 | |
| | Distance | 0.97% | 0.971 | 0.834 | 0.897 | 0.992 | 0.978 | |
| CICIoT2023 without window features | AE | 0.95% | 0.757 | 0.800 | 0.777 | 0.953 | 0.819 | `HTTPS` ≤ 0.097 (0.633) |
| | VAE | 0.91% | 0.624 | 0.774 | 0.691 | 0.950 | 0.765 | |
| | Distance | 0.98% | 0.553 | 0.738 | 0.632 | 0.947 | 0.706 | |
| BODMAS, random split | AE | 1.07% | 0.130 | 0.380 | 0.194 | 0.732 | 0.208 | `header.32` > −0.5 (0.231) |
| | VAE | 1.04% | 0.129 | 0.382 | 0.193 | 0.735 | 0.210 | |
| | Distance | 1.08% | 0.128 | 0.371 | 0.190 | 0.644 | 0.190 | |
| BODMAS, files first seen after Mar 2020 | AE | 0.84% | 0.154 | 0.480 | 0.234 | 0.713 | 0.223 | same (0.280) |
| | VAE | 0.84% | 0.156 | 0.482 | 0.235 | 0.716 | 0.224 | |
| | Distance | 0.91% | 0.154 | 0.459 | 0.230 | 0.601 | 0.206 | |

- "Always clean" scores accuracy 0.952 and F1 0 at 20:1.
- **VAE vs AE.** The VAE ties the AE at the 1% line on all three datasets, without MalMem's `svcscan.*` (recall 0.99) and on later BODMAS files (recall 0.16, false alarms 0.84%). On MalMem its PR-AUC is lower (0.952 vs 0.977) and varies more between seeds (0.917–0.974). The one clear gap is CICIoT2023 without window features, where the VAE catches less (recall 0.62 vs 0.76), close to the distance baseline (0.55).
- **Distance from the mean.** With no model at all, this score matches both networks on CICIoT2023 and, at the flag line, on BODMAS, so there the networks add nothing beyond "far from average". On MalMem they add a lot (recall 0.99 vs 0.52), and more once the shortcut features are dropped (MalMem 0.99 vs 0.20; CICIoT2023 0.76 vs 0.55).
- Isolation Forest is far weaker at the same line: recall 0.13 on MalMem, 0.37 on CICIoT2023, 0.00 on BODMAS.
- **MalMem families.** The autoencoder catches all 15 malware families (recall 1.00 each); without `svcscan.*`, 0.98–1.00 each. The base paper's own test malware covers only 2 families (Conti 1,155 rows, Ako 310).
- **CICIoT2023 attack classes.** Recall comes from floods. DNS spoofing, ARP spoofing, vulnerability scans and web attacks are caught at 0–9%. Dropping the five window-sensitive features costs 0.21 recall.
- **BODMAS over time.** Training before March 2020 and testing on later files did not raise false alarms (0.84% vs 1.15% on held-out older files). Recall stays low: worms 0.33, droppers 0.14, trojans 0.07, backdoors 0.00.
- **Old thresholds on held-out data.** The former "1% budget" (99th percentile of training error) gives 0.93–1.19% false alarms on unseen clean rows, and 1.57% on the BODMAS temporal split.

### SHAP audit: what do the explanations point at?

SHAP splits each flagged artefact's score into per-feature contributions, measured against 100 clean calibration rows. This covers 300 flagged test malware rows per detector and seed (42 and 1), with the same splits and models as above. Shares are averaged per artefact, so every artefact counts equally. BODMAS uses exact Shapley values over its 9 feature groups.

| Dataset | Largest reason for a flagged artefact (AE; VAE) | Share to the known shortcut | Spearman ρ with the stump ranking |
|---|---|---|---|
| CIC MalMem-2022 | `svcscan` plugin: 86% of dumps; 65–82% | `svcscan.*` 37–38%; 32% | 0.85–0.88 |
| MalMem without `svcscan.*` | `handles` plugin, home of the next-best stump `handles.nmutant`: 38–74%; 76–82% | – | 0.81–0.84 |
| CICIoT2023 | `Number` (packet-window size): 99% of flows; 99–100% | window features 97–98% | 0.37–0.56 |
| CICIoT2023 without window features | `syn_count`, `ack_count`, `rst_count`, `ICMP` (flood and scan signals); the best stump, `HTTPS`, ranks 9th–17th | – | 0.33–0.61 |
| BODMAS (9 groups) | `byte_entropy_histogram`: 66–70% of files; 67% | no shortcut | −0.15 (best stump group, `header`, ranks 8th of 9) |

- **Where a lab shortcut exists, SHAP reports it as the main reason.** That's MalMem's running-services count and CICIoT2023's packet-window size, so an examiner reading these explanations would be reading a quirk of how the dataset was recorded. Without the shortcut, MalMem's explanations move to the plugin of the next-best stump, while CICIoT2023's move to plausible attack signals rather than the next stump. On BODMAS, which has no shortcut, they point to byte entropy (packed or encrypted content).
- **Pooled averages mislead.** Averaging |SHAP| over all artefacts gives 98% to `malfind.commitCharge` on MalMem and 100% to `data_directories` on BODMAS, driven by a few extreme values.
- **Stability.** Rankings agree between seeds and between AE and VAE at ρ 0.74–0.95 per feature (per MalMem plugin, down to 0.65). On BODMAS they are identical (ρ 1.00), consistent with both networks measuring distance from the mean there.
- **Reconstruction-error reasons vs SHAP.** The largest per-feature reconstruction errors share only 0–43% of SHAP's top 3 on MalMem and CICIoT2023, but 84–88% on BODMAS. The triage report therefore gives SHAP reasons for flagged artefacts and keeps the error reasons alongside for comparison.
- **Checks.** On the distance baseline, whose exact SHAP values are known, both methods are exact (error ≤ 10⁻¹³). Contributions add up to each score (relative error ≤ 4 × 10⁻⁷).
- **Plots.** `results/shap/plots/` has the standard SHAP views of the autoencoder score for each dataset: waterfall and force plots for the median-scoring flagged artefact, and beeswarm and bar plots over 200 flagged test malware. The global plots scale each artefact's values by its total |SHAP|, for the reason above. For a typical flagged MalMem dump the largest contribution is `svcscan.shared_process_services`.
- **Leave one family out (MalMem).** A supervised stump and a Random Forest, each trained without one of the 15 families, still catch that family (recall 0.975–1.00, false alarms ≤ 0.4%). The stump picks `svcscan.nservices` in all 15 folds, so the shortcut is not tied to any family: it comes from how the lab captured the dumps. Without `svcscan.*`, the stump picks `handles.nmutant` in 14 of 15 folds (recall 0.64 on TIBS, 0.97–1.00 on the rest) and the Random Forest still catches every family (≥ 0.976). The clean-only autoencoder never sees malware, so every family is already unseen for it: recall 1.00 per family, and 0.98–1.00 without `svcscan.*`.

### Clustering: the base paper's second experiment

The paper clusters all 58,596 standardised MalMem rows without labels, then scores the clusters against the labels with the Adjusted Rand Index (ARI: 1 = clusters match the labels exactly, 0 = chance). Following the authors' notebooks reproduces all four ARIs exactly.

| Model (labels scored against) | Paper | Replication | 5 seeds | Reference point | Without `svcscan.*` |
|---|---|---|---|---|---|
| K-means, k = 2 (benign / malware) | 0.7544 | 0.7544 | 0.7544 every seed | K-means on `svcscan.nservices` alone: **0.985** | 0.747 |
| GMM, 2 components (benign / malware) | 0.9592 | 0.9592 | 0.959 ×3, 0.51, **0.00** (mean 0.68) | same | 0.959 every seed |
| GMM, 4 components (benign + 3 types) | 0.6449 | 0.6449 | 0.61–0.67 | a perfect benign/malware split with no type information: **0.667** | 0.61–0.64 |
| DBSCAN, eps 2.3, min_samples 190 (benign + 15 families) | 0.5690 | 0.5690 (9 clusters) | deterministic | a perfect benign/malware split: **0.534** | **0.088** |

- **The "multivariate" clusterings do not find malware types or families.** GMM-4 puts most rows of all three malware types into one cluster (7,553–8,351 rows each), and DBSCAN puts most rows of every family into one cluster. Both score about as well as a split that only separates benign from malware.
- **One feature beats every model.** Two-cluster K-means on `svcscan.nservices` alone, still with no labels, reaches ARI 0.985, above the paper's best (GMM-2, 0.959).
- **GMM-2's 0.96 depends on the seed.** Seed 42 gives 0.959. Of four other seeds, two give 0.959, one 0.51 and one 0.00 (the clusters ignore the class). Benign/malware structure itself is real: without `svcscan.*`, GMM-2 still reaches 0.959 on every seed.
- **DBSCAN's settings were picked against the labels.** Over a 5 × 4 grid around the paper's values (eps 1.5–3.0, min_samples 50–300), only 3 of 20 settings exceed 0.5. At the same eps 2.3, min_samples 100 gives 0.09. The paper tuned these by random search scored with ARI, which needs the labels the method is meant to work without. Without `svcscan.*`, DBSCAN falls to 0.088.
- Removing the 569 duplicate rows moves K-means, GMM-2 and DBSCAN by less than 0.01 at seed 42. GMM-4 drops to 0.52 at seed 42 (0.52–0.70 over seeds).
- DBSCAN runs through a chunked implementation that returns sklearn's labels exactly (checked on subsamples at four settings), because the full neighbour lists (about 370 million pairs) did not fit in memory.

### Audits and splits

| Finding | Value | Source |
|---|---|---|
| MalMem duplicate records / duplicate feature vectors | 534 / 569 | `audit/malmem.json` |
| MalMem best one-feature rule (`svcscan.nservices`) | 99.66% (majority 50%) | `audit/malmem.json` |
| MalMem clean rows with fractional values in count features (SMOTE trace) | 0 of 29,298 | `audit/malmem.json` |
| CICIoT2023 rows repeating an earlier flow, all 63 merged files | 53.5% (25.2 M of 47.0 M); clean 0.4%, the ten TCP / UDP / ICMP / SYN flood classes 42–73% | `audit/ciciot23.json` |
| CICIoT2023 best stump, Merged01 | accuracy 97.95% vs 97.67% "always attack"; `Number` alone 98.7% balanced accuracy | `audit/ciciot23.json` |
| BODMAS best one-feature rule | 78.4% (majority 57.4%) | `audit/bodmas.json` |
| Dumpware10 test images with a near-twin in training (≤ 5 of 256 hash bits) | 35.3% | `audit/dumpware10.json` |
| Dumpware10 no-learning nearest-hash rule | 81.0% | `audit/dumpware10.json` |
| Dumpware10 benign-only detectors, malware caught at 1% false alarms | ≤ 5.2% (supervised ROC-AUC 0.982) | `dumpware10/benign_only.json` |
| MalMem Random Forest, random vs hash-grouped 5-fold | macro-F1 −4.0 points at 4 classes, −8.7 at 16 classes; binary unchanged | `group_split/malmem.json` |

The triage reports for MalMem and CICIoT2023 are in `Probabilistic_Anomaly_Scoring/results/triage/` (`<dataset>_report.md`); BODMAS's are git-ignored because they list per-file values.
