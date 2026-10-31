# Comparative Analysis: Base Paper and Present Work

| | |
|---|---|
| **Project** | Probabilistic Anomaly Scoring for Explainable Digital Forensic Triage (MP2026CSE75, Dept. of CSE, Graphic Era Deemed to be University) |
| **Base paper** | Z. Khalid, F. Iqbal and M. Saqib, "Bridging knowledge gaps in digital forensics using unsupervised explainable AI," *Forensic Sci. Int.: Digital Investigation*, vol. 53, 301924, 2025 |
| **Date** | 31 October 2026 |

Figures for the present work are means over five random seeds unless stated otherwise. Sources are listed in Section 7.

---

## 1. Summary

The base paper applies Isolation Forest and an autoencoder to CIC MalMem-2022 and reports accuracies of 0.8595 and 0.9759. We reproduced both results, then re-evaluated the same models under a stricter protocol: unseen test data, a fixed false-alarm rate, a full set of metrics, and three datasets.

1. **Replication.** Isolation Forest 0.8607 vs 0.8595; autoencoder 0.957–0.973 vs 0.9759.
2. **Accuracy overstates performance.** Labelling every item clean already scores 0.952. Behind the paper's 0.976 are 716 false alarms and a precision of 0.668.
3. **Two corrections.** Feature scaling and a 1% false-alarm threshold cut false alarms by 59% (716 → 293) and raise F1 from 0.796 to 0.91 on the paper's own test set.
4. **Generalisation to unseen data.** False alarms stay at 0.92% and recall is 1.00 for all 15 malware families. The paper tested 2 families.
5. **Other evidence types.** The paper's pipeline, applied unchanged, fails on network traffic and Windows executables. With our corrections, F1 is 0.90 on CICIoT2023 but only 0.19 on BODMAS.

---

## 2. Methodology

| | Base paper | Present work |
|---|---|---|
| Datasets | CIC MalMem-2022 | MalMem-2022, CICIoT2023, BODMAS (Dumpware10 audited only) |
| Models | Isolation Forest, autoencoder; K-means, DBSCAN, GMM | Isolation Forest, autoencoder; VAE in progress |
| Test data | Clean training rows reused; malware from 2 of 15 families | Unseen clean rows (60/20/20 split); malware from all families |
| Preprocessing | No scaling for anomaly detection; duplicates retained | Scaling fitted on clean training data; 569 duplicates removed; malware split by binary hash |
| Threshold | Mean + 3σ of training error | Conformal p-value; flag at p ≤ 0.01 |
| Metrics | Accuracy; ARI for clustering | False-alarm rate, recall, precision, F1, ROC-AUC, PR-AUC, per-family recall |
| Baselines | None | All-clean; best single-feature rule |
| Runs | One | Five seeds |
| Explainability | SHAP (local and global plots) | Per-feature reconstruction error; SHAP audit in progress |
| Temporal test | None | BODMAS: trained before, tested after March 2020 |

---

## 3. Quantitative Results

### 3.1 The base paper's test set (MalMem-2022, 30,763 rows)

| Model | Accuracy | Precision | Recall | F1 | False alarms | Missed |
|---|---|---|---|---|---|---|
| All-clean baseline | 0.952 | – | 0.000 | 0.000 | 0 | 1,465 |
| Isolation Forest, paper | 0.8595 | 0.253 | 1.000 | 0.404 | ≈4,320 | 0 |
| Isolation Forest, replication | 0.8607 | 0.255 | 1.000 | 0.406 | 4,286 | 0 |
| Autoencoder, paper | 0.9759 | 0.668 | 0.984 | 0.796 | 716 | 23 |
| Autoencoder, replication (5 seeds) | 0.957–0.973 | 0.54–0.64 | 0.64–1.00 | 0.59–0.78 | 737–829 | 0–524 |
| **Autoencoder, scaled + 1% threshold (3 seeds)** | **0.990** | **0.833** | **0.993–1.000** | **0.906–0.909** | **293** | **0–10** |

The paper reports accuracy only. Its precision, recall and F1 are derived from its confusion matrix (Fig. 2b).

### 3.2 Held-out evaluation (autoencoder, p ≤ 0.01)

| Dataset | False alarms | Recall | Precision* | F1* | ROC-AUC | PR-AUC* | Paper pipeline F1† |
|---|---|---|---|---|---|---|---|
| MalMem-2022 | 0.92% | 1.000 | 0.845 | 0.916 | 0.999 | 0.977 | 0.71 |
| CICIoT2023 | 0.89% | 0.971 | 0.845 | 0.904 | 0.993 | 0.979 | 0.14 |
| BODMAS | 1.07% | 0.130 | 0.380 | 0.194 | 0.732 | 0.208 | 0.01 |
| BODMAS, files after Mar 2020 | 0.84% | 0.154 | 0.480 | 0.234 | 0.713 | 0.223 | – |

\* At the paper's ratio of 20 clean items per malware item.
† The paper's unscaled pipeline applied unchanged; on MalMem, evaluated on its own test set.

Isolation Forest under the same protocol reaches recall of only 0.13 (MalMem), 0.37 (CICIoT2023) and 0.00 (BODMAS).

### 3.3 Robustness checks

| Check | Result |
|---|---|
| Stability across seeds (paper's test set, F1) | Paper method 0.59–0.78; scaling alone 0.35–0.98; scaling + 1% threshold 0.906–0.909 |
| False-alarm control on unseen data | Paper threshold: 0.07–0.65% on MalMem, 1.46% on BODMAS, 1.95% on newer BODMAS files. Conformal threshold: means of 0.84–1.15% on every dataset. The paper's threshold scores a higher F1 on MalMem (0.956), but nobody chooses its false-alarm rate in advance |
| Class imbalance | Rebalancing and SMOTE did not raise recall; undersampling lowered MalMem recall from 0.80 to 0.13. Scaling is the decisive factor |
| Single-feature shortcut, MalMem | `svcscan.nservices` alone is 99.66% accurate (clean dumps show 392 or 395 services, malware dumps 389). Removing all 7 `svcscan` features leaves autoencoder F1 at 0.916 |
| Window-size features, CICIoT2023 | Removing 5 features lowers recall from 0.97 to 0.76 |
| Per-family recall | MalMem: 1.00 for all 15 families. CICIoT2023: floods 1.00; spoofing, scans and web attacks 0–9%. BODMAS (newer files): worms 0.33, trojans 0.07, backdoors 0.00 |
| Hash-grouped split (supervised Random Forest) | Accuracy 87.4% → 84.7% (4 classes) and 75.2% → 70.7% (16 classes). The random-split figures match those the paper cites from Öztürk & Hizal (87.79%, 75.49%) |
| Triage example (MalMem: 6,139 items, 292 malware) | 349 items flagged, including all 292 malware; the examiner reviews 5.7% of the batch |

---

## 4. Qualitative Assessment

### 4.1 Contributions of the base paper

- Makes the case for unsupervised learning in forensics, where seized evidence carries no labels.
- Applies SHAP explanations to unsupervised anomaly detection and clustering.
- Covers clustering at three levels of detail (binary GMM: ARI 0.9592).
- Publishes its code, which made an exact replication possible.

### 4.2 Limitations identified and our response

| Limitation in the base paper | Consequence | Response in the present work |
|---|---|---|
| Accuracy is the only metric | Hides 716 false alarms and a precision of 0.668 | Full metric set with baselines |
| Evaluated on training data | No evidence that results hold on new evidence | Held-out 60/20/20 split |
| Test malware from 2 of 15 families | Spyware and trojans never tested | All families; per-family recall |
| No feature scaling | Pipeline fails on other datasets | Scaling fitted on clean training data |
| Mean + 3σ threshold | Recall ranges from 0.64 to 1.00 across seeds | Conformal threshold at a fixed 1% false-alarm rate |
| One dataset, one run | Reliability and generality unknown | Three datasets, five seeds, a temporal test |
| Duplicates and repeated dumps ignored | Multi-class scores inflated | Duplicates removed; hash-grouped split |
| SHAP output not validated | Explanations may reflect the capture setup | Shortcut ablations; SHAP audit in progress |

### 4.3 Explainability

The paper's SHAP analysis names `svcscan.process_services` as a leading feature for K-means and notes a clear separation in its values. Our audit shows that three `svcscan` features each separate the classes at about 99.6% on their own, a pattern consistent with the laboratory configuration rather than with malicious behaviour. Part of what the paper's explanations describe is therefore likely the capture environment. The planned SHAP audit will test this directly.

---

## 5. Limitations of the Present Work

- A supervised single-feature rule still outperforms the autoencoder on MalMem (F1 0.961 vs 0.916) and CICIoT2023 (0.983 vs 0.904).
- BODMAS remains largely unsolved: F1 0.19–0.23, ROC-AUC 0.73.
- Dumpware10 was excluded from modelling: detectors trained on clean images alone caught at most 5.2% of malware at 1% false alarms.
- The temporal test covers one dataset and about seven months.
- The paper's clustering experiments were not replicated.

## 6. Remaining Work

- **Variational autoencoder:** compare with the autoencoder on PR-AUC and on recall at 1% false alarms.
- **SHAP audit:** compare SHAP feature rankings with single-feature rankings; on BODMAS, sum SHAP values per feature group.

---

## 7. Sources

| Content | File |
|---|---|
| Base paper | `Research Papers/1-s2.0-S2666281725000630-main.pdf` (Table 1, Fig. 2b) |
| Replication; transfer to other datasets | [results/replication/](../Probabilistic_Anomaly_Scoring/results/replication/) |
| Scaled model on the paper's test set | [results/replication/scaled_paper_testset.json](../Probabilistic_Anomaly_Scoring/results/replication/scaled_paper_testset.json) |
| Held-out, per-family and temporal results | [results/heldout/](../Probabilistic_Anomaly_Scoring/results/heldout/) |
| Class-imbalance tests | [results/prove_imbalance/](../Probabilistic_Anomaly_Scoring/results/prove_imbalance/) |
| Dataset audits | [results/audit/](../Probabilistic_Anomaly_Scoring/results/audit/) |
| Hash-grouped split | [results/group_split/malmem.json](../Probabilistic_Anomaly_Scoring/results/group_split/malmem.json) |
| Dumpware10 clean-only detectors | [results/dumpware10/benign_only.json](../Probabilistic_Anomaly_Scoring/results/dumpware10/benign_only.json) |
| Triage report | [results/triage/malmem_report.md](../Probabilistic_Anomaly_Scoring/results/triage/malmem_report.md) |
