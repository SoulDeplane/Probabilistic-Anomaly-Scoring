# Comparative Analysis: Base Paper and Present Work

| | |
|---|---|
| **Project** | Probabilistic Anomaly Scoring for Explainable Digital Forensic Triage |
| **Base paper** | Z. Khalid, F. Iqbal and M. Saqib, "Bridging knowledge gaps in digital forensics using unsupervised explainable AI," *Forensic Sci. Int.: Digital Investigation*, vol. 53, 301924, 2025 |


---

## 1. Summary

The base paper applies Isolation Forest and an autoencoder to CIC MalMem-2022 and reports accuracies of 0.8595 and 0.9759. We reproduced both results, then re-evaluated the models on unseen data, with a fixed false-alarm rate, full metrics and three datasets.

1. **Replication.** Isolation Forest 0.8607 vs 0.8595; autoencoder 0.957–0.973 vs 0.9759.
2. **Accuracy overstates performance.** Labelling every item clean already scores 0.952. Behind the paper's 0.976 are 716 false alarms and a precision of 0.668.
3. **Two corrections.** Feature scaling and a 1% false-alarm threshold cut false alarms by 59% and raise F1 from 0.796 to 0.91.
4. **Generalisation.** On unseen data, false alarms stay at 0.92% and all 15 malware families are detected. The paper tested 2 families.
5. **Other evidence types.** With our corrections, F1 is 0.90 on network traffic (CICIoT2023) but 0.19 on Windows executables (BODMAS).
6. **Variational autoencoder.** A VAE matches the autoencoder on all three datasets. A model-free distance-from-the-mean score matches both on CICIoT2023 and BODMAS.
7. **Explanations.** A SHAP audit shows that the explanations name each dataset's laboratory shortcut as the main reason for flagging an item.

---

## 2. Methodology

| | Base paper | Present work |
|---|---|---|
| Datasets | CIC MalMem-2022 | MalMem-2022, CICIoT2023, BODMAS |
| Models | Isolation Forest, autoencoder | Isolation Forest, autoencoder, variational autoencoder, model-free distance baseline |
| Test data | Training rows reused; 2 of 15 malware families | Unseen rows; all malware families |
| Preprocessing | No scaling for anomaly detection; duplicates retained | Scaling; duplicates removed |
| Threshold | Mean + 3σ of training error | Conformal p-value at a 1% false-alarm rate |
| Metrics | Accuracy only | False-alarm rate, recall, precision, F1, ROC-AUC, PR-AUC |
| Baselines and runs | None; one run | All-clean and single-feature baselines; five seeds |
| Explainability | SHAP, not validated | SHAP, checked against a case with known answers and audited against single-feature rules |

---

## 3. Results

### 3.1 The base paper's test set (MalMem-2022)

| Model | Accuracy | Precision | Recall | F1 | False alarms |
|---|---|---|---|---|---|
| All-clean baseline | 0.952 | – | 0.000 | 0.000 | 0 |
| Isolation Forest, paper | 0.8595 | 0.253 | 1.000 | 0.404 | ≈4,320 |
| Isolation Forest, replication | 0.8607 | 0.255 | 1.000 | 0.406 | 4,286 |
| Autoencoder, paper | 0.9759 | 0.668 | 0.984 | 0.796 | 716 |
| Autoencoder, replication | 0.957–0.973 | 0.54–0.64 | 0.64–1.00 | 0.59–0.78 | 737–829 |
| **Autoencoder, present work** | **0.990** | **0.833** | **0.993–1.000** | **0.906–0.909** | **293** |

The paper reports accuracy only; its other figures are derived from its confusion matrix.

### 3.2 Unseen data (autoencoder, 1% false-alarm threshold)

| Dataset | False alarms | Recall | Precision | F1 | ROC-AUC | Paper pipeline F1 |
|---|---|---|---|---|---|---|
| MalMem-2022 | 0.92% | 1.000 | 0.845 | 0.916 | 0.999 | 0.71 |
| CICIoT2023 | 0.89% | 0.971 | 0.845 | 0.904 | 0.993 | 0.14 |
| BODMAS | 1.07% | 0.130 | 0.380 | 0.194 | 0.732 | 0.01 |

Precision and F1 are computed at the paper's ratio of 20 clean items per malware item. "Paper pipeline F1" is the paper's method applied unchanged.

### 3.3 Robustness

| Check | Result |
|---|---|
| Stability across seeds | F1 varies 0.59–0.78 with the paper's method and 0.906–0.909 with ours |
| False-alarm control | The paper's threshold gives 0.31–1.95% depending on the dataset; ours stays at 0.84–1.15% |
| Class imbalance | Rebalancing, SMOTE and undersampling do not raise recall; feature scaling is the decisive factor |
| Single-feature shortcut | One feature (`svcscan.nservices`) separates MalMem at 99.66%; removing all `svcscan` features leaves our F1 unchanged at 0.916 |
| Over time (BODMAS) | False alarms stay at 0.84% on files newer than the training data |

### 3.4 Variational autoencoder and distance baseline (unseen data, 1% false-alarm threshold)

| Dataset | Autoencoder F1 | VAE F1 | Distance-from-mean F1 |
|---|---|---|---|
| MalMem-2022 | 0.916 | 0.915 | 0.619 |
| CICIoT2023 | 0.903 | 0.904 | 0.897 |
| BODMAS | 0.194 | 0.193 | 0.190 |

The VAE also matches the autoencoder without the `svcscan` features and on newer BODMAS files. It trails only on CICIoT2023 without its packet-window features (recall 0.62 vs 0.76).

### 3.5 SHAP audit

| Dataset | Main reason given for flagged items | Agreement with single-feature rules |
|---|---|---|
| MalMem-2022 | `svcscan` (laboratory artefact), for 86% of items | Spearman ρ 0.85–0.88 |
| MalMem-2022 without `svcscan` | `handles`, the next-best single-feature rule | ρ 0.81–0.84 |
| CICIoT2023 | `Number` (packet-window size), for 99% of items | – |
| CICIoT2023 without window features | SYN, ACK and RST counts (attack traffic) | – |
| BODMAS | Byte entropy (packed or encrypted files) | No shortcut exists |

---

## 4. Qualitative Assessment

### 4.1 Strengths of the base paper

- Makes the case for unsupervised learning in forensics, where seized evidence is unlabelled.
- Applies SHAP explanations to unsupervised models.
- Covers both anomaly detection and clustering.
- Publishes its code, which made exact replication possible.

### 4.2 Limitations identified and our response

| Limitation in the base paper | Response in the present work |
|---|---|
| Accuracy is the only metric | Full metric set with baselines |
| Evaluated on training data | Held-out test split |
| Test malware from 2 of 15 families | All 15 families |
| No feature scaling | Scaling fitted on clean training data |
| Unstable threshold | Fixed 1% false-alarm rate |
| One dataset, one run | Three datasets, five seeds |
| SHAP output not validated | SHAP audit: explanations compared with single-feature rules and with models retrained without the shortcut features |

### 4.3 Explainability

The paper's SHAP analysis highlights `svcscan` features. Our dataset audit shows that these separate the classes almost perfectly because of the laboratory setup rather than malicious behaviour. Our SHAP audit confirms the effect: SHAP names `svcscan` as the main reason for 86% of flagged MalMem items, and the packet-window size for 99% of flagged CICIoT2023 items. When those features are removed, the explanations move to the next-best shortcut on MalMem and to genuine attack traffic on CICIoT2023. The paper's explanations therefore largely describe the capture environment.

---

## 5. Limitations and Remaining Work

**Limitations**
- A single-feature rule still outperforms our autoencoder on MalMem and CICIoT2023.
- BODMAS remains largely unsolved (F1 0.19).
- The VAE brings no detection gain over the autoencoder, and on CICIoT2023 and BODMAS neither network beats a model-free distance score.
- Where a dataset contains a laboratory shortcut, explanations report that shortcut rather than malware behaviour.
- The paper's clustering experiments were not replicated.

**Remaining work**
- Replication of the paper's clustering experiments.
