# Probabilistic Anomaly Scoring for Explainable Digital Forensic Triage: Study Guide

*Team MP2026CSE75 · Dept. of CSE, Graphic Era Deemed to be University · updated 10 November 2026*

**Contents:** [1. The project](#1-the-project) · [2. Reading results](#2-reading-results) · [3. Done so far](#3-done-so-far) · [4. To change](#4-to-change) · [5. How to finish](#5-how-to-finish) · [6. Explaining it](#6-explaining-it) · [7. Papers reviewed](#7-papers-reviewed) · [8. Results side by side](#8-results-side-by-side)

---

## 1. The project

**Problem.** Examiners seize far more data than they can read, so they must decide what to examine first. That is **triage**.

**Goal.** Give every artefact (memory dump, executable file, network flow) a score for how unusual it is compared with clean data. The score should have a probability meaning and say which features drove it.

**Approach.** Train **only on clean data**. At seizure there are no labels, and new malware families are unknown by definition.

| Term | One-line meaning |
|---|---|
| Autoencoder (AE) | Network that compresses and rebuilds its input; a large rebuild error means unusual |
| Threshold | Cut-off that turns a score into a flag; the base paper uses mean + 3 std of training errors |
| VAE (Focus 1) | Probabilistic autoencoder; its score (negative ELBO) approximates −log P(clean) |
| Isolation Forest | Flags points that random splits isolate quickly |
| SHAP (Focus 2) | Splits a score into per-feature contributions |
| Conformal threshold | Flag line set on held-out clean data, so false alarms stay at a chosen rate |

**Base paper.** Khalid, Iqbal & Saqib (2025), *FSI: Digital Investigation* 53, 301924. They used CIC MalMem-2022: all 29,298 clean rows plus the first 5% of malware (1,465). Isolation Forest scored 0.8595 accuracy and the autoencoder 0.9759.

| Dataset | One sample | Size | Role |
|---|---|---|---|
| CIC MalMem-2022 | Memory dump, 55 features | 58,596 | Main (base paper's) |
| CICIoT2023 | Network-traffic window, 39 features | 47 million | Network evidence |
| BODMAS | Windows executable, 2,381 features, first-seen date | 134,435 | Executable evidence; replaced Dumpware10 for modelling |
| Dumpware10 | Memory dump drawn as an image | 4,294 | Duplicate audit only |

## 2. Reading results

| | Predicted clean | Predicted malware |
|---|---|---|
| Actually clean (29,298) | 28,509 | 789 false alarms |
| Actually malware (1,465) | 524 missed | 941 caught |

- **Accuracy** = all correct ÷ all = 95.7%
- **Precision** = caught ÷ flagged = 941 / 1,730 = 54%
- **Recall** = caught ÷ all malware = 941 / 1,465 = 64%
- **F1** = balance of precision and recall = 0.59
- **PR-AUC / ROC-AUC** rate the score across all thresholds. ROC-AUC 0.5 is a coin flip and 1.0 is perfect.

**Accuracy trap.** Calling everything clean scores **95.2%** and catches nothing. The base paper reported accuracy only (97.6%), which hid a precision of 0.668.

**One-feature shortcut.** The rule "`svcscan.nservices` ≤ 390 means malware" is right **99.66%** of the time on MalMem. Clean dumps show 392 or 395 running services and malware dumps 389. That's a difference in how the lab machines were set up, not malware behaviour. Checking whether SHAP explanations just describe such quirks is the project's most original idea.

## 3. Done so far

Commits on GitHub: `0ac8933`, `3f63fb9`, `4a8bb80`, `b5b3036`, `50df781`, `5546de5`, `714ccba`, `49f6a04`.

1. **Audit and repair.**
   - MalMem: the partial local copy was replaced with the official file.
   - CICIoT2023: 12 truncated files rebuilt.
   - Dumpware10: complete.
   - BODMAS: clean.
2. **Base paper replicated** (`src/replicate_khalid.py`).
   - Isolation Forest: 0.8607 accuracy vs the paper's 0.8595 ✔.
   - Autoencoder: 0.957–0.973 vs 0.976, but recall swings 0.64–1.00 across 5 seeds.
3. **Pipeline moved unchanged to the other datasets** (`src/khalid_ae_other_datasets.py`). It fails on all three:
   - CICIoT recall 0.08, Dumpware10 0.00, BODMAS 0.007; none beats "always clean".
   - Cause: huge unscaled features (CICIoT `Rate` up to 3.1 × 10⁶, BODMAS compile timestamp up to 4.3 × 10⁹). On Dumpware10, the malware and clean images simply don't separate.
4. **Class-imbalance tests A–F** (`src/prove_imbalance.py`).
   - Imbalance is never the cause.
   - Scaling plus a 1% false-alarm budget brings F1 to **0.91 on MalMem, 0.90 on CICIoT, but 0.21 on BODMAS**.
5. **MalMem, the paper's exact test set:** false alarms fall from 716 to 293 and F1 rises from 0.796 to 0.91.
6. **Dumpware10 dropped from modelling.**
   - Detectors trained on clean images only caught ≤5% of malware at 1% false alarms, even with ImageNet features, although a supervised model reaches 0.98 AUC.
   - 35% of its test images have a near-twin in training, and a no-learning rule scores 81%.
7. **BODMAS added** (`src/audit_bodmas.py`).
   - Clean data with timestamps for both classes; the best one-feature rule reaches only 78.4%.
   - On clean files the model never saw, false alarms stayed at 1.0–1.2%, and detectors caught 12–13% of malware (ROC-AUC ≤ 0.80).
8. **Held-out re-test** (`src/protocol.py`, `src/heldout_eval.py`, 5 seeds).
   - Duplicates dropped; clean rows split 60/20/20 into train / calibrate / test; the threshold is the conformal p ≤ 0.01 from the calibration rows.
   - False alarms on unseen clean rows: 0.92% on MalMem (F1 0.92) and 0.89% on CICIoT (F1 0.90). **The 1%-budget results survive.**
9. **Per-family recall.**
   - MalMem: all 15 families caught (1.00 each), including the paper's Conti and Ako.
   - CICIoT: recall comes from floods. Spoofing, scans and web attacks are caught at 0–9%.
10. **Shortcut tests.**
    - MalMem without `svcscan.*`: F1 still 0.92, so the model does not depend on that quirk.
    - CICIoT without `Number`, `Tot sum`, `IAT`, `Variance`, `Rate`: recall falls 0.97 → 0.76.
    - A one-feature rule matches or beats the autoencoder on both: `svcscan.nservices` F1 0.96, `Number` F1 0.98.
11. **BODMAS by date** (train before March 2020, test after): false alarms on newer clean files 0.84%, recall 0.15. No drift in false alarms over seven months.
12. **Hash-grouped split** (`src/group_split.py`): a Random Forest loses 4.0 macro-F1 points at 4 classes and 8.7 at 16 classes. Binary is unaffected.
13. **Audits** (`src/audit_malmem.py`, `src/audit_ciciot23.py`, Dumpware10 scripts saved in `src/`).
    - CICIoT: 53.5% of all 47 M rows repeat an earlier flow, mostly floods.
    - MalMem: no clean row shows SMOTE-style fractional values.
14. **Triage report** (`src/triage_report.py`): ranked list with score, p-value, top reconstruction-error features and a precision–recall curve (`results/triage/`).
15. **VAE** (`src/vae.py`; 64 → 32 → 8-d mean and log-variance → 32 → 64; score = negative ELBO with z = mean).
    - Ties the autoencoder: F1 0.92 / 0.90 / 0.19 on MalMem / CICIoT / BODMAS; also without `svcscan.*` (recall 0.99) and on later BODMAS files (0.16).
    - Trails only on CICIoT without window features: recall 0.62 vs 0.76.
    - Run in WSL2 (Ubuntu), because Windows Smart App Control blocked TensorFlow.
16. **Distance-from-the-mean baseline** (`protocol.distance_score`, no model). It matches both networks on CICIoT (F1 0.90) and BODMAS (0.19), but not on MalMem (0.62 vs 0.92). So on two datasets the networks only measure "far from average".
17. **SHAP audit** (`src/shap_audit.py`; 300 flagged malware per model and seed).
    - The explanations name the shortcut: `svcscan` is the top reason for 86% of flagged MalMem dumps, `Number` for 99% of CICIoT flows.
    - Without the shortcut, MalMem moves to `handles` (the next-best stump's plugin) and CICIoT to SYN/ACK/RST counts. BODMAS points to byte entropy.
    - Checked on the distance baseline, whose exact SHAP values are known.
18. **Triage report uses SHAP** for its top reasons (`src/triage_report.py`); the reconstruction-error reasons are kept for comparison.
19. **Writeups and repository.**
    - Synopsis (renamed from "Synposis") and slides switched to BODMAS; Fig. 4.1 and the slide-11 image redrawn.
    - 10 references fixed or added; 15 s interval and SMOTE claim sourced (Carrier et al., p. 184); typos fixed.
    - `requirements.txt`, a real README, `X_scaled` renamed.

## 4. To change

1. ✔ **Built:** the VAE (Step 4), the SHAP audit (Step 5) and SHAP reasons in the triage report (Step 7).
2. ✔ **Dataset switch:** Dr. Rehan's approval for the revised synopsis and slides.
3. ✔ **Check the redrawn figures:** synopsis Fig. 4.1 and the slide-11 pipeline image.
4. ✔ **Prawiranata & Hadiprakoso:** downloaded through college IEEE access.
5. **Corrected facts; use these from now on:**
   - CICIoT's 97.96% one-feature rule is barely above "always attack" (97.67%). The real shortcut is `Number` (the packet-window size), at 98.7% balanced accuracy.
   - CICIoT duplicates are 53.5% of rows, not 5%.
   - MalMem has 534 duplicate records but 569 duplicate feature vectors; 569 are dropped.
   - 8 of the synopsis's 20 references were wrong, not only [16].

## 5. How to finish

| Step | What | Key detail |
|---|---|---|
| 1 ✔ | Proper split | Clean rows 60/20/20 = train / calibrate / test; drop duplicates; fit the scaler on train only |
| 2 ✔ | Full metrics | Add PR-AUC (`average_precision_score`) plus majority and stump baselines; 5 seeds |
| 3 ✔ | Conformal threshold | p = (1 + calibration scores ≥ s) / (n + 1); flag if p ≤ 0.01 |
| 4 ✔ | VAE | 55 → 64 → 32 → 8-d mean and log-variance → 32 → 64 → 55; score = reconstruction + KL; compare with the AE on PR-AUC and recall at 1% (`src/vae.py`). Result: ties the AE (recall 0.99 / 0.97 / 0.13, PR-AUC 0.95 / 0.98 / 0.21 on MalMem / CICIoT / BODMAS), also without `svcscan.*` (0.99) and on later BODMAS files (0.16). Behind it only on CICIoT without window features (0.62 vs 0.76). A no-model distance-from-the-mean score matches both on CICIoT and BODMAS |
| 5 ✔ | SHAP audit | Explain the deterministic score; compare with the stump ranking (`src/shap_audit.py`). Drop `svcscan.*` and retrain ✔, per-family recall ✔, BODMAS per feature group (exact Shapley) ✔. Result: SHAP names the shortcut as the main reason (`svcscan` for 86% of flagged MalMem dumps, `Number` for 99% of CICIoT flows; ρ 0.85–0.88 with the stump ranking on MalMem). Without it, explanations move to the next-best stump's plugin (MalMem `handles`) or to flood signals (CICIoT). BODMAS: byte entropy, no shortcut |
| 6 ✔ | Other datasets | CICIoT: retrain without `Number`, `Tot sum`, `IAT`, `Variance`, `Rate`, and measure duplicates. BODMAS: train on files before Mar 2020, test on later ones. Dumpware10: write-up only |
| 7 ✔ | Triage report | Ranked list with score, p-value, top reasons (SHAP for flagged artefacts; reconstruction-error reasons kept for comparison), and a precision–recall curve |

```python
cal = np.sort(score_fn(X_cal))                       # scores of held-out clean data
p = (1 + len(cal) - np.searchsorted(cal, s)) / (len(cal) + 1)
flag = p <= 0.01                                     # at most 1% false alarms
```

> Example: a new dump beats all but 12 of 5,859 calibration dumps, so p = 13/5,860 = 0.0022, i.e. "only 0.22% of clean memory looks this unusual".

## 6. Explaining it

> **Pitch:** "We score evidence by how unusual it is compared with clean data only, with a probability and an explanation. Our base paper's 97.6% accuracy is just 2.4 points above calling everything clean. Across four datasets, class imbalance was never the problem. Scaling and a false-alarm budget fix the two lab datasets (F1 ≈ 0.9) but not the realistic one, BODMAS (≈ 0.2). Each easy dataset has a one-feature shortcut (MalMem's running-services count, 99.66%; CICIoT's packet-window size, 98.7% balanced accuracy). Held-out and time-ordered tests confirm all three results. A VAE ties the autoencoder. A SHAP audit shows the explanations name those same shortcuts as the main reason, so they describe the lab setup, not the malware."

| Question | Answer |
|---|---|
| Why not accuracy? | "Always clean" already scores 95.2% |
| Why train only on clean data? | No labels at seizure; new malware is unknown |
| AE vs VAE? | Both get conformal p-values here. The VAE's score has a probability meaning (negative ELBO ≈ −log P(clean)), but it detects no better: it ties the AE in 5 of 6 tests |
| Is a neural network needed? | On MalMem yes (recall 0.99 vs 0.52 for distance from the mean); on CICIoT and BODMAS distance from the mean does as well |
| Do the SHAP explanations help? | They name the shortcut: `svcscan` for 86% of flagged MalMem dumps, `Number` for 99% of CICIoT flows. They describe the lab setup, not the malware |
| Why did transfer fail? | Unscaled features up to 3.1 × 10⁶ and 4.3 × 10⁹ |
| Why not SMOTE? | Tests B, C and D never raised recall |
| Why drop Dumpware10? | Clean-only detection caught ≤5% at 1% false alarms (supervised 0.98 AUC) |
| Why is BODMAS hard? | 77,000 varied real programs; no lab shortcut (78.4%) |
| Why use it anyway? | Clean, large, timestamps, 581 families: a realistic test |
| Novelty? | First VAE and anomaly-class metrics on these datasets, plus an audit of what SHAP explains |

## 7. Papers reviewed

**Malik et al., IEEE Access 13 (2025), few-shot prototypical networks on Dumpware10.**
- **Idea:** average 5 examples of a family into a "prototype" and assign new images to the nearest one.
- **Headline:** "92.79% accuracy", but accuracy is counted over image–prototype pairs. Always answering "no" already scores 90.91% at 11 classes, and their accuracy recomputed from their own precision and recall matches every row of their table. **Real result: recall 0.30, F1 0.43.**
- **Other flaws:** near-twin leakage; training collapse; no threshold, settings or code reported; 38% of images unaccounted for.
- **Useful:** independent evidence of Dumpware10 duplicates, and a ready accuracy-trap example.

**Prawiranata & Hadiprakoso, IEEE ICoCICs 2023, transfer learning on Dumpware10.**
- **Method:** ImageNet-pretrained EfficientNetV2, InceptionV4 and Xception, with and without augmentation (flips and rotations, which make no sense for byte images).
- **Results:** not verified (paywalled). Download through college IEEE access before citing numbers.
- **Limits:** supervised and closed-set; read any ~97% against the 81% no-learning rule.

## 8. Results side by side

Means across seeds; † = F1 varies by ≥ 0.1 between seeds.

| Audit | MalMem | CICIoT2023 | BODMAS |
|---|---|---|---|
| Rows / features | 58,596 / 55 | 47,022,341 / 39 | 134,435 / 2,381 |
| Benign share | 50.0% | 2.3% | 57.4% |
| Best one-feature rule | **99.66%** | 97.95% vs 97.67% always-attack; `Number` **98.7%** balanced | **78.4%** |
| Duplicate rows | 534 records / 569 feature vectors | **53.5%** (all 63 files) | 7 |
| Largest feature value | 1.05 × 10⁶ | 3.1 × 10⁶ | 4.3 × 10⁹ |
| Timestamps | No | No | Yes |

| Step | MalMem P | MalMem R | MalMem F1 | CICIoT P | CICIoT R | CICIoT F1 | BODMAS P | BODMAS R | BODMAS F1 |
|---|---|---|---|---|---|---|---|---|---|
| Paper autoencoder | 0.61 | 0.85 | 0.71† | 0.45 | 0.08 | 0.14 | 0.34 | 0.01 | 0.01 |
| Isolation Forest | 0.25 | 1.00 | 0.41 | – | – | – | – | – | – |
| A. Paper pipeline | 0.60 | 0.80 | 0.69 | 0.09 | 0.01 | 0.01 | 0.63 | 0.02 | 0.03 |
| B. Test 1:1, real | 0.97 | 0.80 | 0.87 | 0.46 | 0.01 | 0.02 | 0.97 | 0.02 | 0.03 |
| C. Test 1:1, SMOTE | 0.97 | 0.80 | 0.88 | 0.39 | 0.01 | 0.01 | 0.97 | 0.02 | 0.03 |
| D. Undersampled training | 0.35 | 0.13 | 0.19 | 0.00 | 0.00 | 0.00 | 0.16 | 0.02 | 0.03 |
| **E. Scaled** | 0.92 | 0.87 | **0.89**† | 0.97 | 0.97 | **0.97** | 0.38 | 0.16 | **0.23** |
| **F. Scaled + 1% budget** | 0.83 | 1.00 | **0.91** | 0.83 | 0.97 | **0.90** | 0.41 | 0.14 | **0.21** |
| F. Scaled + 5% budget | 0.50 | 1.00 | 0.67 | 0.49 | 0.98 | 0.66 | 0.21 | 0.26 | 0.23 |
| Paper test set, scaled, 1% | 0.83 | 1.00 | 0.91 | n/a | n/a | n/a | n/a | n/a | n/a |
| **Held-out clean, p ≤ 0.01** | 0.85 | 1.00 | **0.92** | 0.85 | 0.97 | **0.90** | 0.38 | 0.13 | **0.19** |
| Held-out, shortcut features dropped¹ | 0.85 | 0.99 | 0.92 | 0.80 | 0.76 | 0.78 | n/a | n/a | n/a |
| Held-out, BODMAS files after Mar 2020 | n/a | n/a | n/a | n/a | n/a | n/a | 0.48 | 0.15 | 0.23 |
| **Held-out VAE, p ≤ 0.01** | 0.85 | 0.99 | **0.92** | 0.85 | 0.97 | **0.90** | 0.38 | 0.13 | **0.19** |
| Held-out VAE, shortcut features dropped¹ | 0.86 | 0.99 | 0.92 | 0.77 | 0.62 | 0.69 | n/a | n/a | n/a |
| Held-out VAE, BODMAS files after Mar 2020 | n/a | n/a | n/a | n/a | n/a | n/a | 0.48 | 0.16 | 0.24 |
| Held-out distance from mean (no model) | 0.76 | 0.52 | 0.62 | 0.83 | 0.97 | 0.90 | 0.37 | 0.13 | 0.19 |
| Best one-feature stump, held-out | 0.93 | 1.00 | 0.96 | 1.00 | 0.97 | 0.98 | 0.13 | 0.89 | 0.23 |

| Accuracy | Always benign | MalMem | CICIoT | BODMAS |
|---|---|---|---|---|
| Paper autoencoder | 0.952 | 0.967 | 0.952 | 0.952 |
| E. Scaled | 0.952 | 0.990 | 0.997 | 0.947 |
| F. Scaled + 1% budget | 0.952 | 0.990 | 0.989 | 0.949 |
| B / C. Test 1:1 | 0.500 | 0.885 / 0.887 | 0.502 / 0.501 | 0.509 / 0.508 |

**Notes**
- **Seeds:** 5 for the paper autoencoder on MalMem and BODMAS, 1 on CICIoT, 3 for tests A–F, 5 for the held-out rows.
- **The 1% and 5% rows of test F are tested on their own training rows.** The held-out rows are not: the autoencoder's false alarms on unseen clean rows were 0.84–1.15%.
- **Held-out precision and F1** are at the paper's 20:1 ratio; the stump is supervised (it sees malware labels).
- ¹ MalMem without `svcscan.*`; CICIoT without `Number`, `Tot sum`, `IAT`, `Variance`, `Rate`.
- **MalMem's tests A–F use random malware** from all 15 families; the paper's test set uses only Conti and Ako.
