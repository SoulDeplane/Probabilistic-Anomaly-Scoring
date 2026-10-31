# Comparative Analysis: Base Paper vs Our Project

*Team MP2026CSE75 · Dept. of CSE, Graphic Era Deemed to be University · 31 October 2026*

| | |
|---|---|
| **Base paper** | Khalid, Iqbal & Saqib (2025), "Bridging knowledge gaps in digital forensics using unsupervised explainable AI", *Forensic Sci. Int.: Digital Investigation* 53, 301924 |
| **Our project** | Probabilistic Anomaly Scoring for Explainable Digital Forensic Triage |

Every number for our work comes from a committed result file (listed in [Section 8](#8-sources)). Unless stated otherwise, our numbers are the mean of 5 runs with different random seeds.

**Terms used**

| Term | Meaning in one line |
|---|---|
| False alarm | A clean item wrongly flagged as malware |
| Recall | Share of malware that gets caught |
| Precision | Share of flagged items that really are malware |
| F1 | One number balancing precision and recall (0 = useless, 1 = perfect) |
| ROC-AUC / PR-AUC | How well the score ranks malware above clean, over all thresholds (PR-AUC is the stricter one when malware is rare) |
| Threshold | The cut-off that turns a score into "flag" or "don't flag" |
| Held-out data | Data the model never saw during training |
| Precision at 20:1 | Precision computed as if there are 20 clean items per malware item, the base paper's ratio, so numbers stay comparable |

---

## 1. The bottom line

1. **We reproduced the base paper.** Isolation Forest: 0.8607 accuracy vs their 0.8595. Autoencoder: 0.957–0.973 vs their 0.9759.
2. **Their headline accuracy hides weak results.** Calling every item "clean" already scores 95.2%. Their 97.6% sits only 2.4 points above that, and behind it are 716 false alarms and a precision of 0.668 (one in three flags is wrong).
3. **Two simple fixes make a large difference.** Scaling the features and setting the threshold by a 1% false-alarm budget cut false alarms by 59% (716 → 293) and raise F1 from 0.796 to 0.91, on the paper's own test set.
4. **Our result holds on a fair test.** On clean data the model never saw, false alarms stay at 0.92% and all 15 malware families are caught. The paper tested on its own training data and on only 2 families.
5. **We tested more than one kind of evidence.** The paper's pipeline, unchanged, fails on network traffic (CICIoT2023) and on Windows programs (BODMAS). With our fixes, network traffic reaches F1 0.90, but BODMAS, the most realistic dataset, stays hard at F1 0.19.

---

## 2. Side by side

| Aspect | Base paper | Our project |
|---|---|---|
| Aim | Show that unsupervised ML plus SHAP can serve digital forensics | Rank seized evidence by how unusual it is, with a p-value and a false-alarm rate chosen in advance |
| Datasets | CIC MalMem-2022 only (memory dumps) | MalMem-2022, CICIoT2023 (network), BODMAS (Windows programs); Dumpware10 (images) audited |
| Models | Isolation Forest, Autoencoder (anomaly detection); K-means, DBSCAN, GMM (clustering) | Same Isolation Forest and Autoencoder; Variational Autoencoder (VAE) planned |
| Training data | Autoencoder: all clean rows. Isolation Forest: all rows, malware included | Clean rows only (60% of them) |
| Test data | **The same clean rows used for training**, plus the first 5% of malware in the file | Clean rows never seen in training, plus malware from every family |
| Feature scaling | None for anomaly detection (used only before clustering) | Scaler fitted on clean training rows |
| Threshold | Mean + 3 × standard deviation of training error | Conformal p-value: flag when p ≤ 0.01, i.e. about 1% false alarms |
| Metrics | Accuracy only (plus ARI for clustering) | False-alarm rate, recall, precision, F1, ROC-AUC, PR-AUC, recall per family |
| Baselines | None | "Always clean" and the best one-feature rule |
| Repeat runs | One | 5 seeds, with min–max |
| Duplicates | Not handled | 569 duplicate rows dropped; malware split by binary hash |
| Explanations | SHAP plots (force, waterfall, scatter, summary, bar) | Top reconstruction-error features per item now; a SHAP **audit** is planned |
| Change over time | Not tested | BODMAS: trained on files before March 2020, tested on later ones |

---

## 3. Quantitative comparison

### 3.1 Replication: do we get the paper's numbers?

Same data (29,298 clean + 1,465 malware = 30,763 rows), same models, same settings, taken from the authors' published notebooks.

| Model | Source | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|---|
| Isolation Forest | Base paper | 0.8595 | 0.253 | 1.000 | 0.404 |
| Isolation Forest | Our replication | 0.8607 | 0.255 | 1.000 | 0.406 |
| Autoencoder | Base paper | 0.9759 | 0.668 | 0.984 | 0.796 |
| Autoencoder | Our replication (5 seeds) | 0.957–0.973 (mean 0.967) | 0.54–0.64 | 0.64–1.00 | 0.59–0.78 |
| "Always clean" | — | 0.952 | — | 0.000 | 0.000 |

- Isolation Forest matches almost exactly.
- The autoencoder's accuracy matches, but the paper's run sits at the lucky end. Over 5 seeds, recall swings from 0.64 to 1.00: the paper's method is unstable.
- The paper reported accuracy only. Precision, recall and F1 for the paper come from its confusion matrix (Fig. 2b) and notebook.

### 3.2 What the paper's 97.6% accuracy hides

Paper's autoencoder on its own test set:

| | Predicted clean | Predicted malware |
|---|---|---|
| Actually clean (29,298) | 28,582 | **716 false alarms** |
| Actually malware (1,465) | 23 missed | 1,442 caught |

- The test set is 95.2% clean, so accuracy is high almost by default.
- An examiner would receive 2,158 flagged items, of which 716 (33%) are clean.

### 3.3 Same test set, our two fixes

Same model, same test rows; only the scaling and threshold change.

| Pipeline | Accuracy | Precision | Recall | F1 | False alarms | Missed |
|---|---|---|---|---|---|---|
| Base paper | 0.976 | 0.668 | 0.984 | 0.796 | 716 | 23 |
| Ours: scaled + 1% false-alarm budget (3 seeds) | **0.990** | **0.832–0.833** | **0.993–1.000** | **0.906–0.909** | **293** | **0–10** |
| Change | +1.4 pts | +0.16 | +0.01–0.02 | +0.11 | **−59%** | −13 to −23 |

The examiner now receives about 1,750 flags, of which 293 (17%) are clean, instead of 33%.

### 3.4 Stability: does the result change from run to run?

| Pipeline (paper's test set) | F1 across seeds |
|---|---|
| Paper: unscaled, mean + 3σ | 0.59 – 0.78 |
| Scaled, but still mean + 3σ | 0.35 – 0.98 |
| **Scaled + 1% budget (ours)** | **0.906 – 0.909** |

Scaling alone is not enough. The mean + 3σ cut-off lands in a different place every run. Fixing the false-alarm rate is what makes the result repeatable.

### 3.5 A fair test: data the model never saw

The paper tests on the same clean rows it trained on. We split clean MalMem rows 60/20/20 into train / calibrate / test, after removing 569 duplicates.

| MalMem, held-out test | Isolation Forest, p ≤ 0.01 | Autoencoder (scaled), p ≤ 0.01 |
|---|---|---|
| False alarms on unseen clean data | 1.17% | **0.92%** |
| Recall | 0.134 | **1.000** |
| Precision (20:1) | 0.359 | **0.845** |
| F1 (20:1) | 0.195 | **0.916** |
| ROC-AUC | 0.971 | **0.999** |
| PR-AUC (20:1) | 0.445 | **0.977** |

- The fixed autoencoder keeps its result on unseen data.
- Isolation Forest ranks reasonably (ROC-AUC 0.97) but catches only 13% of malware at a 1% false-alarm rate.

**Practical example** (from our triage report): a seized batch of 6,139 items (5,847 clean, 292 malware). We flag 349. All 292 malware items are among them, along with 57 clean items. The examiner reads 5.7% of the batch and finds every infected item.

### 3.6 Does the method carry over to other evidence types?

The paper only used MalMem and listed "other types of forensic datasets" as future work. We ran its pipeline unchanged on three more datasets, then with our fixes.

| Dataset (evidence type) | Paper pipeline, unchanged: recall / F1 | Ours, held-out, p ≤ 0.01: recall / F1 | Our false alarms |
|---|---|---|---|
| MalMem-2022 (memory) | 0.85 / 0.71 | 1.000 / 0.916 | 0.92% |
| CICIoT2023 (network) | 0.08 / 0.14 | 0.971 / 0.904 | 0.89% |
| BODMAS (Windows programs) | 0.007 / 0.014 | 0.130 / 0.194 | 1.07% |
| Dumpware10 (memory as images) | 0.00 / 0.00 | not modelled (see below) | — |

- **Why the paper's pipeline fails:** without scaling, one huge feature drowns the rest. CICIoT's `Rate` reaches 3.1 × 10⁶, and BODMAS has a timestamp feature up to 4.3 × 10⁹.
- **Class imbalance is not the cause.** Rebalancing the test set or adding SMOTE samples never raised recall, and undersampling the training data lowered it (MalMem 0.80 → 0.13). Only scaling fixed it.
- **BODMAS is genuinely hard**: ROC-AUC 0.73, and Isolation Forest scores 0.50 (a coin flip).
- **Dumpware10 was dropped from modelling**: detectors trained on clean images alone caught at most 5.2% of malware at 1% false alarms, while a supervised model reached 0.98 ROC-AUC. The classes differ, but not in a way that "unusual vs clean" can capture.

### 3.7 Which malware gets caught?

| | Base paper | Ours |
|---|---|---|
| Malware families in the test set | 2 of 15 (Conti 1,155 rows, Ako 310), both ransomware | All 15 (ransomware, spyware, trojans) |
| Recall per family | Not reported | 1.00 for every MalMem family |

On the other datasets the picture is uneven:

- **CICIoT2023:** all flood attacks are caught (recall 1.00), but quieter attacks are mostly missed: DNS spoofing 4.4%, ARP spoofing 4.5%, vulnerability scans 5.9%, XSS 0%.
- **BODMAS (newer files):** worms 0.33, droppers 0.14, trojans 0.07, backdoors 0.00.

### 3.8 Shortcut checks: is the model learning malware or the lab?

| Check | Result | What it means |
|---|---|---|
| Best one-feature rule on MalMem | `svcscan.nservices` ≤ 390 → malware, **99.66%** correct | Clean dumps show 392 or 395 running services; 27,242 of 29,298 malware dumps show exactly 389. This points to how the lab machine was set up, not to malware behaviour |
| Our autoencoder with all 7 `svcscan.*` features removed | F1 0.916 → 0.916, recall 1.000 → 0.991 | Our model does **not** depend on this shortcut |
| CICIoT2023 without the 5 window-size features | Recall 0.97 → 0.76, F1 0.90 → 0.78 | About a fifth of the network result comes from how the traffic was cut into windows |
| One-feature rule vs our autoencoder (held-out) | MalMem 0.961 vs 0.916; CICIoT 0.983 vs 0.904 F1 | On the two lab datasets a single (supervised) rule still wins: they are too easy to show what a complex model adds |
| Same check on BODMAS | Best rule only 78.4% correct (majority class 57.4%) | No shortcut, which is why BODMAS is the realistic test |

**Link to the paper's explanations.** The paper's SHAP explanation for K-means picks `svcscan.process_services` as a top feature and notes a "clear separation" in its values. Our audit shows that three `svcscan.*` features (`nservices`, `shared_process_services`, `kernel_drivers`) each separate the classes at about 99.6% on their own. So at least part of what the paper's SHAP plots "explain" is likely the capture setup rather than malicious behaviour.

### 3.9 Which threshold works on unseen data?

| Held-out false-alarm rate | Paper rule (mean + 3σ, with scaling) | Ours (conformal p ≤ 0.01) |
|---|---|---|
| MalMem | 0.40% (0.07–0.65% across seeds) | 0.92% (0.89–0.96%) |
| CICIoT2023 | 0.31% (0.19–0.52%) | 0.89% (0.76–0.95%) |
| BODMAS | **1.46%** | 1.07% |
| BODMAS, newer files | **1.95%** | 0.84% |

- With scaling, the paper's rule can score a higher F1 on MalMem (0.956 vs 0.916) because it happens to land at a lower false-alarm rate. But nobody chooses that rate, it moves between runs, and on BODMAS it overshoots.
- With the `svcscan.*` features removed, the paper's rule gives recall anywhere from 0.27 to 0.94; ours stays at 0.96–1.00.
- Ours lands near the chosen 1% on every dataset and every seed. That predictability is what an examiner needs.

### 3.10 Does it hold over time?

Only BODMAS has dates. We trained on files first seen before March 2020 and tested on later ones (up to about seven months newer).

| BODMAS | Older held-out files | Newer files |
|---|---|---|
| False alarms | 1.15% | **0.84%** |
| Recall | 0.096 | 0.154 |
| F1 (20:1) | 0.145 | 0.234 |

The false-alarm rate did not drift upward over time. Recall stays low. The paper did not test this.

### 3.11 Effect of keeping each binary's dumps together

Each MalMem malware binary contributes about 10 memory dumps taken 15 seconds apart (2,637 of 2,887 binaries have exactly 10). A random split puts near-copies of the same binary on both sides. We trained a supervised Random Forest both ways:

| Task | Random split | Split by binary hash | Drop |
|---|---|---|---|
| Malware vs clean | 99.99% | 99.96% | none |
| 4 classes: accuracy / macro-F1 | 87.4% / 0.809 | 84.7% / 0.769 | −4.0 F1 points |
| 16 families: accuracy / macro-F1 | 75.2% / 0.534 | 70.7% / 0.447 | −8.7 F1 points |

The supervised scores the base paper cites from Öztürk & Hizal (87.79% at 4 classes, 75.49% at 16) sit right at our random-split numbers. They likely include the same leak.

---

## 4. Qualitative comparison

### 4.1 What the base paper does well

- **Right question.** It argues that unsupervised learning suits forensics, where seized evidence has no labels. Our project builds on that argument.
- **Explainability for unsupervised models.** It shows that SHAP can be applied to anomaly detectors and clustering, not only to classifiers.
- **Broad coverage.** It covers both anomaly detection and clustering at three levels (2, 4 and 16 classes), with ARI up to 0.9592 for GMM.
- **Open code.** The authors published their notebooks. Without them, an exact replication would not have been possible.

### 4.2 Problems we found in the base paper

| Problem | Why it matters | Evidence | What we did |
|---|---|---|---|
| Accuracy is the only metric | It hides 716 false alarms and a precision of 0.668 | §3.2 | Report false alarms, recall, precision, F1, PR-AUC, and baselines |
| Tested on its own training rows | Gives no evidence on unseen evidence | §3.5 | 60/20/20 train / calibrate / test split |
| Only 2 of 15 families tested | Says nothing about spyware or trojans | §3.7 | All 15 families, recall per family |
| No feature scaling for anomaly detection | Huge features dominate; the method breaks on other data | §3.6 | Scaler fitted on clean training data |
| Unstable threshold | Recall 0.64–1.00 depending on the seed | §3.1, §3.4 | Conformal p-value at a fixed 1% false-alarm rate |
| Single run, single dataset | No measure of reliability or generality | §3.4, §3.6 | 5 seeds, 3 datasets, 1 time-ordered test |
| No baseline | 97.6% sounds strong until compared with 95.2% | §3.2 | "Always clean" and one-feature rules |
| SHAP output not checked | Explanations may describe the lab, not the malware | §3.8 | Shortcut tests now; SHAP audit planned |
| Repeated dumps and duplicates ignored | Inflates multi-class scores | §3.11 | Duplicates dropped; split by binary hash |

### 4.3 Dataset facts the paper did not report

| Dataset | Finding | Value |
|---|---|---|
| MalMem-2022 | Duplicate rows | 569 duplicate feature vectors (502 malware, 67 clean) |
| MalMem-2022 | One-feature shortcut | `svcscan.nservices`, 99.66% |
| MalMem-2022 | Dumps per binary | ~10, taken 15 seconds apart |
| MalMem-2022 | Paper says the data was balanced with SMOTE | We found no trace: 0 of 29,298 clean rows have fractional values in the 40 count features. This does not prove SMOTE was never used |
| CICIoT2023 | Repeated rows | 53.5% of all 47 million rows repeat an earlier flow (floods 42–73%, clean only 0.4%) |
| CICIoT2023 | Public release | 12 files truncated; we rebuilt them |
| Dumpware10 | Near-twin images | 35.3% of test images have a near-copy in training; a no-learning rule scores 81% |

### 4.4 Explanations: paper vs ours

| | Base paper | Ours (current) |
|---|---|---|
| Method | SHAP (model-agnostic Explainer) | Share of reconstruction error per feature |
| Output | Force, waterfall, scatter, summary and bar plots | A ranked list: score, p-value, top 3 features vs the clean median |
| Checked against shortcuts? | No | Yes, by dropping the shortcut features and retraining |
| Example top driver | `svcscan.process_services`, `pslist.avg_threads` | `malfind.commitCharge` (memory regions that look like injected code) for the top-ranked items |

The paper's explanations are richer visually. Ours are simpler, but they come with a probability, a fixed false-alarm rate and a check on whether the features describe malware or the lab.

---

## 5. Where the base paper is still ahead, and our limits

**Not done yet in our project**

- **No VAE yet.** The probabilistic model (Step 4) is still to be built; the current p-value is computed from the autoencoder's score.
- **No SHAP audit yet** (Step 5), the project's main novel contribution.
- **Clustering not replicated.** We did not reproduce or extend the paper's K-means, DBSCAN and GMM results.

**Honest limits of our results**

- On MalMem and CICIoT2023, a supervised one-feature rule still beats our autoencoder (F1 0.961 and 0.983 vs 0.916 and 0.904).
- BODMAS remains unsolved: F1 0.19–0.23, ROC-AUC 0.73.
- On network data only floods are caught well; spoofing, scans and web attacks are caught at 0–9%.
- The time-based test covers one dataset and about seven months.
- TensorFlow on CPU is not fully deterministic, so reruns differ slightly.

---

## 6. Scorecard

| Requirement for a forensic triage tool | Base paper | Ours now |
|---|---|---|
| Works without labels | ✔ | ✔ |
| Tested on unseen data | ✘ | ✔ |
| False-alarm rate chosen in advance | ✘ | ✔ (0.84–1.15% observed at a 1% target) |
| Stable across runs | ✘ (recall 0.64–1.00) | ✔ (MalMem F1 0.913–0.918) |
| Metrics beyond accuracy, with baselines | ✘ | ✔ |
| All malware families tested | ✘ (2 of 15) | ✔ (15 of 15) |
| More than one evidence type | ✘ | ✔ (memory, network, programs) |
| Duplicates and shortcuts checked | ✘ | ✔ |
| Tested over time | ✘ | ✔ (BODMAS only) |
| Probability-style score | ✘ | Partial (conformal p-value; VAE pending) |
| Explanation per item | ✔ (SHAP) | Partial (reconstruction error; SHAP audit pending) |
| Explanations checked for shortcuts | ✘ | Partial (shortcut ablations done; SHAP audit pending) |
| Clustering of malware types | ✔ | ✘ (not in scope) |
| Public code | ✔ | ✔ |

---

## 7. Remaining work

| Step | Task | How it will be compared with the paper |
|---|---|---|
| 4 | Variational Autoencoder (55 → 64 → 32 → 8-d latent → 32 → 64 → 55) | PR-AUC and recall at 1% false alarms vs the autoencoder |
| 5 | SHAP audit of the anomaly score | SHAP feature ranking vs the one-feature-rule ranking in `results/audit/malmem.json`; on BODMAS, SHAP summed per feature group |
| — | Supervisor approval of the dataset switch (Dumpware10 → BODMAS) | — |

---

## 8. Sources

| Claim | File |
|---|---|
| Base paper's numbers | `Research Papers/1-s2.0-S2666281725000630-main.pdf` (Table 1, Fig. 2b) |
| Replication (§3.1) | [results/replication/results.json](../Probabilistic_Anomaly_Scoring/results/replication/results.json) |
| Same test set, our fixes (§3.3–3.4) | [results/replication/scaled_paper_testset.json](../Probabilistic_Anomaly_Scoring/results/replication/scaled_paper_testset.json) |
| Paper pipeline on other datasets (§3.6) | [results/replication/](../Probabilistic_Anomaly_Scoring/results/replication/) `ciciot23.json`, `bodmas.json`, `dumpware10.json` |
| Class-imbalance tests (§3.6) | [results/prove_imbalance/](../Probabilistic_Anomaly_Scoring/results/prove_imbalance/) |
| Held-out results, families, thresholds (§3.5–3.10) | [results/heldout/](../Probabilistic_Anomaly_Scoring/results/heldout/) |
| Triage example (§3.5) | [results/triage/malmem_report.md](../Probabilistic_Anomaly_Scoring/results/triage/malmem_report.md) |
| Dataset audits (§3.8, §4.3) | [results/audit/](../Probabilistic_Anomaly_Scoring/results/audit/) |
| Binary-hash split (§3.11) | [results/group_split/malmem.json](../Probabilistic_Anomaly_Scoring/results/group_split/malmem.json) |
| Dumpware10 clean-only detectors (§3.6) | [results/dumpware10/benign_only.json](../Probabilistic_Anomaly_Scoring/results/dumpware10/benign_only.json) |
