# Datasets

The project uses four public datasets, about 25 GB in total. GitHub blocks files over 100 MB and recommends repositories stay under 1–5 GB, so the full CICIoT2023 and Dumpware10 data are **not** stored here. BODMAS is not stored either, because its terms of use forbid sharing it beyond a project's co-authors. BODMAS was added after benign-only detection failed on Dumpware10. Dumpware10 was used only for its duplicate audit, and its local copy, samples and file inventory have since been deleted; the audit results remain in `Probabilistic_Anomaly_Scoring/results/audit/dumpware10.json` and `results/dumpware10/`. This folder contains:

| Item | What it is |
|---|---|
| `cicmalmem22/CSV/Obfuscated-MalMem2022.csv` | The **complete** CIC MalMemAnalysis-2022 dataset (official file, 19 MB) |
| `inventory/*_files.csv` | Every file of every dataset held locally: path, size, SHA-256 checksum, and row count (CSV) |
| `inventory/summary.json` | Per-dataset totals and class counts |
| `samples/ciciot23_sample.csv` | 10,200 CICIoT2023 flows: 300 per class for all 34 classes (drawn from each class's first capture file), 39 features + `Label` |
| `ciciot23/CSV/README.pdf` | CIC's own description of the CICIoT2023 file layout |

The inventory and samples are produced by `Probabilistic_Anomaly_Scoring/src/build_dataset_inventory.py`. A full local copy can be checked against the SHA-256 checksums in the inventory.

## Summary of the full datasets

| Dataset | Evidence type | Files | Size | Contents |
|---|---|---|---|---|
| CIC MalMemAnalysis-2022 | Memory-dump features (55, VolMemLyzer-V2) | 1 | 19 MB | 58,596 records: 29,298 benign, 29,298 malware in 15 families |
| CICIoT2023 | Network-flow features (39) | 374 | 18.7 GB | 47,022,341 flows in 34 classes, stored twice: 309 per-capture CSVs and 63 merged CSVs |
| Dumpware10 | Memory dumps rendered as RGB images | 34,352 | 6.5 GB | 4,294 images (3,686 malware in 10 families, 608 benign) × 8 rendering variants; local copy deleted after the audit |
| BODMAS | Static features of Windows executables (2,381 EMBER features, LIEF 0.9.0) | 3 | 278 MB | 134,435 executables: 77,142 benign, 57,293 malware in 581 families; first-seen timestamps (malware Aug 2019 – Sep 2020, benign 2007 – Sep 2020) |

### CIC MalMemAnalysis-2022: records per class

| Class | Records | Class | Records |
|---|---|---|---|
| Benign | 29,298 | Trojan-Scar | 2,000 |
| Spyware-Transponder | 2,410 | Ransomware-Conti | 1,988 |
| Spyware-Gator | 2,200 | Trojan-Emotet | 1,967 |
| Ransomware-Shade | 2,128 | Ransomware-Maze | 1,958 |
| Ransomware-Ako | 2,000 | Trojan-Zeus | 1,950 |
| Spyware-180solutions | 2,000 | Ransomware-Pysa | 1,717 |
| Spyware-CWS | 2,000 | Trojan-Reconyc | 1,570 |
| Trojan-Refroso | 2,000 | Spyware-TIBS | 1,410 |

### CICIoT2023: flows per class

| Class | Flows | Class | Flows |
|---|---|---|---|
| DDOS-ICMP_FLOOD | 7,200,501 | DDOS-UDP_FRAGMENTATION | 286,925 |
| DDOS-UDP_FLOOD | 5,412,231 | DDOS-ACK_FRAGMENTATION | 285,075 |
| DDOS-TCP_FLOOD | 4,497,649 | DNS_SPOOFING | 178,898 |
| DDOS-PSHACK_FLOOD | 4,094,772 | RECON-HOSTDISCOVERY | 134,378 |
| DDOS-SYN_FLOOD | 4,059,179 | RECON-OSSCAN | 98,259 |
| DDOS-RSTFINFLOOD | 4,045,279 | RECON-PORTSCAN | 82,284 |
| DDOS-SYNONYMOUSIP_FLOOD | 3,598,133 | DOS-HTTP_FLOOD | 71,861 |
| DOS-UDP_FLOOD | 3,318,634 | DDOS-HTTP_FLOOD | 28,790 |
| DOS-TCP_FLOOD | 2,671,430 | DDOS-SLOWLORIS | 23,426 |
| DOS-SYN_FLOOD | 2,028,836 | DICTIONARYBRUTEFORCE | 13,064 |
| **BENIGN** | **1,098,191** | BROWSERHIJACKING | 5,859 |
| MIRAI-GREETH_FLOOD | 991,834 | COMMANDINJECTION | 5,409 |
| MIRAI-UDPPLAIN | 890,574 | SQLINJECTION | 5,245 |
| MIRAI-GREIP_FLOOD | 751,646 | XSS | 3,846 |
| DDOS-ICMP_FRAGMENTATION | 452,490 | BACKDOOR_MALWARE | 3,218 |
| VULNERABILITYSCAN | 373,351 | RECON-PINGSWEEP | 2,262 |
| MITM-ARPSPOOFING | 307,560 | UPLOADING_ATTACK | 1,252 |

### Dumpware10: images per class (per rendering variant)

| Class | Training | Test | Class | Training | Test |
|---|---|---|---|---|---|
| Adposhel | 364 | 93 | InstallCore | 376 | 91 |
| Allaple | 349 | 88 | MultiPlug | 390 | 98 |
| Amonetize | 349 | 87 | **Other (benign)** | **487** | **121** |
| AutoRun | 158 | 38 | VBA | 399 | 100 |
| BrowseFox | 152 | 38 | Vilsel | 311 | 78 |
| Dinwod | 98 | 29 | | | |

Rendering variants: 224, 300, 4096 and square-root image widths, each resized to 224×224 and 300×300.

### BODMAS: malware per category

| Category | Samples | Category | Samples |
|---|---|---|---|
| Trojan | 29,972 | Virus | 192 |
| Worm | 16,697 | PUA | 29 |
| Backdoor | 7,331 | Cryptominer | 20 |
| Downloader | 1,031 | P2P-worm | 16 |
| Ransomware | 821 | Exploit | 12 |
| Dropper | 715 | Trojan-gamethief | 6 |
| Information stealer | 448 | Rootkit | 3 |

Largest families: sfone 4,729, wacatac 4,694, upatre 3,901, wabot 3,673, small 3,339. 57 families have at least 100 samples and 198 have one. Malware first-seen per month ranges from 680 (Aug 2019, partial) to 5,449 (May 2020).

## Audit and repairs applied to the local copies

- **CIC MalMemAnalysis-2022:** the original local copy held only 850 records of one family. It was replaced with the official file, which is byte-identical in two independent public repositories and reproduces the base paper's record order.
- **CICIoT2023:** the public release has 12 truncated files. The 3 truncated per-capture CSVs (DoS-UDP_Flood 7–9) were regenerated from the original PCAPs with CIC's own extractor; every surviving official row was reproduced. 2,003,107 missing rows were restored to the 9 truncated merged files. Class counts are now identical in both copies. 87,062 regenerated rows (0.19%) differ from CIC's original values only by floating-point rounding.
- **Dumpware10:** complete; only folder names were made consistent across the 8 variants. The local copy was deleted after the duplicate audit.
- **BODMAS:** complete and consistent; nothing was repaired. Counts match the dataset paper; labels, metadata and the category file agree row for row; no non-finite values; 49 constant features; 7 duplicate feature vectors, none labelled both benign and malware. One family is spelled two ways (`Unknown`/`unknown`, 7 samples), so there are 582 family strings for 581 families. 3,712 timestamps carry no timezone. The features are unnormalised: 135 exceed 10⁶, led by the COFF timestamp (up to 4.3 × 10⁹). The best single-feature decision stump reaches 78.4% against a 57.4% majority class, so unlike CIC MalMemAnalysis-2022 (99.66%) no single feature separates the classes. Details: `Probabilistic_Anomaly_Scoring/results/audit/bodmas.json`.

## Sources and citation

The full datasets must be obtained from their publishers:

| Dataset | Source | Cite |
|---|---|---|
| CIC MalMemAnalysis-2022 | https://www.unb.ca/cic/datasets/malmem-2022.html | T. Carrier, P. Victor, A. Tekeoglu and A. H. Lashkari, "Detecting obfuscated malware using memory feature engineering," ICISSP 2022 |
| CICIoT2023 | https://www.unb.ca/cic/datasets/iotdataset-2023.html | E. C. P. Neto et al., "CICIoT2023: A real-time dataset and benchmark for large-scale attacks in IoT environment," Sensors 23(13), 5941, 2023 |
| Dumpware10 | https://web.cs.hacettepe.edu.tr/~selman/dumpware10/ (free for academic use; download form) | A. S. Bozkir et al., "Catch them alive: A malware detection approach through memory forensics, manifold learning and computer vision," Computers & Security 103, 102166, 2021 |
| BODMAS | https://whyisyoung.github.io/BODMAS/ (feature vectors and metadata open to all; not to be shared beyond co-authors) | L. Yang, A. Ciptadi, I. Laziuk, A. Ahmadzadeh and G. Wang, "BODMAS: An open dataset for learning based temporal analysis of PE malware," 4th Deep Learning and Security Workshop (DLS), 2021 |

The copies and samples here are included only to document this academic project; all rights remain with the dataset authors.
