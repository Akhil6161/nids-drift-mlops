# 🛡️ NIDS Drift MLOps — Real-Time Network Intrusion Detection with Concept-Drift Monitoring

An end-to-end pipeline that captures **live network traffic**, extracts CICIDS2017-style flow features in real time, classifies each flow as **BENIGN** or **ATTACK** with a trained Random Forest model, logs every prediction, and continuously checks whether the live traffic distribution has **drifted** away from the data the model was trained on — surfacing the results in a Streamlit dashboard.

> This is the team's minor project (with `Akhil6161` and `realadityagupta`), building on Drago et al.'s research on unsupervised, label-independent concept-drift detection for network intrusion detection, adapted to a real-time student-project scale.

---

## ✨ Features

- **Offline model training on CICIDS2017** — loads and concatenates eight labelled attack-category Parquet files (Benign, Brute-force, DoS, Infiltration, Web Attacks, DDoS, Portscan, Botnet), cleans them (drops infinite/missing values and duplicates), collapses the multi-class label into a binary `Benign`/`Attack` target, and trains a class-weighted Random Forest.
- **Live packet capture** — uses Scapy to sniff live traffic off a network interface, reconstructing bidirectional **flows** (grouped by 5-tuple: src/dst IP, src/dst port, protocol) from raw TCP/UDP/IP packets.
- **77-feature flow extraction matching the training schema** — the `Flow` class computes the same feature set the model was trained on: packet/byte counts and rates in each direction, inter-arrival-time (IAT) statistics, TCP flag counts (FIN/SYN/RST/PSH/ACK/URG/ECE/CWE), header lengths, packet-length statistics, subflow stats, and initial TCP window sizes — so a live flow can be scored by the same model trained on the static dataset.
- **Rolling live classification** — once a flow accumulates enough packets, its features are extracted and passed to the trained model for a prediction, which is appended to a CSV prediction log along with the attack probability.
- **Concept-drift detection** — compares a reference window (the first N live predictions) against the most recent window using two complementary statistical tests: **Population Stability Index (PSI)** and the **Kolmogorov–Smirnov (KS) two-sample test**, on `packets`, `bytes`, and `attack_probability`. Combines both into a three-level verdict: `NO_DRIFT`, `MODERATE_DRIFT`, or `SIGNIFICANT_DRIFT`.
- **Continuous drift monitor** — a long-running loop that re-checks for drift automatically whenever new predictions arrive, rather than requiring a manual re-run.
- **Streamlit dashboard** — total/benign/attack prediction counts, attack rate, attack-probability trend over time, prediction distribution, recent predictions table, and the latest drift results.
- **One-command orchestrated pipeline** (`src/pipeline/run.py`) that chains live capture → prediction → drift detection as a single sequential run.

---

## 🤔 How It Works / Why This Design

- **Flow-based features, not raw packets**: individual packets carry almost no signal for intrusion detection on their own — the CICIDS2017 dataset (and most NIDS research) defines features over a *flow* (a bidirectional conversation between two endpoints). Rebuilding those same 77 features from live packets is what lets a model trained on static CSVs be applied to live traffic without retraining from scratch.
- **PSI + KS together, not just one test**: PSI is a standard industry metric for distribution shift but is coarse (bucketed); the KS test is more statistically rigorous but less commonly used operationally. Combining them (both need to agree for "significant" drift, either one triggers "moderate") reduces false alarms from a single noisy test while still catching real distribution shifts — directly in line with the drift-detection research this project adapts.
- **CSV-based logging instead of a database (so far)**: predictions and drift results are appended to CSV files rather than written to MongoDB — simple to inspect and version during development, though it won't scale well as a long-running production system (see Known Gaps below).
- **Class-weighted Random Forest as the baseline model**: Random Forest is a strong, fast-to-train baseline for tabular intrusion-detection data and handles the class imbalance (attacks are much rarer than benign traffic) reasonably well via `class_weight="balanced"`, without needing heavy hyperparameter tuning to get a usable first model.
- **Rolling prediction windows rather than one prediction per flow**: predicting every 5 packets (after an initial 5-packet warm-up) rather than only once at flow termination means long-lived flows get monitored continuously instead of only being scored once they end — closer to how a real-time IDS needs to behave.

---

## 📋 Requirements

- Python 3.9+ (Parquet + Scapy support)
- **Npcap** (Windows) or equivalent packet-capture driver, since live capture uses Scapy's `sniff()` against a specific network interface
- The **CICIDS2017** dataset (Parquet format) placed under `data/raw/` — not committed to the repo (see `data/README.md`); download separately
- A trained model file at `models/nids_random_forest.joblib` (produced by `src/models/train.py`) before live prediction can run

### Install

```bash
git clone https://github.com/Akhil6161/nids-drift-mlops.git
cd nids-drift-mlops
pip install pandas numpy scikit-learn scapy streamlit joblib scipy pyarrow
```

> `requirements.txt` is currently empty — the packages above are inferred from the imports actually used in the code (see [Known Gaps](#-known-gaps--work-in-progress)); pin and commit them there for a reproducible setup.

### Run the pipeline

```bash
# 1. Preprocess the raw CICIDS2017 files into a single cleaned Parquet file
python -m src.data.preprocessor

# 2. Train the Random Forest model
python -m src.models.train

# 3. Find your live network interface name
python -m src.live.interfaces
# then update INTERFACE in src/live/nids.py to match your machine

# 4. Run live capture + real-time prediction (Ctrl+C to stop)
python -m src.live.nids

# 5. Run drift detection against logged predictions
python -m src.drift.detector
# — or run it continuously in the background:
python -m src.drift.monitor

# 6. View the dashboard
streamlit run dashboard.py
```

Steps 4–5 can also be run together with:
```bash
python -m src.pipeline.run
```

---

## 🧱 Tech Stack

| Purpose | Technology |
|---|---|
| Language | Python 3 |
| Data handling | Pandas, NumPy, PyArrow (Parquet) |
| Model | Scikit-learn (`RandomForestClassifier`) |
| Live packet capture | Scapy (raw packet sniffing, requires Npcap on Windows) |
| Drift statistics | SciPy (`ks_2samp`), custom PSI implementation |
| Dashboard | Streamlit |
| Model persistence | joblib |
| Dataset | CICIDS2017 (Parquet, pre-split by attack category) |

---

## 🏗️ Architecture & System Flow

### High-level pipeline

```
CICIDS2017 (raw Parquet)
        │
        ▼
[ src/data/preprocessor.py ]  →  cleaned, binary-labelled Parquet
        │
        ▼
[ src/models/train.py ]  →  RandomForestClassifier  →  models/nids_random_forest.joblib
                                                              │
                                                              │  (loaded at runtime)
                                                              ▼
Live network interface
        │  (Scapy sniff)
        ▼
[ src/live/nids.py ]
   ├─ builds per-flow state via [ src/live/flow_builder.py ] (Flow class)
   ├─ every 5 packets → Flow.to_features() → 77-feature dict
   ├─ [ src/live/predictor.py ] (NIDSPredictor) → model.predict() + predict_proba()
   └─ appends result to logs/nids_predictions.csv
        │
        ▼
[ src/drift/detector.py ]  (or the continuous loop in src/drift/monitor.py)
   ├─ reference window = first 1000 predictions
   ├─ current window   = most recent 100 predictions
   ├─ PSI + KS test on packets / bytes / attack_probability
   └─ writes logs/drift_detection.csv  (NO_DRIFT / MODERATE_DRIFT / SIGNIFICANT_DRIFT)
        │
        ▼
[ dashboard.py ]  (Streamlit)
   reads logs/nids_predictions.csv + logs/drift_detection.csv
   → live metrics, attack-probability trend, drift status, recent predictions
```

### Module map

```
src/data/loader.py            → loads & concatenates the 8 CICIDS2017 Parquet files
src/data/preprocessor.py      → cleans columns, drops nulls/dupes, builds binary Target label
src/models/train.py            → trains + evaluates + saves the Random Forest model
src/live/flow_builder.py       → Flow class: accumulates packets per 5-tuple, computes 77 features
src/live/capture.py,
src/live/flow_capture.py       → earlier/standalone flow-capture scripts (packet counting only,
                                  no prediction) — superseded by src/live/nids.py
src/live/interfaces.py         → lists available network interfaces (Scapy get_if_list)
src/live/predictor.py          → NIDSPredictor: loads the joblib model, predicts on a feature dict
src/live/nids.py               → main live orchestrator: sniff → build flow → predict → log
src/drift/detector.py          → PSI + KS drift detection, one-shot run against the prediction log
src/drift/monitor.py           → wraps detector.py in a polling loop (re-checks on new predictions)
dashboard.py                   → Streamlit dashboard (root-level, reads logs/drift_detection.csv)
src/dashboard/app.py           → an earlier dashboard variant reading a different drift file/schema
src/pipeline/run.py            → runs live capture then drift detection as one sequential pipeline
```

### Data flow: from packet to verdict

1. **Capture**: `sniff()` hands each packet to `process_packet()`, which pulls out IP/port/protocol/TCP-flag/window/header info.
2. **Flow assembly**: the packet is matched to an existing `Flow` (by forward or backward 5-tuple key) or a new one is created; the packet is appended to that flow's forward/backward packet list.
3. **Feature extraction**: once a flow has accumulated enough packets (5, then every 5 after that), `Flow.to_features()` computes all 77 features the model expects — duration, byte/packet counts and rates, IAT statistics, TCP flag counts, header lengths, subflow stats.
4. **Prediction**: `NIDSPredictor` reindexes the feature dict to match the model's exact training column order, then calls `predict()`/`predict_proba()` to get a label (`BENIGN`/`ATTACK`) and attack probability.
5. **Logging**: the prediction, flow identity, and probability are appended to `logs/nids_predictions.csv`.
6. **Drift check**: once enough predictions have accumulated, `detect_drift()` splits the log into a reference window and a current window, computes PSI and KS statistics per feature, and writes a verdict to `logs/drift_detection.csv`.
7. **Visualization**: the Streamlit dashboard reads both CSVs and renders live metrics, trend charts, and the current drift status.

---

## ⚠️ Known Gaps / Work in Progress

Being transparent about where the project currently stands (useful both for your own next steps and for anyone reviewing the repo):

- **`requirements.txt` is empty** — dependencies exist only as inferred imports; should be pinned and committed for reproducibility.
- **The top-level README's tech list (MongoDB, MLflow, DVC, Evidently AI, FastAPI, Docker) doesn't match what's implemented yet** — the current code uses Scapy, scikit-learn, and Streamlit only; none of MongoDB/MLflow/DVC/Evidently/FastAPI/Docker appear anywhere in `src/`. Worth updating the top-line description to reflect current state, or treating that line as a roadmap rather than current fact.
- **`src/drift/monitor.py` currently has a broken import** — it imports `MIN_CURRENT_SIZE` from `src/drift/detector.py`, but `detector.py` only defines `CURRENT_SIZE`. The continuous monitor loop won't run until this is fixed.
- **Two dashboards, two schemas**: `dashboard.py` (root) reads `logs/drift_detection.csv` (matching `detector.py`'s actual output columns: `psi`, `ks_statistic`, `drift_status`), while `src/dashboard/app.py` reads a differently-named `logs/drift_results.csv` with different columns (`previous_attack_rate`, `status`, etc.) that nothing currently writes. `src/dashboard/app.py` looks like an earlier iteration that's now stale — worth removing or reconciling so there's a single source of truth.
- **`src/live/capture.py` and `src/live/flow_capture.py`** are earlier, simpler flow-capture experiments (packet/byte counting, no ML prediction) that have since been superseded by the fuller pipeline in `src/live/nids.py` — fine to keep for reference, but worth noting they're not part of the active pipeline.
- **Active/idle flow-timing features are hardcoded to zero** (`active_mean`, `idle_mean`, etc. in `flow_builder.py`) pending confirmation of the exact calculation CICIDS2017 used — meaning 8 of the 77 model features are currently always zero for live flows, which will reduce live prediction accuracy versus the offline evaluation numbers.
- **The capture interface is hardcoded** to a specific Windows NPF GUID (`INTERFACE = r"\Device\NPF_{...}"`) inside the scripts rather than read from a config file or CLI argument — makes the code non-portable across machines without manually editing source.
- **No automated tests, CI, or containerization yet** — `src/data/test_loader.py` exists but its contents weren't confirmed as a real test suite; there's no CI workflow or Dockerfile in the repo yet, despite the root README's mention of Docker.

None of this is unusual for a project at this stage — flagging it here mainly so it's easy to track and knock out before this becomes a portfolio/resume centerpiece.

---

## 🏁 Conclusion

This project implements a genuinely real-time NIDS pipeline: it captures live packets, reconstructs the same flow-level feature representation used by the CICIDS2017 benchmark, scores flows with a trained Random Forest as traffic happens, and continuously watches for concept drift using a combined PSI/KS statistical approach — closing the loop from "trained once on static data" toward "monitored and (eventually) self-correcting on live data." The core detection and drift logic is solid and working; the main remaining work is wiring up the pieces that turn it from a well-structured local prototype into an actually reproducible, deployable MLOps system — pinned dependencies, a single consistent dashboard/drift schema, automated retraining on drift, and containerized deployment.
