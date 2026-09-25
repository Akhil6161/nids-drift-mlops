# 🛡️ NIDS Drift MLOps

## Real-Time Network Intrusion Detection with Flow-Based Machine Learning, Concept-Drift Monitoring and Automated Model Lifecycle

An end-to-end **Network Intrusion Detection System (NIDS)** designed to detect malicious network traffic in real time while monitoring whether the traffic distribution is changing over time.

The project combines:

**CICIDS2017 → Data Processing → Random Forest → Live Packet Capture → Flow Reconstruction → Feature Extraction → Real-Time Prediction → Prediction Logging → Drift Detection → Candidate Retraining → Model Evaluation → Promotion Gate**

The goal is not simply to train an intrusion-detection model.

The goal is to build a system that recognizes an important problem with machine-learning systems deployed in changing environments:

> **A model can perform well when it is trained, but its assumptions may become less reliable as the underlying traffic distribution changes.**

This project therefore treats model monitoring and lifecycle management as first-class components of the NIDS rather than treating model training as the end of the system.

---

## 📌 Project Status

> **Academic / student MLOps project — actively developed**

The current repository contains the core components for:

* CICIDS2017 preprocessing
* Binary intrusion classification
* Random Forest training
* Live packet capture with Scapy
* Bidirectional network-flow reconstruction
* 77-feature live feature extraction
* Real-time prediction
* Attack-probability logging
* PSI-based drift detection
* Continuous drift monitoring
* Streamlit monitoring dashboard
* Pipeline orchestration and audit logging

The repository also contains orchestration logic for candidate retraining and model promotion.

The retraining and promotion stages are currently being integrated into the complete runnable pipeline and should therefore be treated as **MLOps architecture / work in progress rather than a fully production-hardened deployment system**.

---

# 1. 🎯 Problem Statement

Traditional machine-learning intrusion detection systems usually follow a relatively simple lifecycle:

```text
Dataset
   ↓
Train Model
   ↓
Evaluate Model
   ↓
Deploy Model
   ↓
Predict
```

The problem is that network traffic is not static.

Over time:

* normal traffic patterns change
* applications change
* network usage changes
* protocols and services evolve
* attack behaviour changes
* new attack patterns can appear
* the distribution of model inputs can shift

A model trained on historical traffic therefore operates under an assumption:

```text
Future traffic ≈ Training traffic
```

When that assumption becomes weaker, the model can become stale.

This project introduces a monitoring loop:

```text
                    ┌─────────────────────┐
                    │ Historical Dataset  │
                    └──────────┬──────────┘
                               ↓
                         Model Training
                               ↓
                     Production Model
                               ↓
                    ┌─────────────────┐
                    │ Live Network    │
                    │ Traffic         │
                    └────────┬────────┘
                             ↓
                     Flow Construction
                             ↓
                      Feature Extraction
                             ↓
                       ML Prediction
                             ↓
                     Prediction Logging
                             ↓
                      Drift Monitoring
                             ↓
                     Significant Drift?
                       /            \
                     NO              YES
                     ↓                 ↓
             Keep Model        Candidate Retraining
                                     ↓
                              Candidate Evaluation
                                     ↓
                                Promotion Gate
                                /           \
                              PASS           FAIL
                               ↓               ↓
                       Update Model       Keep Existing
```

This turns a static ML classifier into an **ML monitoring and lifecycle pipeline**.

---

# 2. 🚀 What This Project Actually Does

The system has two major operating modes.

### Mode 1 — Offline ML development

The CICIDS2017 dataset is:

1. Loaded
2. Cleaned
3. Converted from multi-class labels into binary labels
4. Stored as Parquet
5. Split into training and testing data
6. Used to train a Random Forest classifier
7. Evaluated using classification metrics
8. Serialized using Joblib

### Mode 2 — Live NIDS monitoring

The system:

1. Captures packets using Scapy
2. Identifies IP/TCP/UDP traffic
3. Groups packets into bidirectional flows
4. Accumulates flow statistics
5. Extracts the same general feature schema used during training
6. Runs the trained model
7. Calculates attack probability
8. Logs predictions
9. Monitors prediction behaviour
10. Runs drift detection when enough observations are available

---

# 3. 🧠 Why Flow-Based Detection?

A raw packet is often not enough information to characterize network behaviour.

Consider:

```text
Packet 1
Packet 2
Packet 3
Packet 4
Packet 5
...
```

A NIDS is usually interested in characteristics of the **communication flow**, such as:

* how many packets were sent
* how many bytes were transferred
* packet-size statistics
* packet timing
* forward/backward traffic ratios
* TCP flags
* header sizes
* initial TCP window sizes
* inter-arrival times
* flow duration

Therefore this project reconstructs traffic into flows.

A flow is identified using information similar to a 5-tuple:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

For example:

```text
192.168.1.10 : 52144
        ↓
    TCP / 443
        ↓
142.250.xxx.xxx : 443
```

Packets belonging to the same communication are accumulated into a `Flow` object.

The live flow builder then converts that accumulated state into model features.

---

# 4. 🔄 End-to-End System Architecture

```text
                         ┌─────────────────────────┐
                         │     CICIDS2017          │
                         │ Historical Network Data │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │ Data Loader             │
                         │                         │
                         │ Load 8 Parquet files   │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │ Preprocessor            │
                         │                         │
                         │ • Clean columns         │
                         │ • Remove NaN/Inf        │
                         │ • Remove duplicates     │
                         │ • Create binary target  │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │ Random Forest Training  │
                         │                         │
                         │ 77 numerical features  │
                         │ Binary classification  │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │ Production Model        │
                         │ nids_random_forest      │
                         │ .joblib                 │
                         └────────────┬────────────┘
                                      │
                                      │
              ┌───────────────────────┴────────────────────────┐
              │                                                │
              ▼                                                ▼
   ┌──────────────────────┐                         ┌──────────────────────┐
   │ Live Network Traffic │                         │ Controlled Dataset   │
   │                      │                         │ Demonstration        │
   └──────────┬───────────┘                         └──────────┬───────────┘
              │                                                │
              ▼                                                ▼
   ┌──────────────────────┐                         ┌──────────────────────┐
   │ Scapy Packet Capture │                         │ Sample Replay        │
   └──────────┬───────────┘                         └──────────┬───────────┘
              │                                                │
              └──────────────────────┬─────────────────────────┘
                                     ▼
                          ┌─────────────────────────┐
                          │ Flow Reconstruction     │
                          │                         │
                          │ Forward / Backward      │
                          │ packets                 │
                          └────────────┬────────────┘
                                       │
                                       ▼
                          ┌─────────────────────────┐
                          │ Feature Extraction      │
                          │                         │
                          │ 77 CICIDS-style fields │
                          └────────────┬────────────┘
                                       │
                                       ▼
                          ┌─────────────────────────┐
                          │ Random Forest Inference │
                          └────────────┬────────────┘
                                       │
                          ┌────────────┴────────────┐
                          ▼                         ▼
                 ┌────────────────┐       ┌──────────────────┐
                 │ BENIGN / ATTACK│       │ Attack Probability│
                 └────────┬───────┘       └─────────┬────────┘
                          │                         │
                          └────────────┬────────────┘
                                       ▼
                          ┌─────────────────────────┐
                          │ Prediction Log          │
                          │ CSV                     │
                          └────────────┬────────────┘
                                       │
                                       ▼
                          ┌─────────────────────────┐
                          │ Drift Detection         │
                          │                         │
                          │ Reference vs Current    │
                          │ PSI                     │
                          └────────────┬────────────┘
                                       │
                                       ▼
                              ┌──────────────────┐
                              │ Drift Severity   │
                              └────────┬─────────┘
                                       │
                        ┌──────────────┼──────────────┐
                        ▼              ▼              ▼
                   NO_DRIFT     MODERATE_DRIFT   SIGNIFICANT_DRIFT
                        │              │              │
                        │              │              ▼
                        │              │       Candidate Retraining
                        │              │              │
                        │              │              ▼
                        │              │       Candidate Evaluation
                        │              │              │
                        │              │              ▼
                        │              │        Promotion Gate
                        │              │          /       \
                        │              │        PASS       FAIL
                        │              │         │          │
                        ▼              ▼         ▼          ▼
                  Keep Existing Production Model
```

---

# 5. 📊 Dataset

This project uses the **CICIDS2017** intrusion-detection dataset.

The repository expects the processed source data to be divided into Parquet files representing different traffic categories/days.

The loader currently expects these files:

```text
Benign-Monday-no-metadata.parquet
Bruteforce-Tuesday-no-metadata.parquet
DoS-Wednesday-no-metadata.parquet
Infiltration-Thursday-no-metadata.parquet
WebAttacks-Thursday-no-metadata.parquet
DDoS-Friday-no-metadata.parquet
Portscan-Friday-no-metadata.parquet
Botnet-Friday-no-metadata.parquet
```

The project intentionally does not commit the full raw dataset because of its size.

---

# 6. 🏷️ Binary Classification

CICIDS2017 contains multiple traffic/attack categories.

For this project they are converted into a binary target:

| Target | Meaning |
| -----: | ------- |
|    `0` | BENIGN  |
|    `1` | ATTACK  |

The transformation is:

```python
if Label == "Benign":
    Target = 0
else:
    Target = 1
```

This means categories such as:

```text
DoS
DDoS
PortScan
Brute Force
Web Attacks
Infiltration
Botnet
```

are treated as the broader class:

```text
ATTACK
```

The objective is therefore **binary intrusion detection**, not attack-family classification.

---

# 7. 🧹 Data Preprocessing

The preprocessing stage performs several operations.

### 7.1 Column-name normalization

Whitespace is removed and spaces are converted to underscores.

```text
"Flow Duration"
```

becomes:

```text
"Flow_Duration"
```

### 7.2 Infinite-value handling

Network datasets frequently contain infinite values when a rate or division operation has an invalid denominator.

The pipeline converts:

```text
+∞
-∞
```

into missing values.

### 7.3 Missing-value removal

Rows containing missing values are removed.

### 7.4 Duplicate removal

Duplicate network-flow records are removed.

### 7.5 Binary target creation

The original categorical `Label` is converted into:

```text
Target = 0 → Benign
Target = 1 → Attack
```

The cleaned dataset is saved as:

```text
data/processed/cicids2017_processed.parquet
```

The implementation follows this preprocessing flow directly.

---

# 8. 🤖 Machine Learning Model

The baseline classifier is:

```text
RandomForestClassifier
```

Current training configuration:

```python
RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",
)
```

### Why Random Forest?

Random Forest is a practical baseline for this problem because network-flow data is:

* tabular
* heterogeneous
* nonlinear
* potentially highly imbalanced

The model can capture nonlinear relationships between traffic characteristics without requiring extensive feature scaling.

The project also uses:

```python
class_weight="balanced"
```

to compensate for class imbalance.

---

# 9. 🧪 Model Training

The training pipeline:

```text
Processed Parquet
       ↓
Separate X / y
       ↓
Keep numerical features
       ↓
Replace invalid values
       ↓
80/20 train-test split
       ↓
Stratification
       ↓
Random Forest
       ↓
Evaluation
       ↓
Joblib model artifact
```

The split is:

```text
80% Training
20% Testing
```

with:

```python
stratify=y
random_state=42
```

The model is saved as:

```text
models/nids_random_forest.joblib
```

The current training implementation reports accuracy, classification report and confusion matrix.

---

# 10. 📐 Feature Engineering

The live NIDS attempts to recreate the same flow-level representation expected by the trained model.

The feature space contains **77 model features**.

These include categories such as:

### Flow information

* Flow duration
* Total forward packets
* Total backward packets
* Forward packet bytes
* Backward packet bytes

### Packet statistics

* minimum packet length
* maximum packet length
* mean packet length
* standard deviation
* variance

### Inter-arrival time

* flow IAT mean
* flow IAT standard deviation
* flow IAT minimum
* flow IAT maximum
* forward IAT statistics
* backward IAT statistics

### Traffic rates

* bytes/second
* packets/second
* forward packets/second
* backward packets/second

### TCP characteristics

* FIN
* SYN
* RST
* PSH
* ACK
* URG
* ECE
* CWE

### Header information

* forward header length
* backward header length

### Window information

* initial forward TCP window
* initial backward TCP window

The flow builder computes these statistics from packets accumulated in each bidirectional flow.

---

# 11. 🌐 Live Packet Capture

Live monitoring is implemented using **Scapy**.

The capture process:

```text
Network Interface
       ↓
Scapy sniff()
       ↓
IP / IPv6 packet
       ↓
TCP / UDP information
       ↓
5-tuple flow matching
       ↓
Flow object
       ↓
Feature extraction
       ↓
Prediction
```

The live implementation extracts:

* source IP
* destination IP
* source port
* destination port
* protocol
* packet length
* TCP flags
* TCP window size
* header length
* packet timestamp

and uses these values to build the flow representation.

---

# 12. 🔁 Bidirectional Flow Reconstruction

For each packet, the system creates two possible flow keys:

```text
Forward:
(src_ip, src_port, dst_ip, dst_port, protocol)

Backward:
(dst_ip, dst_port, src_ip, src_port, protocol)
```

This allows a response packet to be associated with the same flow.

For example:

```text
Client → Server
192.168.1.10:50000 → 10.0.0.5:443
```

and:

```text
Server → Client
10.0.0.5:443 → 192.168.1.10:50000
```

are treated as the same communication flow.

This matters because many intrusion-detection features depend on comparing the two traffic directions.

---

# 13. ⚡ Rolling Real-Time Prediction

The system does not wait for a flow to finish.

Instead:

```text
First 5 packets
       ↓
Prediction
       ↓
Next 5 packets
       ↓
Prediction
       ↓
Next 5 packets
       ↓
Prediction
       ↓
...
```

Current configuration:

```python
PREDICT_AFTER_PACKETS = 5
PREDICT_EVERY_PACKETS = 5
```

Therefore, once a flow reaches five packets, the system begins generating rolling predictions every five additional packets.

This is useful for long-lived flows because the system can update its assessment while communication is still occurring.

---

# 14. 🔮 Prediction Output

For every prediction the model produces:

```text
prediction
label
attack_probability
```

Example:

```json
{
    "prediction": 1,
    "label": "ATTACK",
    "attack_probability": 0.94
}
```

or:

```json
{
    "prediction": 0,
    "label": "BENIGN",
    "attack_probability": 0.03
}
```

The predictor also reorders the feature DataFrame according to the model's original training feature order before inference.

This is important because a machine-learning model expects the same feature semantics and column ordering it saw during training.

---

# 15. 📝 Prediction Logging

Predictions are stored in:

```text
logs/nids_predictions.csv
```

The log contains fields including:

```text
timestamp
src_ip
src_port
dst_ip
dst_port
protocol
packets
bytes
prediction
label
attack_probability
source
```

Example:

```text
timestamp,src_ip,src_port,dst_ip,dst_port,protocol,packets,bytes,prediction,label,attack_probability,source
```

This prediction log serves as the bridge between:

```text
Online inference
        ↓
Monitoring
        ↓
Drift detection
```

The current implementation appends predictions to CSV rather than using a database.

---

# 16. 📉 What Is Concept Drift?

Concept drift occurs when the statistical relationship between incoming data and the target behaviour changes over time.

In simple terms:

```text
Training Environment
       ↓
Model learns pattern A
       ↓
Production environment changes
       ↓
Traffic behaves differently
       ↓
Model assumptions become stale
```

For an NIDS, this matters because network behaviour is not stationary.

However, an important distinction should be made:

### Data drift

The input distribution changes.

```text
P(X) changes
```

### Concept drift

The relationship between input and target changes.

```text
P(Y | X) changes
```

The current project primarily monitors **distributional changes in selected logged prediction variables**, so it should be described precisely as **PSI-based drift monitoring**, rather than claiming that it directly proves model-performance degradation or ground-truth concept drift.

That distinction is important for a technically accurate MLOps project.

---

# 17. 📊 Current Drift Detection

The current detector compares:

```text
Reference Window
        vs
Current Window
```

The configured windows are:

```text
Reference = first 1000 predictions
Current   = latest 100 predictions
```

The monitored variables are:

```text
packets
bytes
attack_probability
```

The current implementation calculates **Population Stability Index (PSI)** for these variables.

---

# 18. 📐 Population Stability Index

PSI measures how much a distribution has shifted between a reference population and a current population.

Conceptually:

```text
Reference Distribution
        ↓
Expected behaviour

Current Distribution
        ↓
Observed behaviour

Compare both
        ↓
PSI
```

The implementation creates bins based on the reference distribution and compares the proportions in each bin.

The mathematical form is:

```text
PSI = Σ (Current% - Reference%)
             ×
        ln(Current% / Reference%)
```

A larger PSI indicates a larger distributional shift.

The project currently interprets PSI as:

|            PSI | Status              |
| -------------: | ------------------- |
|       `< 0.10` | `NO_DRIFT`          |
| `0.10 – <0.25` | `MODERATE_DRIFT`    |
|      `>= 0.25` | `SIGNIFICANT_DRIFT` |

These thresholds are implemented directly in the detector.

---

# 19. ⚠️ PSI Is Not Proof of Model Failure

This is an important design principle.

If:

```text
PSI > threshold
```

it means:

> The monitored distribution has shifted.

It does **not automatically mean**:

> The model is now inaccurate.

To prove model degradation, ground-truth labels or another reliable evaluation mechanism would be required.

Therefore the intended lifecycle is:

```text
Distribution Shift
        ↓
Monitoring Signal
        ↓
Candidate Retraining
        ↓
Candidate Evaluation
        ↓
Promotion Decision
```

rather than:

```text
Drift = Model is Wrong
```

This separation is important in a real MLOps system.

---

# 20. 🔄 Continuous Drift Monitoring

The project also includes a continuous monitoring process.

The monitor:

1. Checks whether the prediction log exists
2. Reads the current prediction count
3. Waits until enough predictions are available
4. Detects new predictions
5. Runs drift detection
6. Writes updated drift results
7. Repeats after a configured interval

Current polling interval:

```text
30 seconds
```

The monitor therefore provides a simple continuous monitoring loop around the drift detector.

---

# 21. 🔁 MLOps Retraining Architecture

The intended automated lifecycle is:

```text
Prediction Log
      ↓
Drift Detection
      ↓
Significant Drift?
      │
      ├── NO
      │    ↓
      │  Keep Production Model
      │
      └── YES
           ↓
      Candidate Retraining
           ↓
      Candidate Evaluation
           ↓
      Promotion Gate
           │
        ┌──┴──┐
        ↓     ↓
      PASS   FAIL
        ↓     ↓
   Promote   Reject
        ↓     ↓
 Production Existing
   Model     Model
```

The orchestration layer in `src/pipeline/run.py` follows this intended state machine:

1. Validate prediction log
2. Run drift detection
3. Identify significant features
4. Trigger candidate retraining
5. Run model promotion
6. Record pipeline status
7. Record promotion status
8. Save audit information

The orchestration code explicitly invokes `src.models.retrain` after significant drift and `src.models.promote` afterward.

### Current implementation note

The repository should not yet be presented as a completely finished autonomous retraining system until the referenced retraining and promotion modules are present, tested and executable in the repository.

---

# 22. 🧪 Why Use a Candidate Model?

Automatically replacing the production model after detecting drift would be dangerous.

Imagine:

```text
Drift detected
      ↓
Automatically retrain
      ↓
Automatically replace model
```

The new model could actually be worse.

Instead:

```text
Production Model
      │
      │ remains active
      │
      └───────┐
              ↓
       Candidate Model
              ↓
          Evaluate
              ↓
       Promotion Gate
          /       \
       PASS       FAIL
        ↓           ↓
   Promote       Reject
```

This creates a safety boundary between:

```text
MODEL TRAINING
```

and:

```text
MODEL DEPLOYMENT
```

That separation is one of the most important ideas in the project's MLOps architecture.

---

# 23. 📋 Pipeline Audit Logging

The pipeline records operational information such as:

```text
timestamp
pipeline_status
drift_detected
significant_features
moderate_features
retraining_triggered
retraining_status
promotion_triggered
promotion_status
duration_seconds
```

This allows the pipeline to answer questions such as:

* When was drift detected?
* Which variables were affected?
* Was retraining triggered?
* Did retraining complete?
* Was promotion attempted?
* What was the final pipeline status?
* How long did the pipeline take?

This is stored through the pipeline audit mechanism in:

```text
logs/pipeline_log.json
```

The orchestration implementation explicitly records these states.

---

# 24. 📊 Dashboard

The Streamlit dashboard provides a monitoring layer over the pipeline.

Typical operational information includes:

### Prediction metrics

```text
Total predictions
Benign predictions
Attack predictions
Attack rate
Average attack probability
Maximum attack probability
```

### Temporal behaviour

```text
Attack probability over time
Attack-rate changes
Recent predictions
```

### Drift information

```text
Current drift status
Drifted features
PSI values
```

### Pipeline information

```text
Pipeline status
Retraining status
Promotion status
Audit information
```

The dashboard's purpose is not to replace the NIDS itself.

It provides **observability** into what the NIDS is doing.

---

# 25. 🗂️ Repository Structure

The project is organized around separate concerns:

```text
nids-drift-mlops/
│
├── data/
│   ├── raw/
│   │   └── CICIDS2017 Parquet files
│   │
│   └── processed/
│       └── cicids2017_processed.parquet
│
├── models/
│   └── nids_random_forest.joblib
│
├── logs/
│   ├── nids_predictions.csv
│   ├── drift_detection.csv
│   └── pipeline_log.json
│
├── src/
│   │
│   ├── data/
│   │   ├── loader.py
│   │   └── preprocessor.py
│   │
│   ├── models/
│   │   └── train.py
│   │
│   ├── live/
│   │   ├── flow_builder.py
│   │   ├── predictor.py
│   │   ├── nids.py
│   │   ├── capture.py
│   │   ├── flow_capture.py
│   │   └── interfaces.py
│   │
│   ├── drift/
│   │   ├── detector.py
│   │   └── monitor.py
│   │
│   ├── pipeline/
│   │   └── run.py
│   │
│   └── dashboard/
│       └── app.py
│
├── dashboard.py
├── requirements.txt
├── README.md
└── .gitignore
```

Some modules represent earlier experiments or evolving parts of the project, so the active execution path should be treated as:

```text
preprocessor
      ↓
train
      ↓
live nids
      ↓
prediction log
      ↓
drift detector / monitor
      ↓
pipeline orchestration
```

---

# 26. 🧰 Technology Stack

| Layer               | Technology            |
| ------------------- | --------------------- |
| Language            | Python                |
| Data Processing     | Pandas                |
| Numerical Computing | NumPy                 |
| Machine Learning    | Scikit-learn          |
| Model               | Random Forest         |
| Statistics          | SciPy                 |
| Dataset Storage     | Apache Parquet        |
| Parquet Engine      | PyArrow               |
| Packet Capture      | Scapy                 |
| Model Serialization | Joblib                |
| Dashboard           | Streamlit             |
| Dashboard Refresh   | streamlit-autorefresh |
| Version Control     | Git / GitHub          |

Current pinned dependencies are maintained in `requirements.txt`.

---

# 27. ⚙️ Installation

## Prerequisites

Recommended:

```text
Python 3.x
pip
Git
```

For live packet capture you also need appropriate packet-capture permissions/drivers for your operating system.

On Windows, Scapy commonly requires an Npcap installation.

---

## Clone the Repository

```bash
git clone https://github.com/Akhil6161/nids-drift-mlops.git

cd nids-drift-mlops
```

---

## Create a Virtual Environment

### macOS / Linux

```bash
python3 -m venv .venv

source .venv/bin/activate
```

### Windows

```powershell
python -m venv .venv

.venv\Scripts\activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 28. 📁 Dataset Setup

Place the expected Parquet files inside:

```text
data/raw/
```

The expected structure is:

```text
data/
└── raw/
    ├── Benign-Monday-no-metadata.parquet
    ├── Bruteforce-Tuesday-no-metadata.parquet
    ├── DoS-Wednesday-no-metadata.parquet
    ├── Infiltration-Thursday-no-metadata.parquet
    ├── WebAttacks-Thursday-no-metadata.parquet
    ├── DDoS-Friday-no-metadata.parquet
    ├── Portscan-Friday-no-metadata.parquet
    └── Botnet-Friday-no-metadata.parquet
```

Do not commit the full dataset to Git.

---

# 29. 🧹 Step 1 — Preprocess the Dataset

Run:

```bash
python -m src.data.preprocessor
```

This produces:

```text
data/processed/cicids2017_processed.parquet
```

The preprocessing stage:

```text
Raw Parquet
     ↓
Column cleaning
     ↓
Inf handling
     ↓
Missing-value removal
     ↓
Duplicate removal
     ↓
Binary target creation
     ↓
Processed Parquet
```

---

# 30. 🤖 Step 2 — Train the Model

Run:

```bash
python -m src.models.train
```

The training process:

```text
Processed dataset
       ↓
Feature / target separation
       ↓
Numerical feature selection
       ↓
Train-test split
       ↓
Random Forest training
       ↓
Evaluation
       ↓
Joblib serialization
```

Output:

```text
models/nids_random_forest.joblib
```

---

# 31. 🌐 Step 3 — Identify Network Interfaces

Use the interface utility:

```bash
python -m src.live.interfaces
```

Find the interface through which you want to observe traffic.

The current live NIDS configuration contains a machine-specific interface value, so it must be updated for the environment where the project is executed.

This is currently one of the portability limitations of the project.

---

# 32. 🚦 Step 4 — Start Live NIDS

After configuring the interface:

```bash
python -m src.live.nids
```

The system will:

```text
Capture packets
      ↓
Build flows
      ↓
Accumulate packets
      ↓
Generate features
      ↓
Run prediction
      ↓
Calculate attack probability
      ↓
Write prediction log
```

Stop capture using:

```text
Ctrl + C
```

Predictions are written to:

```text
logs/nids_predictions.csv
```

---

# 33. 📉 Step 5 — Run Drift Detection

Once enough predictions have been collected:

```bash
python -m src.drift.detector
```

The detector requires:

```text
1000 reference predictions
+
100 current predictions
```

It then evaluates:

```text
packets
bytes
attack_probability
```

and writes:

```text
logs/drift_detection.csv
```

---

# 34. 🔄 Step 6 — Continuous Drift Monitoring

Run:

```bash
python -m src.drift.monitor
```

The monitor periodically checks whether new predictions have arrived.

Current polling interval:

```text
30 seconds
```

The monitor then reruns drift detection when new data is available.

---

# 35. 🧠 Step 7 — Run the MLOps Pipeline

The orchestration layer can be started with:

```bash
python -m src.pipeline.run
```

The intended execution flow is:

```text
Prediction Log Check
        ↓
Drift Detection
        ↓
Drift Analysis
        ↓
Significant Drift?
        │
   ┌────┴────┐
   │         │
  NO        YES
   │         │
   ↓         ↓
Keep      Retrain
Model     Candidate
             ↓
          Evaluate
             ↓
        Promotion Gate
             ↓
      Promote / Reject
             ↓
        Audit Logging
```

The pipeline implementation explicitly follows this state machine.

---

# 36. 📊 Step 8 — Start Dashboard

Launch Streamlit:

```bash
streamlit run dashboard.py
```

The dashboard can then be used to inspect:

```text
Prediction activity
Attack probability
Attack rate
Recent predictions
Drift status
Pipeline information
```

---

# 37. 🧪 Safe Demonstration Strategy

The project should distinguish between:

### Live monitoring

Real packets captured from the configured network interface.

and:

### Controlled demonstration

Previously collected CICIDS2017 samples used to demonstrate the ML detection and monitoring workflow.

The controlled demonstration should **not generate an actual attack**.

It simply replays known labelled traffic data through the model.

This makes the project suitable for:

* classroom demonstrations
* project evaluations
* dashboards
* testing
* presentations

without intentionally attacking another system.

---

# 38. 🔐 Security Considerations

This project operates at the packet-capture layer.

Running packet capture may require elevated privileges depending on the operating system and capture driver.

Be careful when deploying it on networks that you do not own or have permission to monitor.

The system should be used only on:

```text
Your own network
Laboratory environments
Authorized test environments
```

The project is intended for defensive security research and education.

---

# 39. ⚠️ Important Current Limitations

This section is deliberately explicit.

### 1. Drift monitoring is currently PSI-based

The architecture originally considered PSI + KS, but the current detector implementation calculates PSI.

Therefore the current system should be described as:

> **PSI-based distribution-shift monitoring**

rather than claiming that both PSI and KS are currently active.

---

### 2. Drift does not prove model degradation

A high PSI indicates that a monitored distribution changed.

It does not prove:

```text
model accuracy ↓
```

without ground-truth evaluation.

A stronger future design would connect drift events with delayed labels or validated attack/benign outcomes.

---

### 3. Live feature parity is incomplete

The live flow builder contains eight active/idle timing features that are currently set to zero.

Therefore:

```text
Offline feature representation
        ≠
Perfectly equivalent live feature representation
```

This can affect live prediction quality.

The exact CICIDS2017 feature calculation should eventually be reproduced for these fields.

---

### 4. Network interface configuration is hardcoded

The live capture interface is currently configured directly inside the source code.

This is not portable.

A better implementation would support:

```bash
python -m src.live.nids --interface <interface>
```

or:

```text
.env
config.yaml
environment variable
```

---

### 5. CSV is not a production-scale event store

CSV is useful for:

* prototyping
* debugging
* demonstrations
* local analysis

but is not ideal for:

* high-throughput production traffic
* concurrent writes
* large historical datasets
* distributed monitoring

A production version could use:

```text
Kafka
PostgreSQL
ClickHouse
MongoDB
Object Storage
```

depending on the architecture.

---

### 6. Candidate retraining and promotion need to be fully integrated

The pipeline orchestrator contains calls for:

```text
src.models.retrain
src.models.promote
```

but those components need to exist and be validated as part of the runnable repository before the project should claim completely autonomous model replacement.

---

### 7. No production-grade model registry yet

The current system uses Joblib artifacts.

A stronger MLOps implementation could introduce:

```text
MLflow Model Registry
```

or another model registry to track:

```text
Model version
Training dataset
Metrics
Drift trigger
Promotion decision
Deployment timestamp
Rollback version
```

---

### 8. No complete CI/CD pipeline yet

A mature version should include:

```text
Git Push
   ↓
Automated Tests
   ↓
Linting
   ↓
Model/Data Validation
   ↓
Build
   ↓
Deployment
```

---

# 40. 🛠️ Recommended Future Architecture

The project can evolve from a student prototype into a more production-oriented architecture:

```text
                         NETWORK
                           │
                           ▼
                    Packet Capture
                           │
                           ▼
                   Flow Construction
                           │
                           ▼
                  Feature Extraction
                           │
                           ▼
                    Model Serving
                           │
                           ▼
                     Predictions
                           │
                 ┌─────────┴─────────┐
                 │                   │
                 ▼                   ▼
            Event Store          Dashboard
                 │
                 ▼
           Drift Monitor
                 │
                 ▼
          Drift Alert/Event
                 │
                 ▼
          Candidate Training
                 │
                 ▼
          Offline Evaluation
                 │
                 ▼
            Model Registry
                 │
                 ▼
           Promotion Gate
             /       \
            /         \
        Approved     Rejected
           │             │
           ▼             ▼
     Production       Existing
        Model           Model
           │
           ▼
       Monitoring
           │
           └───────────────┐
                           │
                           ▼
                      Next Cycle
```

Potential technologies:

| Requirement      | Possible Technology         |
| ---------------- | --------------------------- |
| Streaming        | Kafka                       |
| Storage          | PostgreSQL / ClickHouse     |
| Model Registry   | MLflow                      |
| Drift Monitoring | Evidently / custom PSI + KS |
| API              | FastAPI                     |
| Containers       | Docker                      |
| Orchestration    | Kubernetes                  |
| CI/CD            | GitHub Actions              |
| Cloud            | AWS                         |
| Metrics          | Prometheus                  |
| Dashboards       | Grafana / Streamlit         |

These are **future architecture options**, not technologies currently implemented in the repository.

---

# 41. 🧩 Why This Project Is an MLOps Project

The important part of this project is not simply:

```text
Random Forest + CICIDS2017
```

That alone is a conventional ML classification project.

The MLOps component comes from the lifecycle:

```text
Train
  ↓
Deploy
  ↓
Predict
  ↓
Log
  ↓
Monitor
  ↓
Detect distribution shift
  ↓
Trigger retraining
  ↓
Evaluate candidate
  ↓
Promotion decision
  ↓
Deploy new version
  ↓
Monitor again
```

This introduces the idea of a **closed ML lifecycle**.

The model becomes one component inside a larger operational system.

---

# 42. 🔬 Research Motivation

The project is inspired by research into label-independent concept-drift detection for network intrusion detection, particularly work exploring how changes in network behaviour can be detected without continuously requiring ground-truth labels.

The project adapts that general idea to a smaller, practical student-scale architecture:

```text
Reference Traffic
       ↓
Current Traffic
       ↓
Statistical Comparison
       ↓
Drift Signal
       ↓
Potential Model Update
```

The implementation intentionally separates:

```text
Detection
```

from:

```text
Model Lifecycle
```

so that a drift signal does not automatically imply blind model replacement.

---

# 43. 📈 What the Dashboard Should Answer

A useful monitoring dashboard should answer operational questions quickly.

### Question 1

> How much traffic has been processed?

```text
Total Predictions
```

### Question 2

> How much traffic is being classified as malicious?

```text
Attack Count
Attack Rate
```

### Question 3

> How confident is the model?

```text
Attack Probability
```

### Question 4

> Is current traffic behaving differently?

```text
PSI
Drift Status
```

### Question 5

> What changed?

```text
Affected Variables
```

### Question 6

> Did the MLOps system react?

```text
Retraining Status
Promotion Status
Pipeline Status
```

This turns the dashboard from a simple visualization into an **operational observability layer**.

---

# 44. 🧭 Design Principles

The project follows several important design principles.

### Principle 1 — Separate inference from monitoring

```text
Prediction ≠ Monitoring
```

The model should make predictions while a separate component observes behaviour.

---

### Principle 2 — Drift should trigger investigation, not blind deployment

```text
Drift
 ↓
Candidate Model
 ↓
Evaluation
 ↓
Promotion Decision
```

not:

```text
Drift
 ↓
Overwrite Production
```

---

### Principle 3 — Preserve the production model

The production model should remain available until a candidate passes evaluation.

---

### Principle 4 — Log everything important

Without logs, it is difficult to answer:

```text
What happened?
When?
Why?
Which model?
What data?
What triggered retraining?
Why was a model promoted?
```

---

### Principle 5 — Reproduce the training feature schema

If the model is trained on:

```text
77 features
```

the live inference pipeline must reproduce those features with compatible definitions.

Feature mismatch is one of the biggest risks in deploying offline-trained network models to live traffic.

---

# 45. 🧪 Example Lifecycle

Imagine the system begins with:

```text
1000 reference predictions
```

and the traffic initially resembles the training environment.

The detector reports:

```text
NO_DRIFT
```

The production model remains active.

Later, the newest traffic window contains a different distribution:

```text
Packets       ↑
Bytes         ↑
Attack prob.  ↑
```

PSI increases.

The detector reports:

```text
SIGNIFICANT_DRIFT
```

The MLOps pipeline can then initiate:

```text
Candidate Training
        ↓
Candidate Evaluation
        ↓
Promotion Gate
```

If the candidate passes:

```text
Candidate → Production
```

If it fails:

```text
Candidate → Rejected
Production → Unchanged
```

This is the central lifecycle the project is designed to demonstrate.

---

# 46. 🗺️ Development Roadmap

## Phase 1 — Completed/Core

* [x] CICIDS2017 loading
* [x] Data cleaning
* [x] Binary target generation
* [x] Random Forest training
* [x] Model serialization
* [x] Scapy packet capture
* [x] Bidirectional flow reconstruction
* [x] Live feature extraction
* [x] Real-time prediction
* [x] Prediction logging
* [x] PSI drift detection
* [x] Basic continuous monitoring
* [x] Streamlit monitoring

## Phase 2 — MLOps Hardening

* [ ] Fully integrate candidate retraining
* [ ] Fully integrate candidate evaluation
* [ ] Fully integrate promotion gate
* [ ] Model versioning
* [ ] Rollback support
* [ ] Better pipeline state management
* [ ] Reproducible configuration
* [ ] Automated tests

## Phase 3 — Production Architecture

* [ ] Replace CSV with persistent event storage
* [ ] Add model registry
* [ ] Add FastAPI inference service
* [ ] Containerize services
* [ ] Add CI/CD
* [ ] Add metrics and alerting
* [ ] Cloud deployment
* [ ] Scalable packet ingestion

## Phase 4 — Advanced Drift Monitoring

* [ ] Add KS testing
* [ ] Compare multiple drift signals
* [ ] Add ground-truth based performance monitoring
* [ ] Detect prediction drift separately from feature drift
* [ ] Add delayed-label evaluation
* [ ] Add drift history
* [ ] Add automated rollback

---

# 47. 📚 Key Learning Outcomes

This project demonstrates practical experience with:

### Machine Learning

* Binary classification
* Random Forest
* Class imbalance
* Train/test splitting
* Model evaluation
* Model serialization

### Network Security

* Network packet capture
* TCP/UDP traffic
* Bidirectional flows
* Network-flow features
* Intrusion detection

### Statistics

* Distribution comparison
* Population Stability Index
* Drift thresholds
* Reference/current windows

### MLOps

* Prediction logging
* Model monitoring
* Drift detection
* Candidate retraining
* Model promotion
* Audit logging
* Model lifecycle management

### Software Engineering

* Modular Python architecture
* CLI execution
* Pipeline orchestration
* File-based persistence
* Dashboard development
* Git/GitHub workflow

---

# 48. 👥 Team

This project was developed as a team minor project by:

* **Akhil6161**
* **realadityagupta**

The repository is maintained as a collaborative academic project.

---

# 49. 📄 Project Scope

This project is intended as:

```text
Academic research
+
MLOps demonstration
+
Network-security experimentation
+
Real-time ML monitoring
```

It is **not intended to be presented as a production enterprise IDS** without additional work around:

* feature parity
* scalable storage
* model registry
* security hardening
* deployment
* testing
* rollback
* observability
* ground-truth performance monitoring

Being explicit about these boundaries makes the project technically more credible.

---

# 50. ⭐ Why This Project Matters

The core idea is simple:

> **Machine-learning deployment does not end when a model is trained.**

For a network intrusion detection system:

```text
The network changes.
       ↓
The data changes.
       ↓
The model's assumptions may change.
       ↓
The system must detect that change.
       ↓
A candidate model can be trained.
       ↓
The candidate must be evaluated.
       ↓
Only then should production change.
```

That is the central engineering problem this project explores.

---

## 🔗 Repository

**GitHub:**
https://github.com/Akhil6161/nids-drift-mlops

---

## 📌 One-Line Summary

> **A flow-based real-time Network Intrusion Detection System that combines CICIDS2017-trained Random Forest inference with live packet capture, prediction logging, PSI-based drift monitoring, and an MLOps architecture for candidate retraining and controlled model promotion.**

---

## ⚠️ Current Technical Disclaimer

The project is a student/research prototype. Live packet capture, feature extraction, drift detection and model lifecycle components are under active development. Statistical drift should not be interpreted as proof of model-performance degradation without ground-truth evaluation.
