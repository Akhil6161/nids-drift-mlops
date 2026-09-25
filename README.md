# 🛡️ NIDS Drift MLOps

## Real-Time Network Intrusion Detection with Concept-Drift Monitoring and Automated Model Lifecycle

**NIDS Drift MLOps** is an end-to-end Network Intrusion Detection System that combines **machine learning, live network traffic monitoring, flow-based feature extraction, prediction logging, concept-drift monitoring, and an MLOps model lifecycle**.

The system is trained using the **CICIDS2017** dataset and uses a **Random Forest classifier** to identify network traffic as either benign or potentially malicious.

Unlike a traditional NIDS that stops at model prediction, this project also monitors incoming prediction behaviour for distribution changes and provides an architecture for **candidate model retraining, evaluation, and controlled promotion**.

### Core Pipeline

```text
Network Traffic
      ↓
Packet Capture
      ↓
Flow Reconstruction
      ↓
Feature Extraction
      ↓
Random Forest Prediction
      ↓
Prediction Logging
      ↓
Drift Detection
      ↓
Candidate Retraining
      ↓
Candidate Evaluation
      ↓
Promotion Gate
      ↓
Production Model
```

---

# 🎯 Problem Statement

Machine-learning models are trained using historical data, but network traffic is not static.

Applications, users, protocols, workloads, and attack patterns can change over time. As a result, the traffic observed after deployment may differ from the traffic used during training.

A traditional ML-based NIDS generally follows:

```text
Dataset → Training → Model → Prediction
```

This project extends that lifecycle:

```text
Training
   ↓
Deployment
   ↓
Prediction
   ↓
Monitoring
   ↓
Drift Detection
   ↓
Candidate Retraining
   ↓
Evaluation
   ↓
Promotion / Rejection
```

The objective is to make the model **observable and maintainable after deployment**, rather than treating training as the final step.

---

# 🚀 Key Features

### Machine Learning

* Random Forest intrusion detection model
* Binary classification
* CICIDS2017 training data
* 77 network-flow features
* Class-balanced training
* Train/test evaluation
* Joblib model serialization

### Live Network Monitoring

* Packet capture using Scapy
* TCP/UDP traffic handling
* Bidirectional flow reconstruction
* Flow-level feature extraction
* Real-time prediction
* Attack probability calculation
* Prediction logging

### Drift Monitoring

* Population Stability Index (PSI)
* Reference vs current traffic windows
* Drift severity classification
* Continuous monitoring
* Drift result logging

### MLOps

* Drift-triggered pipeline architecture
* Candidate model retraining
* Candidate evaluation
* Promotion gate
* Production-model protection
* Pipeline audit logging

### Dashboard

* Prediction statistics
* Attack rate
* Attack probability
* Recent predictions
* Drift status
* Significant drift features
* Pipeline status
* Retraining/promotion information

---

# 🏗️ System Architecture

```text
                         ┌──────────────────────┐
                         │     CICIDS2017       │
                         │    Training Data     │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Data Preprocessing   │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Random Forest      │
                         │      Training        │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Production Model   │
                         └──────────┬───────────┘
                                    │
                                    │
             ┌──────────────────────┴─────────────────────┐
             │                                            │
             ▼                                            ▼
    ┌──────────────────┐                         ┌──────────────────┐
    │  Live Network    │                         │ Controlled Data  │
    │     Traffic      │                         │   Demonstration   │
    └────────┬─────────┘                         └────────┬─────────┘
             │                                            │
             └──────────────────┬─────────────────────────┘
                                ▼
                     ┌──────────────────────┐
                     │ Flow Reconstruction  │
                     └──────────┬───────────┘
                                ▼
                     ┌──────────────────────┐
                     │ Feature Extraction   │
                     └──────────┬───────────┘
                                ▼
                     ┌──────────────────────┐
                     │ Model Prediction     │
                     └──────────┬───────────┘
                                │
                     ┌──────────┴──────────┐
                     ▼                     ▼
              ┌─────────────┐       ┌──────────────┐
              │ Prediction  │       │    Attack    │
              │   Logging   │       │ Probability  │
              └──────┬──────┘       └──────┬───────┘
                     │                     │
                     └──────────┬──────────┘
                                ▼
                     ┌──────────────────────┐
                     │   Prediction Log     │
                     └──────────┬───────────┘
                                ▼
                     ┌──────────────────────┐
                     │   Drift Detection    │
                     │        PSI            │
                     └──────────┬───────────┘
                                │
                        Significant Drift?
                         ┌──────┴──────┐
                        NO             YES
                        │               │
                        ▼               ▼
                 Keep Current     Candidate Model
                    Model            Retraining
                                        │
                                        ▼
                                  Evaluation
                                        │
                                        ▼
                                 Promotion Gate
                                  /          \
                               PASS          FAIL
                                │              │
                                ▼              ▼
                           New Model      Existing Model
                           Promoted         Retained
```

---

# 📊 Dataset

The project uses the **CICIDS2017** intrusion-detection dataset.

The original dataset contains multiple traffic and attack categories. For this project, the labels are converted into a binary classification problem:

| Target | Meaning |
| -----: | ------- |
|    `0` | Benign  |
|    `1` | Attack  |

Attack categories represented in the source dataset include:

* DoS
* DDoS
* PortScan
* Brute Force
* Web Attacks
* Infiltration
* Botnet
* Heartbleed

The raw dataset is not included in the repository because of its size.

The processed training data contains **77 model features** and one binary target.

---

# 🧹 Data Preprocessing

The preprocessing pipeline performs the following operations:

```text
Raw CICIDS2017 Data
        ↓
Column Normalization
        ↓
Remove Invalid Values
        ↓
Handle Missing Values
        ↓
Remove Duplicates
        ↓
Convert Labels to Binary
        ↓
Processed Parquet Dataset
```

Column names are normalized so that fields such as:

```text
Flow Duration
```

become:

```text
Flow_Duration
```

Infinite and invalid values are removed, missing rows are handled, duplicate records are removed, and the original attack labels are converted into:

```text
Benign → 0
Attack → 1
```

The processed dataset is stored as:

```text
data/processed/cicids2017_processed.parquet
```

---

# 🤖 Machine Learning Model

The baseline model is a:

```text
Random Forest Classifier
```

with the current configuration:

```python
RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)
```

### Why Random Forest?

Network-flow data is structured tabular data containing many statistical and traffic-related features.

Random Forest is useful for this project because it:

* handles nonlinear relationships
* works well with tabular features
* does not require feature scaling
* can handle many input features
* supports class weighting
* provides a strong baseline for experimentation

The dataset is split using an **80/20 stratified train-test split**.

The resulting model is serialized using Joblib:

```text
models/nids_random_forest.joblib
```

---

# 🌐 Live Network Traffic Detection

The live NIDS uses **Scapy** to capture packets from a configured network interface.

The packet-processing pipeline is:

```text
Packet
  ↓
IP / IPv6
  ↓
TCP / UDP
  ↓
Flow Identification
  ↓
Flow Statistics
  ↓
Feature Extraction
  ↓
Model Prediction
```

The system extracts information such as:

* source IP
* destination IP
* source port
* destination port
* protocol
* packet length
* TCP flags
* TCP window size
* header information
* timestamps

---

# 🔄 Bidirectional Flow Reconstruction

Instead of treating every packet independently, packets are grouped into flows.

A flow is identified using information similar to:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

Both communication directions are associated with the same flow.

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

belong to the same communication flow.

This is important because many network-flow features depend on comparing forward and backward traffic.

---

# 📐 Feature Extraction

The live flow builder attempts to reproduce the feature representation used by the CICIDS2017 model.

The feature set includes categories such as:

* Flow duration
* Forward/backward packet counts
* Forward/backward byte counts
* Packet length statistics
* Packet inter-arrival times
* Packet rates
* Header lengths
* TCP flags
* TCP window sizes
* Forward/backward traffic statistics

The model expects **77 numerical features**.

Maintaining feature consistency between:

```text
Offline Training
        ↕
Live Inference
```

is critical because the model must receive features with compatible meaning and ordering.

---

# ⚡ Real-Time Prediction

The live system performs rolling predictions as flows accumulate packets.

The current configuration starts prediction after a minimum number of packets and continues predicting periodically as additional packets arrive.

Each prediction contains information such as:

```text
Timestamp
Source / Destination
Protocol
Packet Count
Byte Count
Prediction
Label
Attack Probability
Traffic Source
```

Example:

```json
{
  "prediction": 1,
  "label": "ATTACK",
  "attack_probability": 0.94
}
```

Predictions are stored in:

```text
logs/nids_predictions.csv
```

This log becomes the input to the monitoring and drift-detection pipeline.

---

# 📉 Concept Drift Monitoring

Network behaviour can change after deployment.

For example:

```text
Normal Traffic
      ↓
New Application / Usage Pattern
      ↓
Different Traffic Distribution
      ↓
Distribution Shift
```

The project monitors this change using **Population Stability Index (PSI)**.

The current detector compares:

```text
Reference Window
        vs
Recent Window
```

and monitors variables including:

```text
packets
bytes
attack_probability
```

---

# 📊 PSI Drift Classification

The current implementation uses:

|            PSI | Classification      |
| -------------: | ------------------- |
|       `< 0.10` | `NO_DRIFT`          |
| `0.10 – <0.25` | `MODERATE_DRIFT`    |
|       `≥ 0.25` | `SIGNIFICANT_DRIFT` |

Conceptually:

```text
Reference Distribution
          │
          │
          ▼
     ┌──────────┐
     │   PSI    │
     └────┬─────┘
          │
          ▼
    Drift Severity
```

### Important distinction

PSI detects a **distribution shift**.

It does not directly prove that:

```text
Model accuracy has decreased
```

because that would require reliable ground-truth labels or another evaluation mechanism.

Therefore, the project treats drift as a **signal to investigate/retrain**, rather than proof that the production model has failed.

---

# 🔁 Automated MLOps Workflow

The MLOps component is designed around the idea that detecting drift should **not automatically overwrite the production model**.

Instead:

```text
Prediction Log
      ↓
Drift Detection
      ↓
Significant Drift
      ↓
Candidate Retraining
      ↓
Candidate Evaluation
      ↓
Promotion Gate
```

The candidate model is evaluated before it can replace the production model.

### If the candidate passes

```text
Candidate
   ↓
Promoted
   ↓
Production Model Updated
```

### If the candidate fails

```text
Candidate
   ↓
Rejected
   ↓
Production Model Unchanged
```

This protects the currently deployed model from an unsuccessful automatic retraining cycle.

---

# 📋 Pipeline Logging

The pipeline records information such as:

* pipeline status
* drift status
* significant features
* retraining status
* promotion status
* execution time

This provides an audit trail for understanding:

```text
When did drift occur?
What changed?
Was retraining triggered?
Was a candidate produced?
Was it promoted?
```

---

# 📊 Streamlit Dashboard

The project includes a Streamlit dashboard for monitoring the NIDS.

The dashboard provides visibility into:

### Traffic

* Total predictions
* Benign predictions
* Attack predictions
* Attack rate
* Traffic source

### Model behaviour

* Average attack probability
* Maximum attack probability
* Recent predictions
* Probability changes

### Drift

* Drift status
* Drifted features
* PSI values
* Recent distribution changes

### MLOps

* Pipeline status
* Retraining status
* Promotion status
* Audit information

Start the dashboard using:

```bash
streamlit run dashboard.py
```

---

# 🧪 Controlled Attack Demonstration

The project can demonstrate attack detection using **existing labelled CICIDS2017 attack samples**.

It does not require generating a real attack.

The demonstration flow is:

```text
Known CICIDS2017 Sample
        ↓
Feature Representation
        ↓
Trained Model
        ↓
Prediction
        ↓
Dashboard / Logs
```

This provides a safer way to demonstrate the detection pipeline in an academic environment.

---

# 🛠️ Technology Stack

| Component           | Technology     |
| ------------------- | -------------- |
| Language            | Python         |
| Machine Learning    | Scikit-learn   |
| Model               | Random Forest  |
| Data Processing     | Pandas / NumPy |
| Dataset             | CICIDS2017     |
| Dataset Storage     | Apache Parquet |
| Parquet Engine      | PyArrow        |
| Statistics          | SciPy          |
| Packet Capture      | Scapy          |
| Model Serialization | Joblib         |
| Dashboard           | Streamlit      |
| Version Control     | Git / GitHub   |

---

# 📁 Project Structure

```text
nids-drift-mlops/
│
├── data/
│   ├── raw/
│   └── processed/
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
│   │   └── nids.py
│   │
│   ├── drift/
│   │   ├── detector.py
│   │   └── monitor.py
│   │
│   ├── pipeline/
│   │   └── run.py
│   │
│   └── dashboard/
│
├── dashboard.py
├── requirements.txt
└── README.md
```

---

# ⚙️ Installation & Usage

## 1. Clone Repository

```bash
git clone https://github.com/Akhil6161/nids-drift-mlops.git
cd nids-drift-mlops
```

## 2. Create Virtual Environment

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

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## 4. Add Dataset

Place the required CICIDS2017 Parquet files inside:

```text
data/raw/
```

## 5. Preprocess

```bash
python -m src.data.preprocessor
```

## 6. Train Model

```bash
python -m src.models.train
```

## 7. Start Live NIDS

Configure the appropriate network interface and run:

```bash
python -m src.live.nids
```

## 8. Run Drift Detection

```bash
python -m src.drift.detector
```

## 9. Start Dashboard

```bash
streamlit run dashboard.py
```

---

# ⚠️ Current Limitations

This project is a **student/research prototype**, not a production enterprise IDS.

Current limitations include:

* PSI is currently the active drift detector; KS testing is not yet part of the implementation.
* Live feature extraction still needs complete parity with every offline CICIDS2017 feature.
* Prediction storage currently uses CSV.
* Network-interface configuration needs better environment-based configuration.
* Candidate retraining and promotion components are still being integrated/hardened.
* No production model registry is currently used.
* No complete CI/CD deployment pipeline is included yet.
* Drift detection alone does not establish actual model-performance degradation.

These are planned areas for further development.

---

# 🔮 Future Improvements

```text
Current System
      ↓
Complete Feature Parity
      ↓
PSI + KS Drift Detection
      ↓
Ground-Truth Performance Monitoring
      ↓
MLflow Model Registry
      ↓
FastAPI Model Serving
      ↓
Docker Deployment
      ↓
CI/CD with GitHub Actions
      ↓
AWS Deployment
      ↓
Automated Rollback
```

Other possible improvements include:

* Kafka-based traffic/event streaming
* PostgreSQL or ClickHouse for prediction storage
* Prometheus/Grafana monitoring
* Model versioning
* Model rollback
* Automated testing
* Alerting
* Kubernetes deployment

---

# 🎓 What This Project Demonstrates

This project brings together several areas of computer science and engineering:

### Machine Learning

* Classification
* Random Forest
* Feature engineering
* Class imbalance
* Model evaluation

### Cybersecurity

* Network traffic analysis
* Packet capture
* Flow reconstruction
* Intrusion detection

### Statistics

* Distribution comparison
* Population Stability Index
* Drift thresholds

### MLOps

* Prediction monitoring
* Drift detection
* Candidate retraining
* Model evaluation
* Promotion gates
* Pipeline auditing

### Software Engineering

* Modular architecture
* Python packages
* CLI workflows
* Logging
* Dashboard development
* Git/GitHub

---

# 👥 Team

Developed as a team minor project by:

**Akhil6161 · realadityagupta**

---

# 📌 Project Summary

> **NIDS Drift MLOps is a real-time network intrusion detection system that combines CICIDS2017-trained Random Forest classification with Scapy-based live traffic monitoring, flow-level feature extraction, prediction logging, PSI-based drift detection, and an MLOps workflow for controlled candidate retraining and model promotion.**

### Repository

[GitHub — NIDS Drift MLOps](https://github.com/Akhil6161/nids-drift-mlops)
