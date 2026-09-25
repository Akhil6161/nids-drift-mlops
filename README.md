\# NIDS Drift MLOps - Real Time Network Intrusion Detection with Concept-Drift Monitoring



\## Network Intrusion Detection System with Live Traffic Monitoring, Concept Drift Detection and Automated Model Retraining



An end-to-end Network Intrusion Detection System (NIDS) that combines machine learning, live network traffic monitoring, concept drift detection, automated candidate retraining, and model promotion into a practical MLOps workflow.



The system is designed to detect network traffic that may represent an intrusion, continuously record predictions, monitor changes in prediction behaviour, and automatically retrain a candidate model when significant drift is detected.



This is the team's minor project (with Akhil6161 and realadityagupta), building on Drago et al.'s research on unsupervised, label-independent concept-drift detection for network intrusion detection, adapted to a real-time student-project scale.

\---



\## 1. Project Overview



Traditional machine-learning based intrusion detection systems can become less effective when network traffic changes over time.



This project addresses that problem by combining:



\*\*Network Traffic → Feature Extraction → ML Prediction → Prediction Logging → Drift Detection → Candidate Retraining → Model Evaluation → Promotion Gate → Production Model\*\*



The system supports both:



1\. \*\*Live network traffic monitoring\*\*

2\. \*\*Controlled attack demonstration using known CICIDS2017 attack samples\*\*



The controlled demonstration does not generate a real cyber attack. It replays existing labelled attack samples from the processed CICIDS2017 dataset through the trained model so that the detection and dashboard workflow can be demonstrated safely.



\---



\## 2. Key Features



\### Machine Learning



\- Random Forest based intrusion detection model

\- Binary classification:

&#x20; - `0` = Benign

&#x20; - `1` = Attack

\- Model training using CICIDS2017

\- Candidate model generation during retraining

\- Candidate model evaluation using accuracy, precision, recall and F1 score



\### Live Network Monitoring



\- Packet capture using Scapy

\- Live traffic feature collection

\- Real-time model prediction

\- Attack probability calculation

\- Prediction logging to CSV

\- Traffic source tracking



\### Concept Drift Detection



The system monitors changes in prediction behaviour using:



\- Population Stability Index (PSI)

\- Kolmogorov-Smirnov (KS) statistical testing



The drift detector classifies features as:



\- `NO\_DRIFT`

\- `MODERATE\_DRIFT`

\- `SIGNIFICANT\_DRIFT`



Significant drift can trigger automated candidate retraining.



\### Automated MLOps Pipeline



The automated pipeline performs:



1\. Prediction-log pre-check

2\. Drift detection

3\. Drift result analysis

4\. Candidate model retraining when significant drift is detected

5\. Candidate model evaluation

6\. Model promotion gate

7\. Pipeline audit logging



The production model is only replaced when the candidate model satisfies the configured promotion criterion.



\### Streamlit Dashboard



The dashboard provides visibility into:



\- Pipeline status

\- Drift status

\- Retraining status

\- Model promotion status

\- Total predictions

\- Benign predictions

\- Attack predictions

\- Attack rate

\- Average attack probability

\- Maximum attack probability

\- Recent probability changes

\- Recent attack-rate changes

\- Significant drift features

\- Traffic source

\- Live traffic predictions

\- Controlled demonstration predictions

\- Pipeline audit information

\- Model promotion information



\---



\## 3. Technology Stack



| Component | Technology |

|---|---|

| Programming Language | Python 3.13 |

| Machine Learning | Scikit-learn |

| ML Model | Random Forest |

| Data Processing | Pandas, NumPy |

| Statistical Analysis | SciPy |

| Dataset Format | Apache Parquet |

| Parquet Engine | PyArrow |

| Live Packet Capture | Scapy |

| Model Serialization | Joblib |

| Dashboard | Streamlit |

| Dashboard Auto Refresh | streamlit-autorefresh |

| Version Control | Git / GitHub |



\---



\## 4. Dataset



The project uses the \*\*CICIDS2017\*\* intrusion detection dataset.



The processed dataset contains network-flow features and a binary target used for model training.



\### Binary classification



| Target | Meaning |

|---:|---|

| `0` | Benign |

| `1` | Attack |



The processed dataset used by the current project contains:



\- \*\*2,231,806 cleaned samples\*\*

\- \*\*77 model features\*\*

\- \*\*1 binary target column\*\*



\### Attack categories present in the source data



The dataset includes traffic associated with categories such as:



\- DoS

\- DDoS

\- PortScan

\- Brute Force

\- Web Attacks

\- Infiltration

\- Botnet

\- Heartbleed



The original raw dataset is intentionally excluded from Git because of its size.



\---



\## 5. Project Architecture



```text

&#x20;                   ┌───────────────────────┐

&#x20;                   │   Network Traffic     │

&#x20;                   └───────────┬───────────┘

&#x20;                               │

&#x20;                               ▼

&#x20;                   ┌───────────────────────┐

&#x20;                   │  Scapy Packet Capture │

&#x20;                   └───────────┬───────────┘

&#x20;                               │

&#x20;                               ▼

&#x20;                   ┌───────────────────────┐

&#x20;                   │ Feature Extraction    │

&#x20;                   └───────────┬───────────┘

&#x20;                               │

&#x20;                               ▼

&#x20;                   ┌───────────────────────┐

&#x20;                   │ Random Forest Model   │

&#x20;                   └───────────┬───────────┘

&#x20;                               │

&#x20;                   ┌───────────┴───────────┐

&#x20;                   │                       │

&#x20;                   ▼                       ▼

&#x20;            ┌──────────────┐      ┌────────────────┐

&#x20;            │ Prediction   │      │ Attack         │

&#x20;            │ Logging      │      │ Probability    │

&#x20;            └──────┬───────┘      └───────┬────────┘

&#x20;                   │                      │

&#x20;                   └──────────┬───────────┘

&#x20;                              ▼

&#x20;                   ┌───────────────────────┐

&#x20;                   │ Prediction Log        │

&#x20;                   └───────────┬───────────┘

&#x20;                               │

&#x20;                               ▼

&#x20;                   ┌───────────────────────┐

&#x20;                   │ Drift Detection       │

&#x20;                   │ PSI + KS Test         │

&#x20;                   └───────────┬───────────┘

&#x20;                               │

&#x20;                        Significant Drift?

&#x20;                         ┌─────┴─────┐

&#x20;                        NO           YES

&#x20;                        │             │

&#x20;                        ▼             ▼

&#x20;                 ┌────────────┐  ┌────────────────┐

&#x20;                 │ Production │  │ Candidate      │

&#x20;                 │ Unchanged  │  │ Retraining     │

&#x20;                 └────────────┘  └───────┬────────┘

&#x20;                                         │

&#x20;                                         ▼

&#x20;                                 ┌────────────────┐

&#x20;                                 │ Candidate      │

&#x20;                                 │ Evaluation     │

&#x20;                                 └───────┬────────┘

&#x20;                                         │

&#x20;                                         ▼

&#x20;                                 ┌────────────────┐

&#x20;                                 │ Promotion Gate │

&#x20;                                 └───────┬────────┘

&#x20;                                         │

&#x20;                                  ┌──────┴──────┐

&#x20;                                  │             │

&#x20;                             PROMOTED      NOT PROMOTED

&#x20;                                  │             │

&#x20;                                  ▼             ▼

&#x20;                             Production    Production

&#x20;                               Model         Model

&#x20;                             Updated       Unchanged
