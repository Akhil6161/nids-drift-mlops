import os
import json
import pandas as pd
import streamlit as st


# ============================================================
# CONFIGURATION
# ============================================================

PREDICTION_FILE = "logs/nids_predictions.csv"
DRIFT_FILE = "logs/drift_detection.csv"
PIPELINE_LOG_FILE = "logs/pipeline_log.json"
PROMOTION_LOG_FILE = "models/promotion_log.json"

REFERENCE_SIZE = 1000
CURRENT_SIZE = 100


st.set_page_config(
    page_title="NIDS MLOps Dashboard",
    page_icon="Shield",
    layout="wide",
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def load_csv(path):
    """Load a CSV file safely."""

    if not os.path.exists(path):
        return None

    try:
        df = pd.read_csv(path)

        if df.empty:
            return None

        df.columns = df.columns.str.strip()

        return df

    except Exception as e:
        st.error(f"Could not read {path}: {e}")
        return None


def load_json(path):
    """Load a JSON file safely."""

    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception as e:
        st.warning(f"Could not read {path}: {e}")
        return None


def calculate_window_metrics(predictions):
    """
    Calculate probability and attack-rate metrics
    using the same reference/current concept
    as the drift detector.
    """

    if len(predictions) < REFERENCE_SIZE + CURRENT_SIZE:
        return None

    reference = predictions.iloc[:REFERENCE_SIZE].copy()
    current = predictions.iloc[-CURRENT_SIZE:].copy()

    previous_probability = float(
        reference["attack_probability"].mean()
    )

    recent_probability = float(
        current["attack_probability"].mean()
    )

    probability_change = (
        recent_probability
        - previous_probability
    )

    previous_attack_rate = float(
        reference["prediction"].mean()
    )

    recent_attack_rate = float(
        current["prediction"].mean()
    )

    attack_rate_change = (
        recent_attack_rate
        - previous_attack_rate
    )

    return {
        "previous_probability": previous_probability,
        "recent_probability": recent_probability,
        "probability_change": probability_change,
        "previous_attack_rate": previous_attack_rate,
        "recent_attack_rate": recent_attack_rate,
        "attack_rate_change": attack_rate_change,
    }


def get_overall_drift_status(drift):
    """Determine the overall drift status."""

    if drift is None or drift.empty:
        return "NO_DATA"

    if "drift_status" not in drift.columns:
        return "NO_DATA"

    statuses = (
        drift["drift_status"]
        .astype(str)
        .str.upper()
        .tolist()
    )

    if "SIGNIFICANT_DRIFT" in statuses:
        return "SIGNIFICANT_DRIFT"

    if "MODERATE_DRIFT" in statuses:
        return "MODERATE_DRIFT"

    return "NO_DRIFT"


def get_affected_features(drift, status):
    """Return features affected by a drift level."""

    if drift is None or drift.empty:
        return []

    if "feature" not in drift.columns:
        return []

    if "drift_status" not in drift.columns:
        return []

    return drift[
        drift["drift_status"]
        .astype(str)
        .str.upper() == status
    ]["feature"].tolist()


# ============================================================
# LOAD DATA
# ============================================================

predictions = load_csv(PREDICTION_FILE)
drift = load_csv(DRIFT_FILE)
pipeline_log = load_json(PIPELINE_LOG_FILE)
promotion_log = load_json(PROMOTION_LOG_FILE)


if predictions is None:

    st.error(
        "Prediction log not found or empty.\n\n"
        f"Expected file: {PREDICTION_FILE}"
    )

    st.stop()


# ============================================================
# CHECK REQUIRED PREDICTION COLUMNS
# ============================================================

required_prediction_columns = [
    "timestamp",
    "prediction",
    "label",
    "attack_probability",
]

missing_prediction_columns = [
    column
    for column in required_prediction_columns
    if column not in predictions.columns
]

if missing_prediction_columns:

    st.error(
        "Prediction CSV is missing required columns:\n\n"
        + ", ".join(missing_prediction_columns)
    )

    st.stop()


# ============================================================
# DATA CLEANING
# ============================================================

predictions["attack_probability"] = pd.to_numeric(
    predictions["attack_probability"],
    errors="coerce",
).fillna(0)


predictions["prediction"] = pd.to_numeric(
    predictions["prediction"],
    errors="coerce",
).fillna(0).astype(int)


# ============================================================
# TRAFFIC SOURCE HANDLING
# ============================================================

if "source" not in predictions.columns:

    predictions["source"] = "UNKNOWN"


predictions["source"] = (
    predictions["source"]
    .astype(str)
    .str.strip()
    .str.upper()
)


# ============================================================
# MAIN METRICS
# ============================================================

total_predictions = len(predictions)

attack_predictions = int(
    (predictions["prediction"] == 1).sum()
)

benign_predictions = int(
    (predictions["prediction"] == 0).sum()
)

attack_rate = (
    attack_predictions / total_predictions
    if total_predictions > 0
    else 0
)

average_probability = float(
    predictions["attack_probability"].mean()
)

maximum_probability = float(
    predictions["attack_probability"].max()
)

latest_probability = float(
    predictions["attack_probability"].iloc[-1]
)


# ============================================================
# SOURCE METRICS
# ============================================================

live_predictions = int(
    (predictions["source"] == "LIVE").sum()
)

demo_predictions = int(
    (predictions["source"] == "CONTROLLED_DEMO").sum()
)

unknown_predictions = int(
    (
        ~predictions["source"].isin(
            ["LIVE", "CONTROLLED_DEMO"]
        )
    ).sum()
)


live_data = predictions[
    predictions["source"] == "LIVE"
].copy()

demo_data = predictions[
    predictions["source"] == "CONTROLLED_DEMO"
].copy()


live_attacks = int(
    (live_data["prediction"] == 1).sum()
)

demo_attacks = int(
    (demo_data["prediction"] == 1).sum()
)


live_attack_rate = (
    live_attacks / live_predictions
    if live_predictions > 0
    else 0
)

demo_attack_rate = (
    demo_attacks / demo_predictions
    if demo_predictions > 0
    else 0
)


# ============================================================
# WINDOW METRICS
# ============================================================

window_metrics = calculate_window_metrics(
    predictions
)


# ============================================================
# OVERALL DRIFT STATUS
# ============================================================

overall_status = get_overall_drift_status(
    drift
)


# ============================================================
# PAGE HEADER
# ============================================================

st.title("NIDS MLOps Dashboard")

st.caption(
    "Network Intrusion Detection | "
    "Live Traffic | ML Prediction | "
    "Drift Monitoring | Automated Retraining"
)

st.divider()


# ============================================================
# MLOPS PIPELINE OVERVIEW
# ============================================================

st.subheader("MLOps Pipeline Overview")

pipeline_col1, pipeline_col2, pipeline_col3, pipeline_col4 = (
    st.columns(4)
)


# Pipeline status

with pipeline_col1:

    if pipeline_log:

        status = str(
            pipeline_log.get(
                "pipeline_status",
                "UNKNOWN",
            )
        ).upper()

        if status == "COMPLETED":

            st.success(
                "PIPELINE\n\nCOMPLETED"
            )

        else:

            st.warning(
                f"PIPELINE\n\n{status}"
            )

    else:

        st.info(
            "PIPELINE\n\nNO AUDIT LOG"
        )


# Drift status

with pipeline_col2:

    if pipeline_log:

        if pipeline_log.get(
            "drift_detected",
            False,
        ):

            st.error(
                "DRIFT\n\nDETECTED"
            )

        else:

            st.success(
                "DRIFT\n\nNOT DETECTED"
            )

    else:

        st.info(
            "DRIFT\n\nNO DATA"
        )


# Retraining

with pipeline_col3:

    if pipeline_log:

        retraining_status = str(
            pipeline_log.get(
                "retraining_status",
                "NOT_RUN",
            )
        ).upper()

        if retraining_status == "COMPLETED":

            st.success(
                "RETRAINING\n\nCOMPLETED"
            )

        else:

            st.info(
                f"RETRAINING\n\n{retraining_status}"
            )

    else:

        st.info(
            "RETRAINING\n\nNO DATA"
        )


# Promotion

with pipeline_col4:

    if promotion_log:

        promotion_status = str(
            promotion_log.get(
                "promotion_status",
                "UNKNOWN",
            )
        ).upper()

        if promotion_status == "PROMOTED":

            st.success(
                "MODEL\n\nPROMOTED"
            )

        elif promotion_status == "NOT_PROMOTED":

            st.warning(
                "MODEL\n\nPRODUCTION RETAINED"
            )

        else:

            st.info(
                f"MODEL\n\n{promotion_status}"
            )

    else:

        st.info(
            "MODEL\n\nNO DATA"
        )


# ============================================================
# PIPELINE AUDIT DETAILS
# ============================================================

if pipeline_log:

    st.markdown("### Pipeline Audit Details")

    audit_col1, audit_col2, audit_col3, audit_col4 = (
        st.columns(4)
    )

    with audit_col1:

        st.metric(
            "Pipeline Status",
            str(
                pipeline_log.get(
                    "pipeline_status",
                    "UNKNOWN",
                )
            ),
        )

    with audit_col2:

        duration = float(
            pipeline_log.get(
                "duration_seconds",
                0,
            )
        )

        st.metric(
            "Execution Time",
            f"{duration:.1f} sec",
        )

    with audit_col3:

        st.metric(
            "Drift Detected",
            "YES"
            if pipeline_log.get(
                "drift_detected",
                False,
            )
            else "NO",
        )

    with audit_col4:

        st.metric(
            "Promotion",
            str(
                pipeline_log.get(
                    "promotion_status",
                    "UNKNOWN",
                )
            ),
        )

    if pipeline_log.get("timestamp"):

        st.caption(
            "Last pipeline execution: "
            + str(
                pipeline_log["timestamp"]
            )
        )


# ============================================================
# MODEL COMPARISON
# ============================================================

if promotion_log:

    st.markdown("### Model Promotion Gate")

    model_col1, model_col2, model_col3, model_col4 = (
        st.columns(4)
    )

    production_f1 = float(
        promotion_log.get(
            "production_f1",
            0,
        )
    )

    candidate_f1 = float(
        promotion_log.get(
            "candidate_f1",
            0,
        )
    )

    f1_improvement = float(
        promotion_log.get(
            "f1_improvement",
            0,
        )
    )

    required_improvement = float(
        promotion_log.get(
            "minimum_f1_improvement",
            0,
        )
    )

    with model_col1:

        st.metric(
            "Production F1",
            f"{production_f1:.6f}",
        )

    with model_col2:

        st.metric(
            "Candidate F1",
            f"{candidate_f1:.6f}",
        )

    with model_col3:

        st.metric(
            "F1 Improvement",
            f"{f1_improvement:+.6f}",
        )

    with model_col4:

        st.metric(
            "Required Improvement",
            f"{required_improvement:.6f}",
        )

    if str(
        promotion_log.get(
            "promotion_status",
            "",
        )
    ).upper() == "NOT_PROMOTED":

        st.info(
            "Production model retained because "
            "the candidate did not meet the promotion gate."
        )

    elif str(
        promotion_log.get(
            "promotion_status",
            "",
        )
    ).upper() == "PROMOTED":

        st.success(
            "Candidate model was promoted to production."
        )


st.divider()


# ============================================================
# TRAFFIC SOURCE MONITORING
# ============================================================

st.subheader("Traffic Source Monitoring")

source_col1, source_col2, source_col3, source_col4 = (
    st.columns(4)
)


with source_col1:

    st.metric(
        "Live Traffic",
        f"{live_predictions:,}",
    )


with source_col2:

    st.metric(
        "Controlled Demo",
        f"{demo_predictions:,}",
    )


with source_col3:

    st.metric(
    "Live Attack Predictions",
    f"{live_attacks:,}",
    )


with source_col4:

    st.metric(
        "Demo Attacks",
        f"{demo_attacks:,}",
    )


st.markdown("### Traffic Source Explanation")

st.info(
    "LIVE TRAFFIC = predictions generated from captured "
    "network traffic.\n\n"
    "CONTROLLED DEMO = labelled CICIDS2017 attack samples "
    "replayed through the prediction pipeline for controlled testing."
)


source_chart = pd.DataFrame(
    {
        "Traffic Source": [
            "LIVE",
            "CONTROLLED_DEMO",
        ],
        "Predictions": [
            live_predictions,
            demo_predictions,
        ],
    }
)


st.bar_chart(
    source_chart.set_index(
        "Traffic Source"
    ),
    width="stretch",
)


source_rate_col1, source_rate_col2 = st.columns(2)


with source_rate_col1:

    st.metric(
        "Live Attack Rate",
        f"{live_attack_rate:.2%}",
    )


with source_rate_col2:

    st.metric(
        "Controlled Demo Attack Rate",
        f"{demo_attack_rate:.2%}",
    )


if unknown_predictions > 0:

    st.warning(
        f"{unknown_predictions:,} predictions have an "
        "unknown traffic source."
    )


# ============================================================
# DETECTION OVERVIEW
# ============================================================

st.divider()

st.subheader("Detection Overview")

col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "Total Predictions",
        f"{total_predictions:,}",
    )


with col2:

    st.metric(
        "Benign",
        f"{benign_predictions:,}",
    )


with col3:

    st.metric(
        "Attacks",
        f"{attack_predictions:,}",
    )


with col4:

    st.metric(
        "Overall Attack Rate",
        f"{attack_rate:.2%}",
    )


# ============================================================
# SECONDARY METRICS
# ============================================================

st.divider()

col1, col2, col3 = st.columns(3)


with col1:

    st.metric(
        "Average Attack Probability",
        f"{average_probability:.2%}",
    )


with col2:

    st.metric(
        "Maximum Attack Probability",
        f"{maximum_probability:.2%}",
    )


with col3:

    st.metric(
        "Latest Attack Probability",
        f"{latest_probability:.2%}",
    )


# ============================================================
# DRIFT MONITORING
# ============================================================

st.divider()

st.subheader("Drift Monitoring")


if drift is None:

    st.warning(
        "No drift detection results available yet."
    )

else:

    required_drift_columns = [
        "timestamp",
        "feature",
        "reference_samples",
        "current_samples",
        "psi",
        "ks_statistic",
        "ks_p_value",
        "drift_status",
    ]

    missing_drift_columns = [
        column
        for column in required_drift_columns
        if column not in drift.columns
    ]

    if missing_drift_columns:

        st.warning(
            "Drift file is missing columns: "
            + ", ".join(missing_drift_columns)
        )

    else:

        significant_features = get_affected_features(
            drift,
            "SIGNIFICANT_DRIFT",
        )

        moderate_features = get_affected_features(
            drift,
            "MODERATE_DRIFT",
        )


        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        if overall_status == "SIGNIFICANT_DRIFT":

            st.error(
                "SIGNIFICANT DRIFT DETECTED"
            )

            if significant_features:

                st.write(
                    "**Affected features:** "
                    + ", ".join(
                        significant_features
                    )
                )


        elif overall_status == "MODERATE_DRIFT":

            st.warning(
                "MODERATE DRIFT DETECTED"
            )

            if moderate_features:

                st.write(
                    "**Affected features:** "
                    + ", ".join(
                        moderate_features
                    )
                )


        elif overall_status == "NO_DRIFT":

            st.success(
                "NO SIGNIFICANT DRIFT"
            )


        else:

            st.info(
                "Drift status is not available."
            )


        # ----------------------------------------------------
        # WINDOW METRICS
        # ----------------------------------------------------

        if window_metrics is not None:

            st.markdown("### Drift Window Metrics")

            col1, col2, col3, col4 = st.columns(4)


            with col1:

                st.metric(
                    "Previous Probability",
                    f"{window_metrics['previous_probability']:.2%}",
                )


            with col2:

                st.metric(
                    "Recent Probability",
                    f"{window_metrics['recent_probability']:.2%}",
                )


            with col3:

                st.metric(
                    "Probability Change",
                    f"{window_metrics['probability_change']:+.2%}",
                )


            with col4:

                st.metric(
                    "Attack Rate Change",
                    f"{window_metrics['attack_rate_change']:+.2%}",
                )


        # ----------------------------------------------------
        # FEATURE DRIFT TABLE
        # ----------------------------------------------------

        st.markdown("### Feature Drift Analysis")

        feature_drift = drift[
            [
                "feature",
                "reference_samples",
                "current_samples",
                "psi",
                "ks_statistic",
                "ks_p_value",
                "drift_status",
            ]
        ].copy()


        feature_drift["psi"] = pd.to_numeric(
            feature_drift["psi"],
            errors="coerce",
        )


        feature_drift["ks_statistic"] = pd.to_numeric(
            feature_drift["ks_statistic"],
            errors="coerce",
        )


        feature_drift["ks_p_value"] = pd.to_numeric(
            feature_drift["ks_p_value"],
            errors="coerce",
        )


        st.dataframe(
            feature_drift,
            width="stretch",
            hide_index=True,
        )


        # ----------------------------------------------------
        # PSI CHART
        # ----------------------------------------------------

        st.markdown(
            "### Population Stability Index"
        )

        psi_chart = feature_drift[
            [
                "feature",
                "psi",
            ]
        ].set_index("feature")


        st.bar_chart(
            psi_chart,
            width="stretch",
        )


        # ----------------------------------------------------
        # KS CHART
        # ----------------------------------------------------

        st.markdown(
            "### KS Statistic"
        )

        ks_chart = feature_drift[
            [
                "feature",
                "ks_statistic",
            ]
        ].set_index("feature")


        st.bar_chart(
            ks_chart,
            width="stretch",
        )


        # ----------------------------------------------------
        # ATTACK RATE COMPARISON
        # ----------------------------------------------------

        if window_metrics is not None:

            st.markdown(
                "### Attack Rate Comparison"
            )

            attack_rate_df = pd.DataFrame(
                {
                    "Period": [
                        "Previous 1000",
                        "Recent 100",
                    ],
                    "Attack Rate": [
                        window_metrics[
                            "previous_attack_rate"
                        ],
                        window_metrics[
                            "recent_attack_rate"
                        ],
                    ],
                }
            )


            st.bar_chart(
                attack_rate_df.set_index(
                    "Period"
                ),
                width="stretch",
            )


# ============================================================
# ATTACK PROBABILITY HISTORY
# ============================================================

st.divider()

st.subheader("Attack Probability History")


probability_chart = predictions[
    [
        "timestamp",
        "attack_probability",
    ]
].copy()


probability_chart["timestamp"] = pd.to_datetime(
    probability_chart["timestamp"],
    errors="coerce",
)


probability_chart = probability_chart.dropna(
    subset=["timestamp"]
)


if not probability_chart.empty:

    probability_chart = probability_chart.set_index(
        "timestamp"
    )


    st.line_chart(
        probability_chart[
            "attack_probability"
        ],
        width="stretch",
    )

else:

    st.info(
        "No valid timestamps available "
        "for the probability chart."
    )


# ============================================================
# PREDICTION DISTRIBUTION
# ============================================================

st.divider()

st.subheader("Prediction Distribution")


distribution = pd.DataFrame(
    {
        "Prediction": [
            "BENIGN",
            "ATTACK",
        ],
        "Count": [
            benign_predictions,
            attack_predictions,
        ],
    }
)


st.bar_chart(
    distribution.set_index(
        "Prediction"
    ),
    width="stretch",
)


# ============================================================
# RECENT PREDICTIONS
# ============================================================

st.divider()

st.subheader("Recent Predictions")

recent = predictions.tail(20).copy()


st.dataframe(
    recent,
    width="stretch",
    hide_index=True,
)


# ============================================================
# DRIFT HISTORY
# ============================================================

if drift is not None:

    st.divider()

    st.subheader("Drift History")


    st.dataframe(
        drift.tail(20),
        width="stretch",
        hide_index=True,
    )


# ============================================================
# SYSTEM INFORMATION
# ============================================================

st.divider()

st.subheader("System Information")


col1, col2, col3 = st.columns(3)


with col1:

    st.write("Prediction Log")

    st.code(
        PREDICTION_FILE
    )


with col2:

    st.write("Drift Log")

    st.code(
        DRIFT_FILE
    )


with col3:

    st.write("Model Status")

    if total_predictions > 0:

        st.success(
            "Model predictions available"
        )

    else:

        st.warning(
            "No model predictions available"
        )


# ============================================================
# PIPELINE STATUS
# ============================================================

st.divider()

st.subheader("Pipeline Status")


col1, col2, col3, col4 = st.columns(4)


with col1:

    st.success(
        "1. Live Capture"
    )


with col2:

    st.success(
        "2. ML Prediction"
    )


with col3:

    st.success(
        "3. Prediction Logging"
    )


with col4:

    if overall_status == "SIGNIFICANT_DRIFT":

        st.error(
            "4. Drift Detected"
        )

    elif overall_status == "MODERATE_DRIFT":

        st.warning(
            "4. Moderate Drift"
        )

    elif overall_status == "NO_DRIFT":

        st.success(
            "4. No Drift"
        )

    else:

        st.info(
            "4. Waiting for Drift"
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "NIDS MLOps Pipeline | "
    "Live Capture -> ML Prediction -> "
    "Logging -> Drift Detection -> "
    "Retraining -> Model Promotion -> Dashboard"
)
