import os
import pandas as pd
import streamlit as st


# ============================================================
# CONFIGURATION
# ============================================================

PREDICTION_FILE = "logs/nids_predictions.csv"
DRIFT_FILE = "logs/drift_results.csv"

st.set_page_config(
    page_title="NIDS MLOps Dashboard",
    page_icon="🛡️",
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

        return df

    except Exception as e:
        st.error(f"Could not read {path}: {e}")
        return None


def normalize_prediction_columns(df):
    """Normalize prediction CSV column names."""

    df = df.copy()

    # Remove accidental whitespace
    df.columns = df.columns.str.strip()

    return df


# ============================================================
# LOAD DATA
# ============================================================

predictions = load_csv(PREDICTION_FILE)

if predictions is None:
    st.error(
        "Prediction log not found or empty.\n\n"
        f"Expected file: {PREDICTION_FILE}"
    )
    st.stop()

predictions = normalize_prediction_columns(predictions)

drift = load_csv(DRIFT_FILE)

if drift is not None:
    drift = normalize_prediction_columns(drift)


# ============================================================
# CHECK REQUIRED COLUMNS
# ============================================================

required_prediction_columns = [
    "timestamp",
    "prediction",
    "label",
    "attack_probability",
]

missing_columns = [
    column
    for column in required_prediction_columns
    if column not in predictions.columns
]

if missing_columns:
    st.error(
        "Prediction CSV is missing required columns:\n\n"
        + ", ".join(missing_columns)
    )
    st.stop()


# ============================================================
# DATA PREPARATION
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
# PAGE HEADER
# ============================================================

st.title("🛡️ NIDS MLOps Dashboard")

st.caption(
    "Network Intrusion Detection • ML Prediction Logging • Drift Monitoring"
)

st.divider()


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

average_probability = predictions[
    "attack_probability"
].mean()


st.subheader("📊 Detection Overview")

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
        "Attack Rate",
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
    maximum_probability = predictions[
        "attack_probability"
    ].max()

    st.metric(
        "Maximum Attack Probability",
        f"{maximum_probability:.2%}",
    )

with col3:
    latest_probability = predictions[
        "attack_probability"
    ].iloc[-1]

    st.metric(
        "Latest Attack Probability",
        f"{latest_probability:.2%}",
    )


# ============================================================
# DRIFT MONITORING
# ============================================================

st.divider()

st.subheader("🔄 Drift Monitoring")

if drift is None:

    st.warning(
        "No drift results available yet."
    )

else:

    required_drift_columns = [
        "previous_attack_rate",
        "recent_attack_rate",
        "attack_rate_change",
        "previous_probability",
        "recent_probability",
        "probability_change",
        "status",
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

        latest_drift = drift.iloc[-1]

        status = str(
            latest_drift["status"]
        )

        probability_change = float(
            latest_drift["probability_change"]
        )

        attack_rate_change = float(
            latest_drift["attack_rate_change"]
        )

        previous_probability = float(
            latest_drift["previous_probability"]
        )

        recent_probability = float(
            latest_drift["recent_probability"]
        )

        previous_attack_rate = float(
            latest_drift["previous_attack_rate"]
        )

        recent_attack_rate = float(
            latest_drift["recent_attack_rate"]
        )


        # -----------------------------------------------
        # STATUS
        # -----------------------------------------------

        if status == "DRIFT_DETECTED":

            st.error(
                f"🚨 DRIFT DETECTED"
            )

        elif status == "NO_SIGNIFICANT_DRIFT":

            st.success(
                f"✅ NO SIGNIFICANT DRIFT"
            )

        else:

            st.warning(
                f"⚠️ {status}"
            )


        # -----------------------------------------------
        # DRIFT METRICS
        # -----------------------------------------------

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Previous Probability",
                f"{previous_probability:.2%}",
            )

        with col2:
            st.metric(
                "Recent Probability",
                f"{recent_probability:.2%}",
            )

        with col3:
            st.metric(
                "Probability Change",
                f"{probability_change:+.2%}",
            )

        with col4:
            st.metric(
                "Attack Rate Change",
                f"{attack_rate_change:+.2%}",
            )


        # -----------------------------------------------
        # ATTACK RATE COMPARISON
        # -----------------------------------------------

        st.markdown("### Attack Rate Comparison")

        attack_rate_df = pd.DataFrame(
            {
                "Period": [
                    "Previous",
                    "Recent",
                ],
                "Attack Rate": [
                    previous_attack_rate,
                    recent_attack_rate,
                ],
            }
        )

        st.bar_chart(
            attack_rate_df.set_index("Period")
        )


# ============================================================
# ATTACK PROBABILITY HISTORY
# ============================================================

st.divider()

st.subheader("📈 Attack Probability History")

probability_chart = predictions[
    ["timestamp", "attack_probability"]
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
        "No valid timestamps available for the probability chart."
    )


# ============================================================
# PREDICTION DISTRIBUTION
# ============================================================

st.divider()

st.subheader("📊 Prediction Distribution")

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
    distribution.set_index("Prediction"),
    width="stretch",
)


# ============================================================
# RECENT PREDICTIONS
# ============================================================

st.divider()

st.subheader("🧾 Recent Predictions")

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

    st.subheader("🔄 Drift History")

    st.dataframe(
        drift.tail(20),
        width="stretch",
        hide_index=True,
    )


# ============================================================
# SYSTEM INFORMATION
# ============================================================

st.divider()

st.subheader("ℹ️ System Information")

col1, col2, col3 = st.columns(3)

with col1:
    st.write("**Prediction Log**")
    st.code(PREDICTION_FILE)

with col2:
    st.write("**Drift Log**")
    st.code(DRIFT_FILE)

with col3:
    st.write("**Model Status**")
    st.success("Model predictions available")


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "NIDS MLOps Pipeline | Live Capture → ML Prediction → "
    "Logging → Drift Detection → Dashboard"
)