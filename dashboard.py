import os
import time

import pandas as pd
import streamlit as st


# ============================================================
# CONFIGURATION
# ============================================================

PREDICTION_FILE = "logs/nids_predictions.csv"
DRIFT_FILE = "logs/drift_detection.csv"

REFRESH_SECONDS = 5


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="NIDS Live Dashboard",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# TITLE
# ============================================================

st.title("🛡️ NIDS Live Network Intrusion Detection Dashboard")

st.caption(
    "Live network traffic monitoring, ML predictions and drift detection"
)


# ============================================================
# LOAD PREDICTIONS
# ============================================================

def load_predictions():

    if not os.path.exists(PREDICTION_FILE):
        return pd.DataFrame()

    try:
        df = pd.read_csv(PREDICTION_FILE)

        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(
                df["timestamp"],
                errors="coerce",
            )

        return df

    except Exception as e:

        st.error(
            f"Could not read prediction file: {e}"
        )

        return pd.DataFrame()


# ============================================================
# LOAD DRIFT RESULTS
# ============================================================

def load_drift():

    if not os.path.exists(DRIFT_FILE):
        return pd.DataFrame()

    try:

        return pd.read_csv(DRIFT_FILE)

    except Exception as e:

        st.error(
            f"Could not read drift file: {e}"
        )

        return pd.DataFrame()


# ============================================================
# DATA
# ============================================================

df = load_predictions()
drift_df = load_drift()


# ============================================================
# NO DATA MESSAGE
# ============================================================

if df.empty:

    st.warning(
        "No NIDS prediction data is available yet."
    )

    st.info(
        "Start the live NIDS capture to generate predictions."
    )

    st.stop()


# ============================================================
# BASIC STATISTICS
# ============================================================

total_predictions = len(df)

if "label" in df.columns:

    benign_predictions = int(
        (df["label"] == "BENIGN").sum()
    )

    attack_predictions = int(
        (df["label"] == "ATTACK").sum()
    )

else:

    benign_predictions = 0
    attack_predictions = 0


if "attack_probability" in df.columns:

    highest_probability = float(
        df["attack_probability"].max()
    )

else:

    highest_probability = 0.0


# ============================================================
# TOP METRICS
# ============================================================

col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "Total Predictions",
        f"{total_predictions:,}",
    )


with col2:

    st.metric(
        "Benign Predictions",
        f"{benign_predictions:,}",
    )


with col3:

    st.metric(
        "Attack Predictions",
        f"{attack_predictions:,}",
    )


with col4:

    st.metric(
        "Highest Attack Probability",
        f"{highest_probability:.0%}",
    )


st.divider()


# ============================================================
# DRIFT SECTION
# ============================================================

st.subheader("📊 Drift Detection")


if drift_df.empty:

    st.info(
        "No drift detection results available."
    )

else:

    required_columns = {
        "feature",
        "psi",
        "drift_status",
    }

    if required_columns.issubset(
        drift_df.columns
    ):

        display_drift = drift_df[
            [
                "feature",
                "psi",
                "drift_status",
            ]
        ].copy()

        st.dataframe(
            display_drift,
            use_container_width=True,
            hide_index=True,
        )

        significant = display_drift[
            display_drift["drift_status"]
            == "SIGNIFICANT_DRIFT"
        ]

        if len(significant) > 0:

            st.error(
                "⚠️ SIGNIFICANT DRIFT DETECTED"
            )

            affected_features = ", ".join(
                significant["feature"].astype(str)
            )

            st.write(
                f"**Affected features:** {affected_features}"
            )

        else:

            st.success(
                "✅ No significant drift detected"
            )

    else:

        st.warning(
            "Drift file does not contain the expected columns."
        )


st.divider()


# ============================================================
# ATTACK PROBABILITY
# ============================================================

st.subheader("🎯 Attack Probability")


if "attack_probability" in df.columns:

    probability_data = df[
        ["timestamp", "attack_probability"]
    ].tail(100).copy()

    probability_data = probability_data.set_index(
        "timestamp"
    )

    st.line_chart(
        probability_data,
        y="attack_probability",
    )


st.divider()


# ============================================================
# PREDICTION COUNTS
# ============================================================

st.subheader("📈 Prediction Distribution")


if "label" in df.columns:

    prediction_counts = (
        df["label"]
        .value_counts()
        .rename_axis("label")
        .to_frame("count")
    )

    st.bar_chart(
        prediction_counts,
        y="count",
    )


st.divider()


# ============================================================
# RECENT PREDICTIONS
# ============================================================

st.subheader("🔎 Recent Network Predictions")


recent_columns = [
    "timestamp",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "packets",
    "bytes",
    "label",
    "attack_probability",
]


available_columns = [
    column
    for column in recent_columns
    if column in df.columns
]


recent_df = df[
    available_columns
].tail(20).copy()


if "attack_probability" in recent_df.columns:

    recent_df["attack_probability"] = (
        recent_df["attack_probability"]
        .map(lambda x: f"{x:.0%}")
    )


st.dataframe(
    recent_df,
    use_container_width=True,
    hide_index=True,
)


# ============================================================
# SYSTEM INFORMATION
# ============================================================

st.divider()

st.subheader("ℹ️ System Status")

status_col1, status_col2, status_col3 = st.columns(3)


with status_col1:

    if os.path.exists(PREDICTION_FILE):

        st.success(
            "Prediction log: ONLINE"
        )

    else:

        st.error(
            "Prediction log: OFFLINE"
        )


with status_col2:

    if os.path.exists(DRIFT_FILE):

        st.success(
            "Drift detector: ONLINE"
        )

    else:

        st.warning(
            "Drift detector: WAITING"
        )


with status_col3:

    st.info(
        f"Dashboard refresh: {REFRESH_SECONDS}s"
    )


# ============================================================
# AUTO REFRESH
# ============================================================

time.sleep(REFRESH_SECONDS)

st.rerun()