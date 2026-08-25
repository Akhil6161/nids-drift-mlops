import os
from datetime import datetime

import numpy as np
import pandas as pd
from scipy.stats import ks_2samp


# ============================================================
# CONFIGURATION
# ============================================================

PREDICTION_FILE = "logs/nids_predictions.csv"
DRIFT_LOG_FILE = "logs/drift_detection.csv"

# First 1000 live predictions are used as the baseline.
REFERENCE_SIZE = 1000

# Latest 100 predictions are monitored.
CURRENT_SIZE = 100

FEATURES = [
    "packets",
    "bytes",
    "attack_probability",
]

# PSI thresholds
PSI_NO_DRIFT = 0.10
PSI_MODERATE = 0.25

# KS significance thresholds
KS_SIGNIFICANCE = 0.05


# ============================================================
# LOAD DATA
# ============================================================

def load_predictions():
    """Load prediction records from the NIDS prediction log."""

    if not os.path.exists(PREDICTION_FILE):
        raise FileNotFoundError(
            f"Prediction file not found: {PREDICTION_FILE}"
        )

    df = pd.read_csv(PREDICTION_FILE)

    if df.empty:
        raise ValueError(
            "Prediction file is empty."
        )

    return df


# ============================================================
# PSI CALCULATION
# ============================================================

def calculate_psi(reference, current, bins=10):
    """
    Calculate Population Stability Index (PSI).

    The bins are created from the reference distribution so that
    the current distribution is compared against a fixed baseline.
    """

    reference = np.asarray(reference, dtype=float)
    current = np.asarray(current, dtype=float)

    reference = reference[np.isfinite(reference)]
    current = current[np.isfinite(current)]

    if len(reference) == 0 or len(current) == 0:
        return 0.0

    quantiles = np.linspace(
        0,
        1,
        bins + 1,
    )

    edges = np.quantile(
        reference,
        quantiles,
    )

    edges = np.unique(edges)

    if len(edges) < 3:
        return 0.0

    # Make sure the full range is included.
    edges[0] = -np.inf
    edges[-1] = np.inf

    reference_counts, _ = np.histogram(
        reference,
        bins=edges,
    )

    current_counts, _ = np.histogram(
        current,
        bins=edges,
    )

    reference_percent = (
        reference_counts / len(reference)
    )

    current_percent = (
        current_counts / len(current)
    )

    # Prevent division by zero and log(0).
    epsilon = 0.0001

    reference_percent = np.where(
        reference_percent == 0,
        epsilon,
        reference_percent,
    )

    current_percent = np.where(
        current_percent == 0,
        epsilon,
        current_percent,
    )

    psi = np.sum(
        (
            current_percent
            - reference_percent
        )
        * np.log(
            current_percent
            / reference_percent
        )
    )

    return float(psi)


# ============================================================
# KS TEST
# ============================================================

def calculate_ks(reference, current):
    """
    Calculate the two-sample Kolmogorov-Smirnov statistic.

    Returns:
        ks_statistic
        ks_p_value
    """

    reference = np.asarray(reference, dtype=float)
    current = np.asarray(current, dtype=float)

    reference = reference[np.isfinite(reference)]
    current = current[np.isfinite(current)]

    if len(reference) == 0 or len(current) == 0:
        return 0.0, 1.0

    statistic, p_value = ks_2samp(
        reference,
        current,
        alternative="two-sided",
        method="auto",
    )

    return float(statistic), float(p_value)


# ============================================================
# DRIFT INTERPRETATION
# ============================================================

def interpret_drift(psi, ks_p_value):
    """
    Combine PSI and KS results into one drift status.

    SIGNIFICANT_DRIFT:
        PSI is significant AND KS test is statistically significant.

    MODERATE_DRIFT:
        PSI indicates moderate drift OR KS detects a significant
        distribution difference.

    NO_DRIFT:
        Neither test indicates meaningful distribution change.
    """

    if (
        psi >= PSI_MODERATE
        and ks_p_value < KS_SIGNIFICANCE
    ):
        return "SIGNIFICANT_DRIFT"

    if (
        psi >= PSI_NO_DRIFT
        or ks_p_value < KS_SIGNIFICANCE
    ):
        return "MODERATE_DRIFT"

    return "NO_DRIFT"


# ============================================================
# DETECT DRIFT
# ============================================================

def detect_drift(df):
    """
    Compare the initial live reference window with
    the most recent live prediction window.
    """

    minimum_required = (
        REFERENCE_SIZE + CURRENT_SIZE
    )

    if len(df) < minimum_required:
        raise ValueError(
            "Not enough predictions for drift detection. "
            f"Need at least {minimum_required}, "
            f"but only {len(df)} are available."
        )

    # --------------------------------------------------------
    # Reference window
    # --------------------------------------------------------
    reference = df.iloc[
        :REFERENCE_SIZE
    ].copy()

    # --------------------------------------------------------
    # Current monitoring window
    # --------------------------------------------------------
    current = df.iloc[
        -CURRENT_SIZE:
    ].copy()

    results = []

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    for feature in FEATURES:

        reference_values = pd.to_numeric(
            reference[feature],
            errors="coerce",
        ).dropna()

        current_values = pd.to_numeric(
            current[feature],
            errors="coerce",
        ).dropna()

        # ----------------------------------------------------
        # PSI
        # ----------------------------------------------------
        psi = calculate_psi(
            reference_values,
            current_values,
        )

        # ----------------------------------------------------
        # KS
        # ----------------------------------------------------
        ks_statistic, ks_p_value = calculate_ks(
            reference_values,
            current_values,
        )

        # ----------------------------------------------------
        # Combined interpretation
        # ----------------------------------------------------
        status = interpret_drift(
            psi,
            ks_p_value,
        )

        results.append(
            {
                "timestamp": timestamp,
                "feature": feature,
                "reference_samples": len(
                    reference_values
                ),
                "current_samples": len(
                    current_values
                ),
                "psi": round(
                    psi,
                    6,
                ),
                "ks_statistic": round(
                    ks_statistic,
                    6,
                ),
                "ks_p_value": round(
                    ks_p_value,
                    6,
                ),
                "drift_status": status,
            }
        )

    return pd.DataFrame(results)


# ============================================================
# SAVE RESULTS
# ============================================================

def save_results(results):
    """Save drift results to CSV."""

    directory = os.path.dirname(
        DRIFT_LOG_FILE
    )

    if directory:
        os.makedirs(
            directory,
            exist_ok=True,
        )

    results.to_csv(
        DRIFT_LOG_FILE,
        index=False,
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("NIDS DRIFT DETECTION")
    print("=" * 60)

    print()

    print(
        "Prediction file:",
        PREDICTION_FILE,
    )

    print(
        "Reference samples:",
        REFERENCE_SIZE,
    )

    print(
        "Current samples:",
        CURRENT_SIZE,
    )

    print()

    try:

        df = load_predictions()

        print(
            "Total predictions:",
            len(df),
        )

        print()

        results = detect_drift(df)

        save_results(results)

        print(
            "Drift detection completed."
        )

        print()

        print(
            results[
                [
                    "feature",
                    "psi",
                    "ks_statistic",
                    "ks_p_value",
                    "drift_status",
                ]
            ].to_string(index=False)
        )

        print()

        # ----------------------------------------------------
        # Overall alert
        # ----------------------------------------------------

        significant_features = results[
            results["drift_status"]
            == "SIGNIFICANT_DRIFT"
        ]["feature"].tolist()

        moderate_features = results[
            results["drift_status"]
            == "MODERATE_DRIFT"
        ]["feature"].tolist()

        if significant_features:

            print("=" * 60)
            print("ALERT: SIGNIFICANT DRIFT DETECTED")
            print("=" * 60)

            print(
                "Affected features:",
                ", ".join(significant_features),
            )

        elif moderate_features:

            print("=" * 60)
            print("WARNING: MODERATE DRIFT DETECTED")
            print("=" * 60)

            print(
                "Affected features:",
                ", ".join(moderate_features),
            )

        else:

            print("=" * 60)
            print("NO SIGNIFICANT DRIFT DETECTED")
            print("=" * 60)

        print()

        print(
            "Results saved to:",
            DRIFT_LOG_FILE,
        )

    except Exception as e:

        print(
            "[Drift detection error]",
            str(e),
        )

    print()

    print("=" * 60)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()