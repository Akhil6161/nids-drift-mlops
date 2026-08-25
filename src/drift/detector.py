import os
from datetime import datetime

import numpy as np
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

PREDICTION_FILE = "logs/nids_predictions.csv"
DRIFT_LOG_FILE = "logs/drift_detection.csv"

REFERENCE_SIZE = 1000
MIN_CURRENT_SIZE = 100

FEATURES = [
    "packets",
    "bytes",
    "attack_probability",
]


# ============================================================
# LOAD DATA
# ============================================================

def load_predictions():

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
# SIMPLE PSI CALCULATION
# ============================================================

def calculate_psi(reference, current, bins=10):

    reference = np.asarray(reference, dtype=float)
    current = np.asarray(current, dtype=float)

    reference = reference[np.isfinite(reference)]
    current = current[np.isfinite(current)]

    if len(reference) == 0 or len(current) == 0:
        return 0.0

    # Create bins using reference distribution.
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

    # Extend boundaries slightly so minimum/maximum
    # values are included safely.
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

    # Avoid division by zero.
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
# DRIFT INTERPRETATION
# ============================================================

def interpret_psi(psi):

    if psi < 0.10:
        return "NO_DRIFT"

    if psi < 0.25:
        return "MODERATE_DRIFT"

    return "SIGNIFICANT_DRIFT"


# ============================================================
# DETECT DRIFT
# ============================================================

def detect_drift(df):

    if len(df) < REFERENCE_SIZE + MIN_CURRENT_SIZE:

        raise ValueError(
            "Not enough predictions for drift detection. "
            f"Need at least "
            f"{REFERENCE_SIZE + MIN_CURRENT_SIZE}, "
            f"but only {len(df)} are available."
        )

    reference = df.iloc[
        :REFERENCE_SIZE
    ].copy()

    current = df.iloc[
        -MIN_CURRENT_SIZE:
    ].copy()

    results = []

    for feature in FEATURES:

        reference_values = pd.to_numeric(
            reference[feature],
            errors="coerce",
        ).dropna()

        current_values = pd.to_numeric(
            current[feature],
            errors="coerce",
        ).dropna()

        psi = calculate_psi(
            reference_values,
            current_values,
        )

        status = interpret_psi(psi)

        results.append({
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "feature": feature,
            "reference_samples": len(
                reference_values
            ),
            "current_samples": len(
                current_values
            ),
            "psi": round(psi, 6),
            "drift_status": status,
        })

    return pd.DataFrame(results)


# ============================================================
# SAVE RESULTS
# ============================================================

def save_results(results):

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
        MIN_CURRENT_SIZE,
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
                    "drift_status",
                ]
            ].to_string(index=False)
        )

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