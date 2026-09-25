import csv
import os
from datetime import datetime

import joblib
import pandas as pd


# ============================================================
# NIDS CONTROLLED ATTACK DEMONSTRATION
# ============================================================
#
# This script does NOT generate an attack on a network.
#
# It takes known ATTACK samples from the already processed
# CICIDS2017 dataset and passes them through the SAME saved
# Random Forest model used by the live NIDS.
#
# Purpose:
#   1. Verify that the trained model detects known attacks.
#   2. Create controlled ATTACK prediction records.
#   3. Allow the Streamlit dashboard to demonstrate
#      BENIGN + ATTACK predictions.
#
# ============================================================


PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
    )
)

DATA_PATH = os.path.join(
    PROJECT_ROOT,
    "data",
    "processed",
    "cicids2017_processed.parquet",
)

MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "nids_random_forest.joblib",
)

LOG_PATH = os.path.join(
    PROJECT_ROOT,
    "logs",
    "nids_predictions.csv",
)

# Number of known attack samples to replay.
DEMO_SAMPLES = 20

# IMPORTANT:
# These are controlled CICIDS2017 attack samples.
# No real network attack is generated.
TRAFFIC_SOURCE = "CONTROLLED_DEMO"


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():
    print("=" * 60)
    print("NIDS CONTROLLED ATTACK DEMONSTRATION")
    print("=" * 60)

    print()
    print("Loading trained NIDS model...")

    model = joblib.load(MODEL_PATH)

    print("Model loaded successfully.")
    print(f"Expected features: {len(model.feature_names_in_)}")

    return model


# ============================================================
# LOAD DATA
# ============================================================

def load_attack_samples(model):
    print()
    print("Loading processed CICIDS2017 dataset...")

    df = pd.read_parquet(DATA_PATH)

    print(f"Dataset rows: {len(df):,}")

    if "Target" not in df.columns:
        raise ValueError(
            "Target column was not found in the processed dataset."
        )

    attack_df = df[df["Target"] == 1].copy()

    if len(attack_df) < DEMO_SAMPLES:
        raise ValueError(
            f"Only {len(attack_df)} attack samples are available."
        )

    # Use a deterministic sample so the demonstration is repeatable.
    attack_df = attack_df.head(DEMO_SAMPLES)

    # The model expects exactly its training feature columns.
    feature_names = list(model.feature_names_in_)

    missing_features = [
        feature
        for feature in feature_names
        if feature not in attack_df.columns
    ]

    if missing_features:
        raise ValueError(
            "Missing model features: "
            + ", ".join(missing_features)
        )

    X = attack_df[feature_names].copy()

    # Same numerical cleaning used by the training pipeline.
    X = X.replace(
        [float("inf"), float("-inf")],
        0,
    )

    X = X.fillna(0)

    return attack_df, X


# ============================================================
# PREDICT
# ============================================================

def predict_attacks(model, attack_df, X):
    print()
    print("Running controlled attack samples through model...")
    print()

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)[:, 1]

    results = []

    for index, (
        (_, original_row),
        prediction,
        probability,
    ) in enumerate(
        zip(
            attack_df.iterrows(),
            predictions,
            probabilities,
        ),
        start=1,
    ):
        result = {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "src_ip": "CONTROLLED-CICIDS2017",
            "src_port": 0,
            "dst_ip": "CONTROLLED-DEMO",
            "dst_port": 0,
            "protocol": 0,
            "packets": 0,
            "bytes": 0,
            "prediction": int(prediction),
            "label": (
                "ATTACK"
                if int(prediction) == 1
                else "BENIGN"
            ),
            "attack_probability": round(
                float(probability),
                4,
            ),
            "source": TRAFFIC_SOURCE,
        }

        # If the dataset contains useful flow metadata,
        # use it when available.
        if "Src IP" in original_row.index:
            result["src_ip"] = str(
                original_row["Src IP"]
            )

        if "Src Port" in original_row.index:
            try:
                result["src_port"] = int(
                    original_row["Src Port"]
                )
            except Exception:
                pass

        if "Dst IP" in original_row.index:
            result["dst_ip"] = str(
                original_row["Dst IP"]
            )

        if "Dst Port" in original_row.index:
            try:
                result["dst_port"] = int(
                    original_row["Dst Port"]
                )
            except Exception:
                pass

        if "Protocol" in original_row.index:
            try:
                result["protocol"] = int(
                    original_row["Protocol"]
                )
            except Exception:
                pass

        # Use common CICIDS packet/byte feature names if available.
        packet_candidates = [
            "Total Fwd Packets",
            "Total Backward Packets",
        ]

        byte_candidates = [
            "Total Length of Fwd Packets",
            "Total Length of Bwd Packets",
        ]

        packet_total = 0

        for column in packet_candidates:
            if column in original_row.index:
                try:
                    packet_total += int(
                        float(original_row[column])
                    )
                except Exception:
                    pass

        byte_total = 0

        for column in byte_candidates:
            if column in original_row.index:
                try:
                    byte_total += int(
                        float(original_row[column])
                    )
                except Exception:
                    pass

        result["packets"] = packet_total
        result["bytes"] = byte_total

        results.append(result)

        print("-" * 60)
        print(f"Attack sample {index}/{DEMO_SAMPLES}")
        print(
            "Prediction:",
            result["label"],
        )
        print(
            "Attack probability:",
            f"{float(probability) * 100:.2f}%",
        )
        print(
            "Traffic source:",
            TRAFFIC_SOURCE,
        )

    return results


# ============================================================
# SAVE TO NIDS LOG
# ============================================================

def save_results(results):
    print()
    print("Saving controlled results to NIDS prediction log...")

    os.makedirs(
        os.path.dirname(LOG_PATH),
        exist_ok=True,
    )

    fieldnames = [
        "timestamp",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "packets",
        "bytes",
        "prediction",
        "label",
        "attack_probability",
        "source",
    ]

    file_exists = os.path.exists(LOG_PATH)

    with open(
        LOG_PATH,
        "a",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        if not file_exists:
            writer.writeheader()

        writer.writerows(results)

    print()
    print(f"Results saved to: {LOG_PATH}")


# ============================================================
# SUMMARY
# ============================================================

def print_summary(results):
    total = len(results)

    attacks = sum(
        1
        for result in results
        if result["prediction"] == 1
    )

    benign = total - attacks

    highest_probability = max(
        result["attack_probability"]
        for result in results
    )

    print()
    print("=" * 60)
    print("CONTROLLED ATTACK DEMONSTRATION SUMMARY")
    print("=" * 60)

    print()
    print("Samples tested       :", total)
    print("Predicted ATTACK     :", attacks)
    print("Predicted BENIGN     :", benign)

    print(
        "Highest attack probability:",
        f"{highest_probability * 100:.2f}%",
    )

    print(
        "Traffic source       :",
        TRAFFIC_SOURCE,
    )

    print()
    print(
        "These samples are controlled CICIDS2017 attack "
        "samples passed through the saved NIDS model."
    )

    print()
    print("=" * 60)


# ============================================================
# MAIN
# ============================================================

def main():
    model = load_model()

    attack_df, X = load_attack_samples(
        model
    )

    results = predict_attacks(
        model,
        attack_df,
        X,
    )

    save_results(results)

    print_summary(results)


if __name__ == "__main__":
    main()