from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split


PROJECT_ROOT = Path(__file__).resolve().parents[2]

PROCESSED_DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cicids2017_processed.parquet"
)

MODEL_DIR = PROJECT_ROOT / "models"
MODEL_PATH = MODEL_DIR / "nids_random_forest.joblib"


def load_processed_data():
    print("Loading processed dataset...")

    df = pd.read_parquet(PROCESSED_DATA_PATH)

    print(f"Dataset shape: {df.shape}")

    return df


def prepare_features(df):
    print("Preparing features...")

    # Remove the original text label.
    df = df.drop(columns=["Label"], errors="ignore")

    # Separate features and target.
    X = df.drop(columns=["Target"])
    y = df["Target"]

    # Keep only numerical columns.
    X = X.select_dtypes(include=["number"])

    # Replace infinite values.
    X = X.replace([float("inf"), float("-inf")], 0)

    # Fill any remaining missing values.
    X = X.fillna(0)

    print(f"Feature count: {X.shape[1]}")
    print(f"Samples: {X.shape[0]:,}")

    return X, y


def train_model(X_train, y_train):
    print()
    print("Training Random Forest...")

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    model.fit(X_train, y_train)

    return model


def evaluate_model(model, X_test, y_test):
    print()
    print("=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    print(f"Accuracy: {accuracy:.4f}")

    print()
    print("Classification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=["Benign", "Attack"],
        )
    )

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))


def save_model(model):
    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(model, MODEL_PATH)

    print()
    print(f"Model saved to:")
    print(MODEL_PATH)


def main():
    df = load_processed_data()

    X, y = prepare_features(df)

    print()
    print("Splitting dataset...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print(f"Training samples: {len(X_train):,}")
    print(f"Testing samples:  {len(X_test):,}")

    model = train_model(
        X_train,
        y_train,
    )

    evaluate_model(
        model,
        X_test,
        y_test,
    )

    save_model(model)


if __name__ == "__main__":
    main()