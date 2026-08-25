from pathlib import Path

import pandas as pd

from loader import load_dataset


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DATA_DIR = PROJECT_ROOT / "data" / "processed"


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Clean whitespace from column names."""

    df = df.copy()

    df.columns = (
        df.columns
        .str.strip()
        .str.replace(" ", "_")
    )

    return df


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """Clean network traffic data."""

    df = clean_column_names(df)

    # Replace infinite numerical values with missing values.
    df = df.replace([float("inf"), float("-inf")], pd.NA)

    # Remove rows containing missing values.
    df = df.dropna()

    # Remove duplicate network-flow records.
    df = df.drop_duplicates()

    return df


def create_binary_label(df: pd.DataFrame) -> pd.DataFrame:
    """Convert multiple attack categories into Benign / Attack."""

    df = df.copy()

    df["Target"] = df["Label"].apply(
        lambda label: 0 if str(label).strip().lower() == "benign" else 1
    )

    return df


def save_processed_data(df: pd.DataFrame) -> None:
    """Save the processed dataset."""

    PROCESSED_DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    output_path = PROCESSED_DATA_DIR / "cicids2017_processed.parquet"

    df.to_parquet(
        output_path,
        index=False
    )

    print()
    print(f"Processed dataset saved to:")
    print(output_path)


def main():
    print("Loading CICIDS2017 dataset...")

    df = load_dataset()

    print()
    print(f"Original shape: {df.shape}")

    print()
    print("Cleaning data...")

    df = clean_data(df)

    print(f"Shape after cleaning: {df.shape}")

    print()
    print("Creating binary attack label...")

    df = create_binary_label(df)

    print()
    print("Target distribution:")
    print(df["Target"].value_counts())

    print()
    print("Target meaning:")
    print("0 = Benign")
    print("1 = Attack")

    save_processed_data(df)


if __name__ == "__main__":
    main()