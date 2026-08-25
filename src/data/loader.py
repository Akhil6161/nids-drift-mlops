from pathlib import Path
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"


DATASET_FILES = [
    "Benign-Monday-no-metadata.parquet",
    "Bruteforce-Tuesday-no-metadata.parquet",
    "DoS-Wednesday-no-metadata.parquet",
    "Infiltration-Thursday-no-metadata.parquet",
    "WebAttacks-Thursday-no-metadata.parquet",
    "DDoS-Friday-no-metadata.parquet",
    "Portscan-Friday-no-metadata.parquet",
    "Botnet-Friday-no-metadata.parquet",
]


def load_file(filename: str) -> pd.DataFrame:
    """Load one CICIDS2017 Parquet file."""

    path = RAW_DATA_DIR / filename

    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    print(f"Loading: {filename}")

    return pd.read_parquet(path)


def load_dataset() -> pd.DataFrame:
    """Load and combine all CICIDS2017 Parquet files."""

    dataframes = []

    for filename in DATASET_FILES:
        df = load_file(filename)
        dataframes.append(df)

        print(f"Rows loaded: {len(df):,}")

    combined = pd.concat(
        dataframes,
        axis=0,
        ignore_index=True
    )

    print()
    print("=" * 60)
    print("CICIDS2017 DATASET LOADED")
    print("=" * 60)
    print(f"Total rows:    {len(combined):,}")
    print(f"Total columns: {len(combined.columns):,}")
    print("=" * 60)

    return combined