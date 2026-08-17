from pathlib import Path
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"


def load_csv(file_path: str) -> pd.DataFrame:
    """
    Load a CSV network-traffic dataset.

    Parameters
    ----------
    file_path : str
        Name of the CSV file inside data/raw/.

    Returns
    -------
    pandas.DataFrame
        Loaded network traffic data.
    """

    path = RAW_DATA_DIR / file_path

    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}\n"
            "Please place the CSV file inside data/raw/."
        )

    print(f"Loading dataset: {path}")

    data = pd.read_csv(path)

    print(f"Rows: {len(data):,}")
    print(f"Columns: {len(data.columns):,}")

    return data