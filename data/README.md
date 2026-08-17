# Network Traffic Data

This directory contains the datasets used by the NIDS Drift MLOps project.

## Structure

- `raw/` - Original downloaded network traffic datasets.
- `processed/` - Cleaned and ML-ready datasets.

## Dataset

The project initially uses the CICIDS2017 intrusion detection dataset.

The raw dataset should not be modified. Any preprocessing or feature engineering should create files under `processed/`.

## Important

Large datasets are intentionally not committed to GitHub.