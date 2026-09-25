import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import pandas as pd


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

LOGS_DIR = PROJECT_ROOT / "logs"
MODELS_DIR = PROJECT_ROOT / "models"

PREDICTION_LOG_FILE = (
    LOGS_DIR
    / "nids_predictions.csv"
)

DRIFT_LOG_FILE = (
    LOGS_DIR
    / "drift_detection.csv"
)

PIPELINE_LOG_FILE = (
    LOGS_DIR
    / "pipeline_log.json"
)

PROMOTION_LOG_FILE = (
    MODELS_DIR
    / "promotion_log.json"
)


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def timestamp():
    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def ensure_directories():
    LOGS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    MODELS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


def run_command(
    *command,
    title,
):
    """
    Run a pipeline subprocess.

    Returns:
        True  -> command completed successfully
        False -> command failed
    """

    print()
    print("=" * 60)
    print(title)
    print("=" * 60)
    print()

    try:
        result = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
        )

    except KeyboardInterrupt:
        print()
        print("=" * 60)
        print(f"{title} INTERRUPTED")
        print("=" * 60)
        print()

        # ----------------------------------------------------
        # LIVE NIDS IS EXPECTED TO BE STOPPED USING CTRL+C.
        # ----------------------------------------------------

        if "LIVE NIDS" in title.upper():

            print(
                "Live NIDS was stopped by the user."
            )

            print(
                "Continuing with the remaining "
                "pipeline steps."
            )

            print()

            return True

        print(
            "Pipeline step was interrupted."
        )

        return False

    except Exception as error:

        print()
        print("=" * 60)
        print(f"{title} FAILED")
        print("=" * 60)
        print()

        print(
            "Execution error:",
            str(error),
        )

        return False

    if result.returncode != 0:

        print()
        print("=" * 60)
        print(f"{title} FAILED")
        print("=" * 60)
        print()

        print(
            f"Process returned exit code: "
            f"{result.returncode}"
        )

        return False

    print()
    print(
        f"{title} COMPLETED"
    )
    print()

    return True


# ============================================================
# CHECK PREDICTION LOG
# ============================================================

def check_prediction_log():
    """
    Verify that the prediction log exists
    before starting drift detection.
    """

    print()
    print("=" * 60)
    print("PIPELINE PRE-CHECK")
    print("=" * 60)
    print()

    if PREDICTION_LOG_FILE.exists():

        print(
            "Prediction log: FOUND"
        )

        return True

    print(
        "Prediction log: NOT FOUND"
    )

    return False


# ============================================================
# DRIFT SUMMARY
# ============================================================

def read_drift_results():
    """
    Read the latest drift detection results.

    Returns:
        significant_drift, significant_features,
        moderate_features
    """

    significant_features = []
    moderate_features = []

    if not DRIFT_LOG_FILE.exists():

        print()
        print(
            "Drift detection file was not found."
        )

        return (
            False,
            significant_features,
            moderate_features,
        )

    try:

        df = pd.read_csv(
            DRIFT_LOG_FILE
        )

    except Exception as error:

        print()
        print(
            "Unable to read drift detection file:",
            str(error),
        )

        return (
            False,
            significant_features,
            moderate_features,
        )

    if df.empty:

        print()
        print(
            "Drift detection file is empty."
        )

        return (
            False,
            significant_features,
            moderate_features,
        )

    if "drift_status" not in df.columns:

        print()
        print(
            "drift_status column not found."
        )

        return (
            False,
            significant_features,
            moderate_features,
        )

    if "feature" not in df.columns:

        print()
        print(
            "feature column not found."
        )

        return (
            False,
            significant_features,
            moderate_features,
        )

    statuses = (
        df["drift_status"]
        .astype(str)
        .str.upper()
    )

    significant_mask = (
        statuses == "SIGNIFICANT_DRIFT"
    )

    moderate_mask = (
        statuses == "MODERATE_DRIFT"
    )

    significant_features = (
        df.loc[
            significant_mask,
            "feature",
        ]
        .astype(str)
        .tolist()
    )

    moderate_features = (
        df.loc[
            moderate_mask,
            "feature",
        ]
        .astype(str)
        .tolist()
    )

    significant_drift = (
        len(significant_features) > 0
    )

    return (
        significant_drift,
        significant_features,
        moderate_features,
    )


# ============================================================
# SAVE PIPELINE AUDIT LOG
# ============================================================

def save_pipeline_log(
    pipeline_status,
    drift_detected,
    significant_features,
    moderate_features,
    retraining_triggered,
    retraining_status,
    promotion_triggered,
    promotion_status,
    duration_seconds,
):
    ensure_directories()

    data = {
        "timestamp": timestamp(),
        "pipeline_status": pipeline_status,
        "drift_detected": drift_detected,
        "significant_features": significant_features,
        "moderate_features": moderate_features,
        "retraining_triggered": retraining_triggered,
        "retraining_status": retraining_status,
        "promotion_triggered": promotion_triggered,
        "promotion_status": promotion_status,
        "duration_seconds": round(
            duration_seconds,
            3,
        ),
    }

    with open(
        PIPELINE_LOG_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
        )

    print()
    print(
        "Pipeline audit log saved:"
    )

    print(
        PIPELINE_LOG_FILE
    )


# ============================================================
# MAIN PIPELINE
# ============================================================

def main():

    start_time = time.time()

    ensure_directories()

    print("=" * 60)
    print(
        "NIDS MLOps AUTOMATED PIPELINE"
    )
    print("=" * 60)

    print()
    print(
        f"Project root: {PROJECT_ROOT}"
    )

    print()

    # --------------------------------------------------------
    # PIPELINE STATE
    # --------------------------------------------------------

    pipeline_status = "FAILED"

    drift_detected = False

    significant_features = []

    moderate_features = []

    retraining_triggered = False

    retraining_status = "NOT_TRIGGERED"

    promotion_triggered = False

    promotion_status = "NOT_TRIGGERED"

    # --------------------------------------------------------
    # PRE-CHECK
    # --------------------------------------------------------

    prediction_log_found = (
        check_prediction_log()
    )

    if not prediction_log_found:

        print()
        print(
            "No prediction log is available."
        )

        print(
            "Pipeline cannot perform drift detection."
        )

        duration_seconds = (
            time.time()
            - start_time
        )

        save_pipeline_log(
            pipeline_status="FAILED",
            drift_detected=False,
            significant_features=[],
            moderate_features=[],
            retraining_triggered=False,
            retraining_status="NOT_TRIGGERED",
            promotion_triggered=False,
            promotion_status="NOT_TRIGGERED",
            duration_seconds=duration_seconds,
        )

        return 1

    # ========================================================
    # STEP 1 - DRIFT DETECTION
    # ========================================================

    print()
    print("=" * 60)
    print("STEP 1 - DRIFT DETECTION")
    print("=" * 60)
    print()

    success = run_command(
        sys.executable,
        "-m",
        "src.drift.detector",
        title="RUNNING: src.drift.detector",
    )

    if not success:

        print()
        print(
            "Drift detection step failed."
        )

        duration_seconds = (
            time.time()
            - start_time
        )

        save_pipeline_log(
            pipeline_status="FAILED",
            drift_detected=False,
            significant_features=[],
            moderate_features=[],
            retraining_triggered=False,
            retraining_status="NOT_TRIGGERED",
            promotion_triggered=False,
            promotion_status="NOT_TRIGGERED",
            duration_seconds=duration_seconds,
        )

        return 1

    # --------------------------------------------------------
    # READ DRIFT RESULTS
    # --------------------------------------------------------

    (
        drift_detected,
        significant_features,
        moderate_features,
    ) = read_drift_results()

    print()
    print("=" * 60)
    print("DRIFT SUMMARY")
    print("=" * 60)
    print()

    if drift_detected:

        print(
            "Significant drift: YES"
        )

        print(
            "Affected features:",
            ", ".join(
                significant_features
            ),
        )

    else:

        print(
            "Significant drift: NO"
        )

        if moderate_features:

            print(
                "Moderate drift features:",
                ", ".join(
                    moderate_features
                ),
            )

        else:

            print(
                "Affected features: NONE"
            )

    print()

    # ========================================================
    # STEP 2 - RETRAINING
    # ========================================================

    if drift_detected:

        retraining_triggered = True

        print(
            "ALERT: SIGNIFICANT DRIFT DETECTED"
        )

        print(
            "Affected features:",
            ", ".join(
                significant_features
            ),
        )

        print()

        print(
            "STEP 2 - SIGNIFICANT DRIFT DETECTED"
        )

        print(
            "Retraining candidate model..."
        )

        print()

        success = run_command(
            sys.executable,
            "-m",
            "src.models.retrain",
            title="RUNNING: src.models.retrain",
        )

        if success:

            retraining_status = (
                "COMPLETED"
            )

        else:

            retraining_status = (
                "FAILED"
            )

            duration_seconds = (
                time.time()
                - start_time
            )

            save_pipeline_log(
                pipeline_status="FAILED",
                drift_detected=True,
                significant_features=(
                    significant_features
                ),
                moderate_features=(
                    moderate_features
                ),
                retraining_triggered=True,
                retraining_status=(
                    retraining_status
                ),
                promotion_triggered=False,
                promotion_status=(
                    "NOT_TRIGGERED"
                ),
                duration_seconds=(
                    duration_seconds
                ),
            )

            return 1

        # ====================================================
        # STEP 3 - MODEL PROMOTION GATE
        # ====================================================

        promotion_triggered = True

        print()
        print(
            "STEP 3 - MODEL PROMOTION GATE"
        )

        print()

        success = run_command(
            sys.executable,
            "-m",
            "src.models.promote",
            title="RUNNING: src.models.promote",
        )

        if success:

            # ------------------------------------------------
            # READ PROMOTION STATUS
            # ------------------------------------------------

            if PROMOTION_LOG_FILE.exists():

                try:

                    with open(
                        PROMOTION_LOG_FILE,
                        "r",
                        encoding="utf-8",
                    ) as file:

                        promotion_data = (
                            json.load(file)
                        )

                    promotion_status = str(
                        promotion_data.get(
                            "promotion_status",
                            "UNKNOWN",
                        )
                    )

                except Exception:

                    promotion_status = (
                        "UNKNOWN"
                    )

            else:

                promotion_status = (
                    "UNKNOWN"
                )

        else:

            promotion_status = (
                "FAILED"
            )

            duration_seconds = (
                time.time()
                - start_time
            )

            save_pipeline_log(
                pipeline_status="FAILED",
                drift_detected=True,
                significant_features=(
                    significant_features
                ),
                moderate_features=(
                    moderate_features
                ),
                retraining_triggered=True,
                retraining_status=(
                    retraining_status
                ),
                promotion_triggered=True,
                promotion_status=(
                    promotion_status
                ),
                duration_seconds=(
                    duration_seconds
                ),
            )

            return 1

    else:

        print()
        print(
            "STEP 2 - NO SIGNIFICANT DRIFT"
        )

        print()
        print(
            "Candidate retraining skipped."
        )

        print(
            "Production model remains unchanged."
        )

        print()

        retraining_triggered = False

        retraining_status = (
            "NOT_TRIGGERED"
        )

        promotion_triggered = False

        promotion_status = (
            "NOT_TRIGGERED"
        )

    # ========================================================
    # FINAL PIPELINE STATUS
    # ========================================================

    pipeline_status = "COMPLETED"

    duration_seconds = (
        time.time()
        - start_time
    )

    save_pipeline_log(
        pipeline_status=pipeline_status,
        drift_detected=drift_detected,
        significant_features=(
            significant_features
        ),
        moderate_features=(
            moderate_features
        ),
        retraining_triggered=(
            retraining_triggered
        ),
        retraining_status=(
            retraining_status
        ),
        promotion_triggered=(
            promotion_triggered
        ),
        promotion_status=(
            promotion_status
        ),
        duration_seconds=(
            duration_seconds
        ),
    )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print()
    print("=" * 60)
    print("FINAL PIPELINE SUMMARY")
    print("=" * 60)
    print()

    print(
        "Drift detected        :",
        "YES" if drift_detected else "NO",
    )

    print(
        "Affected features     :",
        ", ".join(
            significant_features
        )
        if significant_features
        else "NONE",
    )

    print(
        "Candidate retraining  :",
        retraining_status,
    )

    print(
        "Promotion gate        :",
        "EXECUTED"
        if promotion_triggered
        else "NOT_EXECUTED",
    )

    print(
        "Promotion status      :",
        promotion_status,
    )

    print()

    print(
        "NIDS MLOps PIPELINE COMPLETED"
    )

    print("=" * 60)

    return 0 if pipeline_status == "COMPLETED" else 1


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    raise SystemExit(
        main()
    )