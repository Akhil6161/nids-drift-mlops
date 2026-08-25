import os
import time
from datetime import datetime

import pandas as pd

from src.drift.detector import (
    PREDICTION_FILE,
    DRIFT_LOG_FILE,
    REFERENCE_SIZE,
    MIN_CURRENT_SIZE,
    detect_drift,
    save_results,
)


# ============================================================
# CONFIGURATION
# ============================================================

CHECK_INTERVAL_SECONDS = 30

LAST_CHECKED_COUNT = 0


# ============================================================
# DISPLAY DRIFT RESULTS
# ============================================================

def display_results(results):

    print()
    print("=" * 60)
    print("DRIFT MONITORING RESULT")
    print("=" * 60)

    print(
        "Time:",
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
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

    significant = results[
        results["drift_status"]
        == "SIGNIFICANT_DRIFT"
    ]

    moderate = results[
        results["drift_status"]
        == "MODERATE_DRIFT"
    ]

    if len(significant) > 0:

        print(
            "ALERT: SIGNIFICANT DRIFT DETECTED"
        )

        print(
            "Affected features:",
            ", ".join(
                significant["feature"].tolist()
            ),
        )

    elif len(moderate) > 0:

        print(
            "WARNING: MODERATE DRIFT DETECTED"
        )

    else:

        print(
            "STATUS: NO SIGNIFICANT DRIFT"
        )

    print("=" * 60)


# ============================================================
# RUN DRIFT CHECK
# ============================================================

def run_drift_check():

    if not os.path.exists(
        PREDICTION_FILE
    ):

        print(
            "[Monitor] Prediction file not found."
        )

        return

    try:

        df = pd.read_csv(
            PREDICTION_FILE
        )

    except Exception as e:

        print(
            "[Monitor] Could not read prediction file:",
            str(e),
        )

        return

    total_predictions = len(df)

    print()
    print(
        "[Monitor] Predictions available:",
        total_predictions,
    )

    required_samples = (
        REFERENCE_SIZE
        + MIN_CURRENT_SIZE
    )

    if total_predictions < required_samples:

        print(
            "[Monitor] Waiting for enough predictions."
        )

        print(
            "[Monitor] Required:",
            required_samples,
        )

        print(
            "[Monitor] Available:",
            total_predictions,
        )

        return

    try:

        results = detect_drift(df)

        save_results(results)

        display_results(results)

    except Exception as e:

        print(
            "[Monitor] Drift detection error:",
            str(e),
        )


# ============================================================
# MAIN MONITOR LOOP
# ============================================================

def main():

    global LAST_CHECKED_COUNT

    print("=" * 60)
    print("NIDS AUTOMATIC DRIFT MONITOR")
    print("=" * 60)

    print()

    print(
        "Prediction file:",
        PREDICTION_FILE,
    )

    print(
        "Drift log:",
        DRIFT_LOG_FILE,
    )

    print(
        "Check interval:",
        CHECK_INTERVAL_SECONDS,
        "seconds",
    )

    print()

    print(
        "The monitor is running."
    )

    print(
        "Press Ctrl+C to stop."
    )

    print()

    try:

        while True:

            if os.path.exists(
                PREDICTION_FILE
            ):

                try:

                    df = pd.read_csv(
                        PREDICTION_FILE
                    )

                    current_count = len(df)

                    if (
                        current_count
                        != LAST_CHECKED_COUNT
                    ):

                        LAST_CHECKED_COUNT = (
                            current_count
                        )

                        run_drift_check()

                    else:

                        print(
                            datetime.now().strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),
                            "- No new predictions.",
                        )

                except Exception as e:

                    print(
                        "[Monitor] Error:",
                        str(e),
                    )

            else:

                print(
                    "[Monitor] Waiting for prediction file..."
                )

            time.sleep(
                CHECK_INTERVAL_SECONDS
            )

    except KeyboardInterrupt:

        print()
        print(
            "Drift monitor stopped by user."
        )

    print()
    print("=" * 60)
    print("DRIFT MONITOR STOPPED")
    print("=" * 60)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()