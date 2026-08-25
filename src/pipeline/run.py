import subprocess
import sys


def run_command(command, title):
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)
    print()

    result = subprocess.run(command)

    if result.returncode != 0:
        print()
        print("=" * 60)
        print(f"{title} FAILED")
        print("=" * 60)
        return False

    return True


def main():
    print("=" * 60)
    print("NIDS MLOPS PIPELINE")
    print("=" * 60)

    print()
    print("Project pipeline:")
    print("1. Live network capture")
    print("2. ML prediction")
    print("3. Prediction logging")
    print("4. Drift detection")
    print()

    # ---------------------------------------------------------
    # STEP 1 - LIVE NIDS
    # ---------------------------------------------------------

    success = run_command(
        [sys.executable, "-m", "src.live.nids"],
        "STEP 1 - LIVE NIDS"
    )

    if not success:
        return

    # ---------------------------------------------------------
    # STEP 2 - DRIFT DETECTION
    # ---------------------------------------------------------

    success = run_command(
        [sys.executable, "-m", "src.drift.detector"],
        "STEP 2 - DRIFT DETECTION"
    )

    if not success:
        return

    # ---------------------------------------------------------
    # PIPELINE COMPLETE
    # ---------------------------------------------------------

    print()
    print("=" * 60)
    print("NIDS MLOPS PIPELINE COMPLETE")
    print("=" * 60)

    print()
    print("Prediction log:")
    print("logs/nids_predictions.csv")

    print()
    print("Drift log:")
    print("logs/drift_results.csv")

    print()
    print("Pipeline finished successfully.")


if __name__ == "__main__":
    main()
