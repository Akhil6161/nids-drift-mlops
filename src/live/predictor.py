import os
import joblib
import pandas as pd


MODEL_PATH = os.path.join(
    "models",
    "nids_random_forest.joblib"
)


class NIDSPredictor:

    def __init__(self, model_path=MODEL_PATH):

        print("Loading NIDS model...")

        self.model = joblib.load(model_path)

        self.feature_names = list(
            self.model.feature_names_in_
        )

        print("Model loaded successfully.")
        print(
            "Expected features:",
            len(self.feature_names)
        )

    def predict(self, features):

        # Convert dictionary to DataFrame
        df = pd.DataFrame(
            [features]
        )

        # Make sure the columns are in exactly
        # the same order as during training.
        df = df.reindex(
            columns=self.feature_names,
            fill_value=0
        )

        prediction = self.model.predict(df)[0]

        probability = self.model.predict_proba(df)[0]

        attack_probability = probability[1]

        if prediction == 1:
            label = "ATTACK"
        else:
            label = "BENIGN"

        return {
            "prediction": int(prediction),
            "label": label,
            "attack_probability":
                float(attack_probability),
        }


def main():

    print()
    print("=" * 60)
    print("NIDS LIVE PREDICTOR")
    print("=" * 60)

    predictor = NIDSPredictor()

    print()
    print("Predictor is ready.")


if __name__ == "__main__":
    main()