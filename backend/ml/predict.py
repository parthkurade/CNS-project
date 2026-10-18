
"""Predict whether an email is spam using the saved model."""

from __future__ import annotations

from pathlib import Path

import joblib

DEFAULT_MODEL = Path("backend/ml/email_model.joblib")


def predict_email(
    text: str,
    model_path: Path = DEFAULT_MODEL,
) -> dict[str, object]:
    """Classify email text and return its predicted label and confidence."""
    if not model_path.exists():
        raise FileNotFoundError(
            f"Model not found at {model_path}. Train the model first."
        )

    model = joblib.load(model_path)
    prediction = int(model.predict([text])[0])

    probabilities = model.predict_proba([text])[0]
    confidence = float(max(probabilities))

    return {
        "label": "spam" if prediction == 1 else "ham",
        "confidence": confidence,
    }


if __name__ == "__main__":
    sample = input("Paste email text: ")
    print(predict_email(sample))
