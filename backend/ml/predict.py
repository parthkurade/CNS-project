"""Predict whether an email is spam/phishing using the saved model."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import joblib

DEFAULT_MODEL = Path("backend/ml/email_model.joblib")


@dataclass
class MLResult:
    probability: float
    verdict: str
    top_features: list[dict] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.verdict


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


def predict_phishing(
    text: str,
    subject: str = "",
    url_features: dict | None = None,
    header_features: dict | None = None,
    model_path: Path = DEFAULT_MODEL,
) -> MLResult:
    """Predict phishing probability for pipeline integration."""
    full_text = f"Subject: {subject}\n\n{text}".strip()
    if not model_path.exists():
        return MLResult(probability=0.0, verdict="LEGITIMATE", top_features=[])

    try:
        model = joblib.load(model_path)
        probabilities = model.predict_proba([full_text])[0]
        # class 1 is spam / phishing
        prob = float(probabilities[1]) if len(probabilities) > 1 else float(probabilities[0])

        top_features: list[dict] = []
        if hasattr(model, "named_steps") and "tfidf" in model.named_steps:
            vec = model.named_steps["tfidf"]
            classifier = model.named_steps.get("classifier")
            if hasattr(classifier, "coef_"):
                feature_names = vec.get_feature_names_out()
                coefs = classifier.coef_[0]
                # find words present in text
                words = set(full_text.lower().split())
                matched = []
                for idx, name in enumerate(feature_names):
                    if name in words and coefs[idx] > 0:
                        matched.append({"feature": name, "weight": round(float(coefs[idx]), 3)})
                matched.sort(key=lambda x: x["weight"], reverse=True)
                top_features = matched[:5]

        if prob >= 0.70:
            verdict = "MALICIOUS"
        elif prob >= 0.40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LEGITIMATE"

        return MLResult(probability=prob, verdict=verdict, top_features=top_features)
    except Exception:
        return MLResult(probability=0.0, verdict="LEGITIMATE", top_features=[])
