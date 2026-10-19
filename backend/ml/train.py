
"""Train and save an email spam/phishing classification model."""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

DEFAULT_DATA = Path("data/emails.csv")
DEFAULT_MODEL = Path("backend/ml/email_model.joblib")


def train_model(data_path: Path, model_path: Path) -> dict[str, object]:
    """Train a TF-IDF + Logistic Regression model and save it."""
    data = pd.read_csv(data_path)

    required_columns = {"text", "label"}
    if not required_columns.issubset(data.columns):
        raise ValueError("Dataset must contain 'text' and 'label' columns.")

    data = data.dropna(subset=["text", "label"])
    if data["label"].nunique() < 2:
        raise ValueError("Training data must contain at least two classes.")

    x_train, x_test, y_train, y_test = train_test_split(
        data["text"].astype(str),
        data["label"].astype(int),
        test_size=0.2,
        random_state=42,
        stratify=data["label"],
    )

    model = Pipeline(
        [
            ("tfidf", TfidfVectorizer(stop_words="english", max_features=20000)),
            ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced")),
        ]
    )

    model.fit(x_train, y_train)
    predictions = model.predict(x_test)

    report = classification_report(y_test, predictions, output_dict=True)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)

    print(f"Model saved to: {model_path}")
    print(classification_report(y_test, predictions))

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    args = parser.parse_args()

    train_model(args.data, args.model)


if __name__ == "__main__":
    main()
