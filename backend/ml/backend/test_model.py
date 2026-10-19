
import joblib
import pandas as pd
import pytest
from sklearn.pipeline import Pipeline

from backend.ml.predict import predict_email
from backend.ml.train import train_model


def test_train_model_saves_model(tmp_path):
    data_path = tmp_path / "emails.csv"
    model_path = tmp_path / "email_model.joblib"

    dataset = pd.DataFrame(
        {
            "text": [
                "hello friend how are you",
                "meeting scheduled for tomorrow",
                "project report attached",
                "see you at lunch",
                "claim your prize now",
                "urgent verify your account",
                "winner click here now",
                "update your bank password",
                "free offer claim reward",
                "account suspended act now",
            ],
            "label": [0, 0, 0, 0, 1, 1, 1, 1, 1, 1],
        }
    )
    dataset.to_csv(data_path, index=False)

    train_model(data_path, model_path)

    assert model_path.exists()
    model = joblib.load(model_path)
    assert isinstance(model, Pipeline)


def test_predict_email_requires_trained_model(tmp_path):
    missing_model = tmp_path / "missing_model.joblib"

    with pytest.raises(FileNotFoundError):
        predict_email("Hello there", missing_model)
