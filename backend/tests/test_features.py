
from backend.ml.features import extract_features


def test_extract_features_counts_urls_and_words():
    text = "URGENT! Verify your account at https://example.com"

    features = extract_features(text)

    assert features["url_count"] == 1
    assert features["word_count"] > 0
    assert features["exclamation_count"] == 1
    assert features["suspicious_term_count"] >= 2


def test_extract_features_handles_empty_text():
    features = extract_features("")

    assert features["text_length"] == 0
    assert features["word_count"] == 0
    assert features["url_count"] == 0
