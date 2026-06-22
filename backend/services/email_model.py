import joblib

model = joblib.load("saved_models/phishing_model.pkl")
vectorizer = joblib.load("saved_models/vectorizer.pkl")


def predict_email(email_text):

    email_vector = vectorizer.transform([email_text])

    prediction = model.predict(email_vector)[0]

    confidence = model.predict_proba(email_vector)[0]

    risk_score = round(max(confidence) * 100)

    if prediction == 1:
        return {
            "prediction": "Phishing",
            "threat_level": "HIGH",
            "risk_score": risk_score,
            "reasons": [
                "AI model classified email as phishing"
            ]
        }

    return {
        "prediction": "Safe",
        "threat_level": "LOW",
        "risk_score": risk_score,
        "reasons": [
            "AI model classified email as legitimate"
        ]
    }