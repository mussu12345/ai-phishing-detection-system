import joblib

model = joblib.load("saved_models/phishing_model.pkl")
vectorizer = joblib.load("saved_models/vectorizer.pkl")

email = """
URGENT!

Your bank account has been suspended.

Click here to verify your account and update your password.
"""

email_vector = vectorizer.transform([email])

prediction = model.predict(email_vector)[0]

probability = model.predict_proba(email_vector)[0]

print("Prediction:", prediction)
print("Confidence:", max(probability) * 100)