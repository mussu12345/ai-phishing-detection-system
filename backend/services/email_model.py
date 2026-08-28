# ============================================================
# services/email_model.py
# DYNAMIC PHISHING EMAIL ML MODEL
# ============================================================

import os
import re
import joblib
import numpy as np


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "saved_models"
)


# ============================================================
# MODEL FILES
# ============================================================

MODEL_PATHS = {
    "Logistic Regression": os.path.join(
        MODEL_DIR,
        "logistic_regression.pkl"
    ),
    "Naive Bayes": os.path.join(
        MODEL_DIR,
        "naive_bayes.pkl"
    ),
    "SVM": os.path.join(
        MODEL_DIR,
        "svm.pkl"
    ),
    "Random Forest": os.path.join(
        MODEL_DIR,
        "random_forest.pkl"
    )
}

VECTORIZER_PATH = os.path.join(
    MODEL_DIR,
    "vectorizer.pkl"
)


# ============================================================
# LOAD MODELS ONCE
# ============================================================

models = {}
vectorizer = None


def load_models():

    global models
    global vectorizer

    # Load TF-IDF vectorizer
    if vectorizer is None:

        if not os.path.exists(VECTORIZER_PATH):
            raise FileNotFoundError(
                f"Vectorizer not found: {VECTORIZER_PATH}"
            )

        vectorizer = joblib.load(
            VECTORIZER_PATH
        )

    # Load all four models
    if not models:

        for name, path in MODEL_PATHS.items():

            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"Model not found: {path}"
                )

            models[name] = joblib.load(
                path
            )


# ============================================================
# GET PHISHING PROBABILITY
# ============================================================

def get_phishing_probability(model, features):

    # --------------------------------------------------------
    # Logistic Regression / Naive Bayes / Random Forest
    # --------------------------------------------------------

    if hasattr(model, "predict_proba"):

        probabilities = model.predict_proba(
            features
        )

        classes = list(
            model.classes_
        )

        # Find class 1 = phishing
        if 1 in classes:

            phishing_index = classes.index(1)

        else:

            phishing_index = len(classes) - 1

        probability = probabilities[
            0,
            phishing_index
        ]

        return float(
            probability
        )

    # --------------------------------------------------------
    # SVM
    # --------------------------------------------------------

    if hasattr(model, "decision_function"):

        score = float(
            model.decision_function(
                features
            )[0]
        )

        # Prevent overflow
        score = np.clip(
            score,
            -50,
            50
        )

        probability = (
            1.0 /
            (
                1.0 +
                np.exp(-score)
            )
        )

        return float(
            probability
        )

    # --------------------------------------------------------
    # Fallback
    # --------------------------------------------------------

    prediction = model.predict(
        features
    )[0]

    return 1.0 if int(prediction) == 1 else 0.0


# ============================================================
# EMAIL INDICATORS
# ============================================================

def analyze_indicators(email):

    text = email.lower()

    phishing_indicators = 0
    legitimate_indicators = 0

    reasons = []

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    urls = re.findall(
        r"https?://[^\s]+|www\.[^\s]+",
        email,
        flags=re.IGNORECASE
    )

    if urls:

        phishing_indicators += 1

        reasons.append(
            f"Email contains {len(urls)} URL(s)"
        )

    # --------------------------------------------------------
    # URGENCY
    # --------------------------------------------------------

    urgency_words = [
        "urgent",
        "immediately",
        "action required",
        "act now",
        "verify now",
        "expires",
        "suspended",
        "final warning",
        "within 24 hours",
        "as soon as possible"
    ]

    urgency_found = [
        word
        for word in urgency_words
        if word in text
    ]

    if urgency_found:

        phishing_indicators += 1

        reasons.append(
            "Uses urgency or pressure tactics"
        )

    # --------------------------------------------------------
    # CREDENTIALS
    # --------------------------------------------------------

    credential_words = [
        "password",
        "passwd",
        "login",
        "username",
        "otp",
        "one time password",
        "verification code",
        "security code"
    ]

    credential_found = [
        word
        for word in credential_words
        if word in text
    ]

    if credential_found:

        phishing_indicators += 1

        reasons.append(
            "Email references sensitive credentials"
        )

    # --------------------------------------------------------
    # FINANCIAL
    # --------------------------------------------------------

    financial_words = [
        "bank account",
        "credit card",
        "debit card",
        "payment",
        "transaction",
        "refund",
        "invoice",
        "wallet",
        "account number"
    ]

    financial_found = [
        word
        for word in financial_words
        if word in text
    ]

    if financial_found:

        phishing_indicators += 1

        reasons.append(
            "Email references financial information"
        )

    # --------------------------------------------------------
    # VERIFICATION
    # --------------------------------------------------------

    verification_words = [
        "verify your account",
        "verify account",
        "confirm your identity",
        "confirm identity",
        "verify your identity",
        "account verification"
    ]

    verification_found = [
        word
        for word in verification_words
        if word in text
    ]

    if verification_found:

        phishing_indicators += 1

        reasons.append(
            "Contains account verification language"
        )

    # --------------------------------------------------------
    # SUSPICIOUS LINK + ACCOUNT LANGUAGE
    # --------------------------------------------------------

    account_words = [
        "account",
        "login",
        "verify",
        "verification",
        "password"
    ]

    if urls and any(
        word in text
        for word in account_words
    ):

        phishing_indicators += 1

        reasons.append(
            "Contains a link combined with account or verification language"
        )

    # --------------------------------------------------------
    # LEGITIMATE INDICATORS
    # --------------------------------------------------------

    legitimate_phrases = [
        "thank you for your message",
        "thank you for contacting us",
        "regards",
        "best regards",
        "kind regards",
        "sincerely",
        "looking forward to hearing from you",
        "have a nice day"
    ]

    for phrase in legitimate_phrases:

        if phrase in text:

            legitimate_indicators += 1

    return (
        phishing_indicators,
        legitimate_indicators,
        urls,
        reasons
    )


# ============================================================
# DYNAMIC MODEL CONFIDENCE
# ============================================================

def calculate_model_confidence(phishing_probability):

    probability = float(
        np.clip(
            phishing_probability,
            0.0,
            1.0
        )
    )

    # Confidence is distance from 50%.
    #
    # 50% phishing probability = 50% confidence
    # 90% phishing probability = 90% confidence
    # 10% phishing probability = 90% confidence

    confidence = max(
        probability,
        1.0 - probability
    )

    return confidence * 100.0


# ============================================================
# PREDICT EMAIL
# ============================================================

def predict_email(email):

    if not isinstance(
        email,
        str
    ):
        email = str(email)

    email = email.strip()

    # --------------------------------------------------------
    # EMPTY EMAIL
    # --------------------------------------------------------

    if not email:

        return {
            "prediction": "Suspicious",
            "threat_level": "MEDIUM",
            "risk_score": 50,
            "reasons": [
                "No email content was provided"
            ],
            "prevention": [
                "Enter valid email content"
            ],
            "model_results": []
        }

    # --------------------------------------------------------
    # LOAD MODELS
    # --------------------------------------------------------

    load_models()

    # --------------------------------------------------------
    # TF-IDF
    # --------------------------------------------------------

    features = vectorizer.transform(
        [email]
    )

    # --------------------------------------------------------
    # MODEL RESULTS
    # --------------------------------------------------------

    model_results = []
    probabilities = []

    for name, model in models.items():

        try:

            probability = get_phishing_probability(
                model,
                features
            )

            probability = float(
                np.clip(
                    probability,
                    0.0,
                    1.0
                )
            )

            # ------------------------------------------------
            # CURRENT EMAIL PREDICTION
            # ------------------------------------------------

            if probability >= 0.50:

                prediction = "Phishing"

            else:

                prediction = "Safe"

            # ------------------------------------------------
            # CURRENT EMAIL CONFIDENCE
            # ------------------------------------------------

            confidence = calculate_model_confidence(
                probability
            )

            model_results.append({

                "name": name,

                "prediction": prediction,

                "confidence": round(
                    confidence,
                    2
                ),

                "phishing_probability": round(
                    probability * 100,
                    2
                )

            })

            probabilities.append(
                probability
            )

        except Exception as e:

            print(
                f"MODEL ERROR - {name}: {e}"
            )

            model_results.append({

                "name": name,

                "prediction": "Unavailable",

                "confidence": 0,

                "phishing_probability": 0,

                "error": str(e)

            })

    # ========================================================
    # INDICATORS
    # ========================================================

    (
        phishing_indicators,
        legitimate_indicators,
        urls,
        indicator_reasons
    ) = analyze_indicators(
        email
    )

    # ========================================================
    # ML ENSEMBLE
    # ========================================================

    valid_probabilities = [
        p
        for p in probabilities
        if p is not None
    ]

    if valid_probabilities:

        ml_probability = float(
            np.mean(
                valid_probabilities
            )
        )

    else:

        ml_probability = 0.50

    ml_percentage = (
        ml_probability * 100
    )

    # ========================================================
    # FINAL CLASSIFICATION
    # ========================================================

    if ml_probability >= 0.70:

        prediction = "Phishing"

    elif ml_probability <= 0.30:

        prediction = "Safe"

    else:

        if phishing_indicators >= 3:

            prediction = "Phishing"

        elif phishing_indicators == 0:

            prediction = "Safe"

        else:

            prediction = "Suspicious"

    # ========================================================
    # RISK SCORE
    # ========================================================

    risk_score = ml_percentage

    if phishing_indicators >= 4:

        risk_score += 15

    elif phishing_indicators == 3:

        risk_score += 10

    elif phishing_indicators == 2:

        risk_score += 5

    risk_score -= (
        legitimate_indicators * 3
    )

    risk_score = max(
        0,
        min(
            risk_score,
            100
        )
    )

    # ========================================================
    # THREAT LEVEL
    # ========================================================

    if risk_score >= 70:

        threat_level = "HIGH"

    elif risk_score >= 40:

        threat_level = "MEDIUM"

    else:

        threat_level = "LOW"

    # ========================================================
    # BEST MODEL FOR THIS EMAIL
    # ========================================================
    #
    # IMPORTANT:
    # We calculate this separately for every email.
    #
    # The model with the highest confidence for the CURRENT
    # email becomes the best model for that email.
    #
    # Therefore it is NOT hard-coded to Random Forest.
    # ========================================================

    available_models = [
        model
        for model in model_results
        if model.get("prediction") != "Unavailable"
        and model.get("confidence", 0) > 0
    ]

    if available_models:

        best_model = max(
            available_models,
            key=lambda model: model["confidence"]
        )

    else:

        best_model = None

    # ========================================================
    # REASONS
    # ========================================================

    reasons = []

    if phishing_indicators >= 3:

        reasons.append(
            "Multiple phishing indicators were detected"
        )

    elif phishing_indicators == 2:

        reasons.append(
            "Several suspicious email indicators were detected"
        )

    elif phishing_indicators == 1:

        reasons.append(
            "A suspicious email indicator was detected"
        )

    reasons.extend(
        indicator_reasons
    )

    reasons.append(
        f"ML ensemble estimated a phishing probability of {ml_percentage:.1f}%"
    )

    if best_model:

        reasons.append(
            f"{best_model['name']} gave the highest confidence for this email "
            f"({best_model['confidence']:.2f}%)"
        )

    if prediction == "Phishing":

        reasons.append(
            "The machine learning models classify this email as phishing"
        )

    elif prediction == "Safe":

        reasons.append(
            "The machine learning models classify this email as legitimate"
        )

    else:

        reasons.append(
            "The machine learning assessment is borderline and requires caution"
        )

    if not reasons:

        reasons.append(
            "No strong phishing behavior was detected"
        )

    # Remove duplicates
    reasons = list(
        dict.fromkeys(
            reasons
        )
    )

    # ========================================================
    # PREVENTION
    # ========================================================

    if prediction == "Phishing":

        prevention = [

            "Do not click links in the email",

            "Do not enter passwords, OTPs or financial information",

            "Verify the sender using an official website or known contact",

            "Report the email as phishing",

            "Delete the email if confirmed malicious"

        ]

    elif prediction == "Suspicious":

        prevention = [

            "Avoid clicking links until the sender is verified",

            "Do not provide passwords or OTPs",

            "Verify the request through an official channel",

            "Check the sender address carefully"

        ]

    else:

        prevention = [

            "No major phishing indicators detected",

            "Continue to verify unexpected requests",

            "Avoid sharing sensitive information unnecessarily"

        ]

    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        "prediction": prediction,

        "threat_level": threat_level,

        "risk_score": round(
            risk_score,
            2
        ),

        "reasons": reasons,

        "prevention": prevention,

        "model_results": model_results,

        # IMPORTANT:
        # Send best model explicitly to React.
        "best_model": (
            {
                "name": best_model["name"],
                "prediction": best_model["prediction"],
                "confidence": best_model["confidence"],
                "phishing_probability":
                    best_model["phishing_probability"]
            }
            if best_model
            else None
        ),

        "email_analysis": {

            "ml_phishing_probability": round(
                ml_percentage,
                2
            ),

            "phishing_indicators":
                phishing_indicators,

            "legitimate_indicators":
                legitimate_indicators,

            "urls_detected":
                len(urls)

        }

    }