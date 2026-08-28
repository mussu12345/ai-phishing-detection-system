import json
from services.email_model import predict_email


def process_email_dataset(file_path="data/emails.json"):

    with open(file_path, "r", encoding="utf-8") as file:
        emails = json.load(file)

    results = []

    for email in emails:

        analysis = predict_email(email["body"])

        result = {
            "email_id": email["email_id"],
            "sender": email["sender"],
            "subject": email["subject"],
            "body": email["body"],
            "prediction": analysis.get(
                "prediction",
                "Suspicious"
            ),
            "threat_level": analysis.get(
                "threat_level",
                "MEDIUM"
            ),
            "risk_score": analysis.get(
                "risk_score",
                0
            ),
            "reasons": analysis.get(
                "reasons",
                []
            ),
            "prevention": analysis.get(
                "prevention",
                []
            ),
            "status": get_email_status(
                analysis.get(
                    "threat_level",
                    "MEDIUM"
                )
            )
        }

        results.append(result)

    return results


def get_email_status(threat_level):

    threat_level = str(
        threat_level
    ).upper()

    if threat_level == "HIGH":
        return "QUARANTINED"

    elif threat_level == "MEDIUM":
        return "FLAGGED"

    return "DELIVERED"