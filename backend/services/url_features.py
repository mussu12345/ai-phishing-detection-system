import re
from urllib.parse import urlparse

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False
def analyze_url(url):

    score = 0
    reasons = []

    # URL Length
    if len(url) > 50:
        score += 20
        reasons.append("URL is unusually long")

    # Hyphens
    if url.count("-") > 2:
        score += 20
        reasons.append("Too many hyphens")

    # HTTPS
    if not url.startswith("https"):
        score += 25
        reasons.append("Not using HTTPS")

    # Suspicious Keywords
    suspicious_words = [
        "login",
        "verify",
        "secure",
        "update",
        "bank",
        "account"
    ]

    for word in suspicious_words:
        if word in url.lower():
            score += 10
            reasons.append(f"Contains '{word}' keyword")

    # IP Address Detection
    ip_pattern = r"(\d+\.\d+\.\d+\.\d+)"

    if re.search(ip_pattern, url):
        score += 25
        reasons.append("Uses IP address instead of domain")

    # Threat Classification
    if score >= 70:
        threat_level = "HIGH"
        prediction = "Phishing"

    elif score >= 40:
        threat_level = "MEDIUM"
        prediction = "Suspicious"

    else:
        threat_level = "LOW"
        prediction = "Safe"

    return {
        "prediction": prediction,
        "risk_score": min(score, 100),
        "threat_level": threat_level,
        "reasons": reasons
    }