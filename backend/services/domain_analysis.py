import socket
import ssl
from urllib.parse import urlparse


def analyze_domain(url):

    result = {
        "domain": None,
        "dns_exists": False,
        "ip_address": None,
        "https": False,
        "risk_score": 0,
        "threat_level": "LOW",
        "reasons": []
    }

    try:
        parsed = urlparse(url)

        domain = parsed.hostname

        if not domain:
            result["risk_score"] = 100
            result["threat_level"] = "HIGH"
            result["reasons"].append(
                "Unable to extract domain from URL"
            )
            return result

        result["domain"] = domain

        # ------------------------------------------------
        # DNS CHECK
        # ------------------------------------------------

        try:

            ip_address = socket.gethostbyname(domain)

            result["dns_exists"] = True
            result["ip_address"] = ip_address

        except socket.gaierror:

            result["dns_exists"] = False
            result["risk_score"] += 30

            result["reasons"].append(
                "Domain does not resolve through DNS"
            )

        # ------------------------------------------------
        # HTTPS CHECK
        # ------------------------------------------------

        if parsed.scheme.lower() == "https":

            result["https"] = True

        else:

            result["https"] = False
            result["risk_score"] += 15

            result["reasons"].append(
                "Domain is not accessed through HTTPS"
            )

        # ------------------------------------------------
        # DOMAIN LENGTH
        # ------------------------------------------------

        if len(domain) > 40:

            result["risk_score"] += 10

            result["reasons"].append(
                "Domain name is unusually long"
            )

        # ------------------------------------------------
        # SUBDOMAIN CHECK
        # ------------------------------------------------

        parts = domain.split(".")

        if len(parts) >= 4:

            result["risk_score"] += 15

            result["reasons"].append(
                "Domain contains many subdomains"
            )

        # ------------------------------------------------
        # NUMERIC DOMAIN
        # ------------------------------------------------

        digit_count = sum(
            character.isdigit()
            for character in domain
        )

        if digit_count >= 5:

            result["risk_score"] += 10

            result["reasons"].append(
                "Domain contains many numeric characters"
            )

        # ------------------------------------------------
        # PUNYCODE
        # ------------------------------------------------

        if domain.lower().startswith("xn--") or ".xn--" in domain.lower():

            result["risk_score"] += 20

            result["reasons"].append(
                "Domain uses Punycode"
            )

        # ------------------------------------------------
        # FINAL SCORE
        # ------------------------------------------------

        result["risk_score"] = min(
            result["risk_score"],
            100
        )

        if result["risk_score"] >= 70:

            result["threat_level"] = "HIGH"

        elif result["risk_score"] >= 40:

            result["threat_level"] = "MEDIUM"

        else:

            result["threat_level"] = "LOW"

        return result

    except Exception as e:

        return {
            "domain": None,
            "dns_exists": False,
            "ip_address": None,
            "https": False,
            "risk_score": 100,
            "threat_level": "HIGH",
            "reasons": [
                f"Domain analysis failed: {str(e)}"
            ]
        }