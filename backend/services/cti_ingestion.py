import csv
import os
import re
from urllib.parse import urlparse

from database import add_threat_indicator


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_SOURCE = "public_dataset"


# ============================================================
# URL VALIDATION
# ============================================================

def is_valid_url(url):

    if not url:
        return False

    url = url.strip()

    try:
        parsed = urlparse(url)

        return (
            parsed.scheme in ["http", "https"]
            and bool(parsed.netloc)
        )

    except Exception:
        return False


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domain(url):

    try:

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        # Remove username/password if present
        if "@" in domain:
            domain = domain.split("@")[-1]

        # Remove port
        domain = domain.split(":")[0]

        # Remove www
        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    except Exception:
        return None


# ============================================================
# BASIC DOMAIN VALIDATION
# ============================================================

def is_valid_domain(domain):

    if not domain:
        return False

    # Basic domain pattern
    pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    return bool(re.match(pattern, domain))


# ============================================================
# INDICATOR CLASSIFICATION
# ============================================================

def classify_indicator(value):

    value = value.strip()

    # URL
    if is_valid_url(value):

        return "url"

    # IPv4
    ip_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    if re.match(ip_pattern, value):

        return "ip"

    # Domain
    if is_valid_domain(value):

        return "domain"

    return None


# ============================================================
# THREAT TYPE
# ============================================================

def determine_threat_type(indicator_type):

    if indicator_type in ["url", "domain"]:

        return "phishing"

    if indicator_type == "ip":

        return "malicious_infrastructure"

    return "unknown"


# ============================================================
# SEVERITY
# ============================================================

def determine_severity(indicator_type):

    if indicator_type == "url":
        return "high"

    if indicator_type == "domain":
        return "high"

    if indicator_type == "ip":
        return "high"

    return "medium"


# ============================================================
# CONFIDENCE
# ============================================================

def determine_confidence(
    indicator_type,
    source="public_dataset"
):

    # Initial confidence policy.
    #
    # IMPORTANT:
    # This is NOT claiming that the indicator is
    # objectively this percentage malicious.
    #
    # It represents our confidence in the imported
    # intelligence based on the source.

    if source == "verified_feed":

        return 95

    if source == "public_dataset":

        return 80

    if source == "internal_test":

        return 95

    return 70


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_indicator(value):

    value = value.strip()

    # Remove surrounding quotes
    value = value.strip("\"'")

    # URL normalization
    if value.startswith(("http://", "https://")):

        try:

            parsed = urlparse(value)

            scheme = parsed.scheme.lower()

            domain = parsed.netloc.lower()

            path = parsed.path.rstrip("/")

            query = parsed.query

            normalized = f"{scheme}://{domain}{path}"

            if query:
                normalized += f"?{query}"

            return normalized

        except Exception:
            return value.lower()

    # Domain / IP normalization
    return value.lower().rstrip(".")


# ============================================================
# PROCESS ONE INDICATOR
# ============================================================

def process_indicator(
    indicator,
    source=DEFAULT_SOURCE
):

    if not indicator:

        return {
            "success": False,
            "reason": "Empty indicator"
        }

    normalized = normalize_indicator(indicator)

    indicator_type = classify_indicator(normalized)

    if not indicator_type:

        return {
            "success": False,
            "reason": "Unsupported indicator format",
            "indicator": indicator
        }

    threat_type = determine_threat_type(
        indicator_type
    )

    severity = determine_severity(
        indicator_type
    )

    confidence = determine_confidence(
        indicator_type,
        source
    )

    add_threat_indicator(
        indicator=normalized,
        indicator_type=indicator_type,
        threat_type=threat_type,
        severity=severity,
        confidence=confidence,
        source=source
    )

    return {
        "success": True,
        "indicator": normalized,
        "indicator_type": indicator_type,
        "threat_type": threat_type,
        "severity": severity,
        "confidence": confidence,
        "source": source
    }


# ============================================================
# IMPORT CSV DATASET
# ============================================================

def import_csv(
    file_path,
    column_name="url",
    source=DEFAULT_SOURCE
):

    if not os.path.exists(file_path):

        raise FileNotFoundError(
            f"Dataset not found: {file_path}"
        )

    processed = 0
    skipped = 0

    results = []

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        reader = csv.DictReader(file)

        if not reader.fieldnames:

            raise ValueError(
                "CSV does not contain a header"
            )

        if column_name not in reader.fieldnames:

            raise ValueError(
                f"Column '{column_name}' not found. "
                f"Available columns: {reader.fieldnames}"
            )

        for row in reader:

            value = row.get(column_name)

            result = process_indicator(
                value,
                source
            )

            results.append(result)

            if result["success"]:

                processed += 1

            else:

                skipped += 1

    return {
        "processed": processed,
        "skipped": skipped,
        "total": processed + skipped,
        "results": results
    }