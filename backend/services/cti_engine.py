from urllib.parse import urlparse
import ipaddress

from database import get_threat_indicator


# ============================================================
# NORMALIZE URL
# ============================================================

def normalize_url(url):

    if not url:
        return None

    url = url.strip()

    try:

        parsed = urlparse(url)

        if not parsed.scheme or not parsed.netloc:
            return None

        scheme = parsed.scheme.lower()
        domain = parsed.netloc.lower()

        path = parsed.path.rstrip("/")

        normalized = f"{scheme}://{domain}{path}"

        if parsed.query:
            normalized += f"?{parsed.query}"

        return normalized

    except Exception:

        return None


# ============================================================
# EXTRACT DOMAIN
# ============================================================

def extract_domain(url):

    try:

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        # Remove username/password
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
# CHECK IP
# ============================================================

def is_ip_address(value):

    try:

        ipaddress.ip_address(value)

        return True

    except ValueError:

        return False


# ============================================================
# CTI ANALYSIS
# ============================================================

def analyze_cti(url):

    result = {

        "matched": False,

        "indicator_type": None,

        "indicator": None,

        "threat_type": None,

        "severity": None,

        "confidence": 0,

        "source": None,

        "risk_score": 0,

        "reasons": []

    }

    # --------------------------------------------------------
    # Normalize
    # --------------------------------------------------------

    normalized_url = normalize_url(url)

    if not normalized_url:

        result["reasons"].append(
            "Invalid URL format"
        )

        return result

    # --------------------------------------------------------
    # 1. EXACT URL LOOKUP
    # --------------------------------------------------------

    url_indicator = get_threat_indicator(
        normalized_url,
        "url"
    )

    if url_indicator:

        result["matched"] = True

        result["indicator_type"] = "url"

        result["indicator"] = (
            url_indicator["indicator"]
        )

        result["threat_type"] = (
            url_indicator["threat_type"]
        )

        result["severity"] = (
            url_indicator["severity"]
        )

        result["confidence"] = (
            url_indicator["confidence"]
        )

        result["source"] = (
            url_indicator["source"]
        )

        # CTI confidence becomes risk contribution
        result["risk_score"] = min(
            100,
            url_indicator["confidence"]
        )

        result["reasons"].append(
            "URL matched a known threat indicator"
        )

        return result

    # --------------------------------------------------------
    # 2. DOMAIN LOOKUP
    # --------------------------------------------------------

    domain = extract_domain(normalized_url)

    if not domain:

        return result

    domain_indicator = get_threat_indicator(
        domain,
        "domain"
    )

    if domain_indicator:

        result["matched"] = True

        result["indicator_type"] = "domain"

        result["indicator"] = (
            domain_indicator["indicator"]
        )

        result["threat_type"] = (
            domain_indicator["threat_type"]
        )

        result["severity"] = (
            domain_indicator["severity"]
        )

        result["confidence"] = (
            domain_indicator["confidence"]
        )

        result["source"] = (
            domain_indicator["source"]
        )

        result["risk_score"] = min(
            100,
            domain_indicator["confidence"]
        )

        result["reasons"].append(
            "Domain matched a known threat indicator"
        )

        return result

    # --------------------------------------------------------
    # 3. IP LOOKUP
    # --------------------------------------------------------

    if is_ip_address(domain):

        ip_indicator = get_threat_indicator(
            domain,
            "ip"
        )

        if ip_indicator:

            result["matched"] = True

            result["indicator_type"] = "ip"

            result["indicator"] = (
                ip_indicator["indicator"]
            )

            result["threat_type"] = (
                ip_indicator["threat_type"]
            )

            result["severity"] = (
                ip_indicator["severity"]
            )

            result["confidence"] = (
                ip_indicator["confidence"]
            )

            result["source"] = (
                ip_indicator["source"]
            )

            result["risk_score"] = min(
                100,
                ip_indicator["confidence"]
            )

            result["reasons"].append(
                "IP address matched a known threat indicator"
            )

            return result

    # --------------------------------------------------------
    # NO MATCH
    # --------------------------------------------------------

    result["reasons"].append(
        "No matching IOC found in local threat database"
    )

    return result