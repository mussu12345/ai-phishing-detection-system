
import re
import socket
from urllib.parse import urlparse, unquote
from difflib import SequenceMatcher


# ============================================================
# TRUSTED DOMAINS
# ============================================================

TRUSTED_DOMAINS = {
    "google.com": "Google",
    "microsoft.com": "Microsoft",
    "github.com": "GitHub",
    "wikipedia.org": "Wikipedia"
}


# ============================================================
# URL VALIDATION
# ============================================================

def is_valid_url(url):
    """
    Check whether the input is a valid HTTP/HTTPS URL.
    """

    try:
        result = urlparse(url)

        return bool(
            result.scheme.lower() in ["http", "https"]
            and result.netloc
            and result.hostname
        )

    except Exception:
        return False


# ============================================================
# IP ADDRESS DETECTION
# ============================================================

def is_ip_address(hostname):
    """
    Detect whether hostname is a valid IPv4 address.
    """

    if not hostname:
        return False

    ipv4_pattern = (
        r"^(?:25[0-5]|2[0-4][0-9]|"
        r"1[0-9]{2}|[1-9]?[0-9])\."
        r"(?:25[0-5]|2[0-4][0-9]|"
        r"1[0-9]{2}|[1-9]?[0-9])\."
        r"(?:25[0-5]|2[0-4][0-9]|"
        r"1[0-9]{2}|[1-9]?[0-9])\."
        r"(?:25[0-5]|2[0-4][0-9]|"
        r"1[0-9]{2}|[1-9]?[0-9])$"
    )

    return bool(
        re.match(
            ipv4_pattern,
            hostname
        )
    )


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def get_base_domain(hostname):
    """
    Extract the main domain.

    Example:
        login.google.com -> google.com
        www.google.com   -> google.com
        google.com       -> google.com
    """

    if not hostname:
        return ""

    hostname = hostname.lower().strip()

    if hostname.startswith("www."):
        hostname = hostname[4:]

    parts = hostname.split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname


# ============================================================
# DOMAIN SIMILARITY
# ============================================================

def get_domain_similarity(domain1, domain2):
    """
    Calculate similarity between two domains.
    """

    return (
        SequenceMatcher(
            None,
            domain1.lower(),
            domain2.lower()
        ).ratio()
        * 100
    )


# ============================================================
# LOOKALIKE / TYPOSQUATTING DETECTION
# ============================================================

def analyze_lookalike_domain(hostname):
    """
    Detect domains that resemble trusted domains.

    Examples:

        google.com
            -> legitimate

        googe.com
            -> possible typosquatting

        g00gle.com
            -> possible lookalike

        google-login.xyz
            -> possible brand impersonation
    """

    if not hostname:
        return {
            "matched": False,
            "legitimate": False,
            "risk_score": 0,
            "similarity": 0,
            "matched_domain": None,
            "brand": None,
            "reason": None
        }

    hostname = hostname.lower().strip()

    if hostname.startswith("www."):
        hostname = hostname[4:]

    base_domain = get_base_domain(hostname)

    # --------------------------------------------------------
    # EXACT TRUSTED DOMAIN
    # --------------------------------------------------------

    if base_domain in TRUSTED_DOMAINS:

        # Exact trusted domain is legitimate.
        if hostname == base_domain:
            return {
                "matched": False,
                "legitimate": True,
                "risk_score": 0,
                "similarity": 100,
                "matched_domain": base_domain,
                "brand": TRUSTED_DOMAINS[base_domain],
                "reason": None
            }

        # A subdomain is NOT automatically trusted.
        # Example:
        # fake-login.google.com
        #
        # It belongs to google.com technically, but
        # the subdomain itself may still be suspicious.
        return {
            "matched": False,
            "legitimate": True,
            "risk_score": 0,
            "similarity": 100,
            "matched_domain": base_domain,
            "brand": TRUSTED_DOMAINS[base_domain],
            "reason": None
        }

    # --------------------------------------------------------
    # FIND CLOSEST TRUSTED DOMAIN
    # --------------------------------------------------------

    best_similarity = 0
    best_domain = None
    best_brand = None

    for trusted_domain, brand in TRUSTED_DOMAINS.items():

        similarity = get_domain_similarity(
            base_domain,
            trusted_domain
        )

        if similarity > best_similarity:
            best_similarity = similarity
            best_domain = trusted_domain
            best_brand = brand

    # --------------------------------------------------------
    # BRAND NAME INSIDE DOMAIN
    # --------------------------------------------------------

    brand_impersonation = False

    for trusted_domain, brand in TRUSTED_DOMAINS.items():

        brand_name = trusted_domain.split(".")[0]

        if brand_name in base_domain:

            if base_domain != trusted_domain:
                brand_impersonation = True
                best_domain = trusted_domain
                best_brand = brand

                break

    # --------------------------------------------------------
    # VERY HIGH SIMILARITY
    # --------------------------------------------------------

    if best_similarity >= 85:

        return {
            "matched": True,
            "legitimate": False,
            "risk_score": 75,
            "similarity": round(
                best_similarity,
                2
            ),
            "matched_domain": best_domain,
            "brand": best_brand,
            "reason": (
                f"Possible typosquatting: domain is very "
                f"similar to legitimate {best_brand} domain "
                f"'{best_domain}'"
            )
        }

    # --------------------------------------------------------
    # BRAND IMPERSONATION
    # --------------------------------------------------------

    if brand_impersonation:

        return {
            "matched": True,
            "legitimate": False,
            "risk_score": 70,
            "similarity": round(
                best_similarity,
                2
            ),
            "matched_domain": best_domain,
            "brand": best_brand,
            "reason": (
                f"Possible brand impersonation involving "
                f"{best_brand}"
            )
        }

    # --------------------------------------------------------
    # MODERATE SIMILARITY
    # --------------------------------------------------------

    if best_similarity >= 70:

        return {
            "matched": True,
            "legitimate": False,
            "risk_score": 45,
            "similarity": round(
                best_similarity,
                2
            ),
            "matched_domain": best_domain,
            "brand": best_brand,
            "reason": (
                f"Domain resembles legitimate "
                f"{best_brand} domain "
                f"'{best_domain}'"
            )
        }

    # --------------------------------------------------------
    # NO LOOKALIKE
    # --------------------------------------------------------

    return {
        "matched": False,
        "legitimate": False,
        "risk_score": 0,
        "similarity": round(
            best_similarity,
            2
        ),
        "matched_domain": best_domain,
        "brand": best_brand,
        "reason": None
    }


# ============================================================
# DNS CHECK
# ============================================================

def check_dns(hostname):
    """
    Check whether the hostname resolves through DNS.
    """

    if not hostname:
        return False

    try:

        socket.gethostbyname(hostname)

        return True

    except Exception:

        return False


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url(url):

    score = 0

    reasons = []

    features = {}

    # ========================================================
    # BASIC VALIDATION
    # ========================================================

    if not is_valid_url(url):

        return {
            "prediction": "Phishing",
            "risk_score": 100,
            "threat_level": "HIGH",
            "reasons": [
                "Invalid or malformed URL"
            ],
            "features": {}
        }

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    path = parsed.path or ""

    query = parsed.query or ""

    lower_url = url.lower()

    decoded_url = unquote(url)

    # ========================================================
    # HOSTNAME
    # ========================================================

    features["hostname"] = hostname

    features["base_domain"] = get_base_domain(
        hostname
    )

    # ========================================================
    # 1. URL LENGTH
    # ========================================================

    url_length = len(url)

    features["url_length"] = url_length

    if url_length > 100:

        score += 15

        reasons.append(
            "URL is extremely long"
        )

    elif url_length > 50:

        score += 10

        reasons.append(
            "URL is unusually long"
        )

    # ========================================================
    # 2. HTTPS
    # ========================================================

    uses_https = (
        parsed.scheme.lower() == "https"
    )

    features["https"] = uses_https

    if not uses_https:

        score += 15

        reasons.append(
            "URL is not using HTTPS"
        )

    # ========================================================
    # 3. IP ADDRESS
    # ========================================================

    uses_ip = is_ip_address(
        hostname
    )

    features["uses_ip"] = uses_ip

    if uses_ip:

        score += 30

        reasons.append(
            "Uses IP address instead of domain"
        )

    # ========================================================
    # 4. @ SYMBOL
    # ========================================================

    contains_at = "@" in url

    features["contains_at_symbol"] = (
        contains_at
    )

    if contains_at:

        score += 25

        reasons.append(
            "Contains '@' symbol which may hide "
            "the real destination"
        )

    # ========================================================
    # 5. HYPHENS
    # ========================================================

    hyphen_count = hostname.count("-")

    features["hyphen_count"] = (
        hyphen_count
    )

    if hyphen_count >= 3:

        score += 15

        reasons.append(
            "Domain contains too many hyphens"
        )

    elif hyphen_count == 2:

        score += 5

    # ========================================================
    # 6. DOTS / SUBDOMAINS
    # ========================================================

    dot_count = hostname.count(".")

    subdomain_count = max(
        0,
        dot_count - 1
    )

    features["dot_count"] = dot_count

    features["subdomain_count"] = (
        subdomain_count
    )

    if subdomain_count >= 3:

        score += 20

        reasons.append(
            "Contains an unusually high number "
            "of subdomains"
        )

    elif subdomain_count == 2:

        score += 5

    # ========================================================
    # 7. DIGITS
    # ========================================================

    digit_count = sum(
        char.isdigit()
        for char in hostname
    )

    features["digit_count"] = digit_count

    if digit_count >= 5:

        score += 15

        reasons.append(
            "Domain contains many numeric characters"
        )

    elif digit_count >= 3:

        score += 5

    # ========================================================
    # 8. SPECIAL CHARACTERS
    # ========================================================

    special_characters = re.findall(
        r"[^a-zA-Z0-9./:_\-?=&%]",
        url
    )

    special_count = len(
        special_characters
    )

    features["special_character_count"] = (
        special_count
    )

    if special_count >= 3:

        score += 10

        reasons.append(
            "URL contains unusual special characters"
        )

    # ========================================================
    # 9. URL ENCODING
    # ========================================================

    encoded_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )

    features["encoded_character_count"] = (
        encoded_count
    )

    if encoded_count >= 3:

        score += 15

        reasons.append(
            "URL contains encoded characters "
            "that may indicate obfuscation"
        )

    # ========================================================
    # 10. DOUBLE SLASH
    # ========================================================

    after_scheme = re.sub(
        r"^https?://",
        "",
        url,
        flags=re.IGNORECASE
    )

    double_slash = "//" in after_scheme

    features["double_slash"] = (
        double_slash
    )

    if double_slash:

        score += 15

        reasons.append(
            "Contains suspicious double slash"
        )

    # ========================================================
    # 11. SUSPICIOUS KEYWORDS
    # ========================================================

    suspicious_words = [

        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "secure",
        "security",
        "update",
        "account",
        "bank",
        "banking",
        "password",
        "credential",
        "credentials",
        "confirm",
        "wallet",
        "payment",
        "recover",
        "recovery",
        "suspended",
        "unlock",
        "authenticate",
        "authentication",
        "otp",
        "billing",
        "invoice",
        "refund",
        "reset"
    ]

    found_keywords = []

    for word in suspicious_words:

        if word in lower_url:

            found_keywords.append(
                word
            )

    features["suspicious_keywords"] = (
        found_keywords
    )

    keyword_score = min(
        len(found_keywords) * 5,
        25
    )

    score += keyword_score

    for word in found_keywords[:5]:

        reasons.append(
            f"Contains suspicious keyword '{word}'"
        )

    # ========================================================
    # 12. PUNYCODE
    # ========================================================

    contains_punycode = (
        "xn--" in hostname.lower()
    )

    features["punycode"] = (
        contains_punycode
    )

    if contains_punycode:

        score += 25

        reasons.append(
            "Domain uses Punycode which can be used "
            "in look-alike domains"
        )

    # ========================================================
    # 13. SUSPICIOUS TLD
    # ========================================================

    suspicious_tlds = {

        ".xyz",
        ".top",
        ".click",
        ".work",
        ".zip",
        ".review",
        ".country",
        ".gq",
        ".tk",
        ".ml",
        ".cf"
    }

    domain_tld = ""

    if "." in hostname:

        domain_tld = (
            "."
            + hostname.split(".")[-1].lower()
        )

    features["tld"] = domain_tld

    if domain_tld in suspicious_tlds:

        score += 15

        reasons.append(
            f"Uses potentially high-risk TLD "
            f"'{domain_tld}'"
        )

    # ========================================================
    # 14. VERY LONG DOMAIN
    # ========================================================

    domain_length = len(hostname)

    features["domain_length"] = (
        domain_length
    )

    if domain_length > 40:

        score += 15

        reasons.append(
            "Domain name is unusually long"
        )

    # ========================================================
    # 15. PATH ANALYSIS
    # ========================================================

    path_length = len(path)

    features["path_length"] = (
        path_length
    )

    if path_length > 80:

        score += 10

        reasons.append(
            "URL path is unusually long"
        )

    # ========================================================
    # 16. QUERY ANALYSIS
    # ========================================================

    query_length = len(query)

    features["query_length"] = (
        query_length
    )

    if query_length > 100:

        score += 10

        reasons.append(
            "URL query contains excessive data"
        )

    # ========================================================
    # 17. DECODED URL ANALYSIS
    # ========================================================

    decoded_changed = (
        decoded_url != url
    )

    features["decoded_url_changed"] = (
        decoded_changed
    )

    if decoded_changed:

        # Check decoded URL for phishing terms.
        decoded_lower = decoded_url.lower()

        decoded_keywords = []

        for word in suspicious_words:

            if word in decoded_lower:

                decoded_keywords.append(
                    word
                )

        features["decoded_suspicious_keywords"] = (
            decoded_keywords
        )

        if decoded_keywords:

            score += 15

            reasons.append(
                "Encoded URL contains suspicious "
                "phishing-related content"
            )

    # ========================================================
    # 18. DNS CHECK
    # ========================================================

    dns_exists = check_dns(
        hostname
    )

    features["dns_exists"] = (
        dns_exists
    )

    if not dns_exists:

        score += 20

        reasons.append(
            "Domain does not resolve through DNS"
        )

    # ========================================================
    # 19. LOOKALIKE DETECTION
    # ========================================================

    lookalike_result = (
        analyze_lookalike_domain(
            hostname
        )
    )

    features["lookalike"] = (
        lookalike_result
    )

    lookalike_score = float(
        lookalike_result.get(
            "risk_score",
            0
        )
    )

    similarity = float(
        lookalike_result.get(
            "similarity",
            0
        )
    )

    matched_domain = (
        lookalike_result.get(
            "matched_domain"
        )
    )

    brand = (
        lookalike_result.get(
            "brand"
        )
    )

    if lookalike_result.get(
        "legitimate"
    ):

        features["brand_verified"] = True

    elif lookalike_score > 0:

        score += lookalike_score

        lookalike_reason = (
            lookalike_result.get(
                "reason"
            )
        )

        if lookalike_reason:

            reasons.append(
                lookalike_reason
            )

        if brand:

            reasons.append(
                f"Domain similarity with "
                f"{brand}: {similarity:.2f}%"
            )

    else:

        features["brand_verified"] = False

    # ========================================================
    # 20. STRONG PHISHING INDICATORS
    # ========================================================

    strong_indicators = 0

    if uses_ip:
        strong_indicators += 1

    if contains_at:
        strong_indicators += 1

    if contains_punycode:
        strong_indicators += 1

    if lookalike_score >= 70:
        strong_indicators += 1

    if len(found_keywords) >= 2:
        strong_indicators += 1

    if (
        not uses_https
        and len(found_keywords) >= 1
    ):
        strong_indicators += 1

    features["strong_phishing_indicators"] = (
        strong_indicators
    )

    if strong_indicators >= 2:

        score += 20

        reasons.append(
            "Multiple strong phishing indicators "
            "were detected"
        )

    # ========================================================
    # FINAL SCORE
    # ========================================================

    score = min(
        round(score, 2),
        100
    )

    # ========================================================
    # FINAL CLASSIFICATION
    # ========================================================

    if score >= 70:

        threat_level = "HIGH"

        prediction = "Phishing"

    elif score >= 40:

        threat_level = "MEDIUM"

        prediction = "Suspicious"

    else:

        threat_level = "LOW"

        prediction = "Safe"

    # ========================================================
    # IMPORTANT SAFETY OVERRIDE
    # ========================================================

    # Never classify a URL as Safe when there are
    # strong phishing indicators.

    if strong_indicators >= 2:

        prediction = "Phishing"

        threat_level = "HIGH"

        score = max(
            score,
            70
        )

    # Lookalike domains with very high similarity
    # should never be Safe.

    if lookalike_score >= 70:

        prediction = "Phishing"

        threat_level = "HIGH"

        score = max(
            score,
            70
        )

    # IP + suspicious keyword combination.

    if (
        uses_ip
        and len(found_keywords) >= 1
    ):

        prediction = "Phishing"

        threat_level = "HIGH"

        score = max(
            score,
            70
        )

    # @ symbol is a strong URL deception indicator.

    if contains_at:

        prediction = "Phishing"

        threat_level = "HIGH"

        score = max(
            score,
            70
        )

    # Punycode should not be considered safe automatically.

    if contains_punycode:

        prediction = "Suspicious"

        threat_level = "MEDIUM"

        score = max(
            score,
            50
        )

    return {

        "prediction": prediction,

        "risk_score": round(
            score,
            2
        ),

        "threat_level": threat_level,

        "reasons": reasons,

        "features": features
    }

