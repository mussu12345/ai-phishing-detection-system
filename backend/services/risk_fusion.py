# ============================================================
# HYBRID RISK FUSION ENGINE
# ============================================================

def calculate_hybrid_risk(
    url_result,
    domain_result,
    cti_result,
    ml_result=None
):

    url_score = url_result.get("risk_score", 0)
    domain_score = domain_result.get("risk_score", 0)
    cti_score = cti_result.get("risk_score", 0)

    ml_score = 0

    if ml_result:
        ml_score = ml_result.get("risk_score", 0)

    # --------------------------------------------------------
    # WEIGHTED RISK CALCULATION
    # --------------------------------------------------------

    if ml_result:

        final_score = (
            url_score * 0.25 +
            domain_score * 0.20 +
            cti_score * 0.35 +
            ml_score * 0.20
        )

    else:

        final_score = (
            url_score * 0.40 +
            domain_score * 0.25 +
            cti_score * 0.35
        )

    final_score = round(
        min(max(final_score, 0), 100),
        2
    )

    # --------------------------------------------------------
    # CTI OVERRIDE
    # --------------------------------------------------------

    if (
        cti_result.get("matched") is True
        and cti_result.get("confidence", 0) >= 90
    ):

        final_score = max(
            final_score,
            cti_result.get("confidence", 0)
        )

    # --------------------------------------------------------
    # THREAT LEVEL
    # --------------------------------------------------------

    if final_score >= 70:

        threat_level = "HIGH"
        prediction = "Phishing"

    elif final_score >= 40:

        threat_level = "MEDIUM"
        prediction = "Suspicious"

    else:

        threat_level = "LOW"
        prediction = "Safe"

    # --------------------------------------------------------
    # REASONS
    # --------------------------------------------------------

    reasons = []

    reasons.extend(
        url_result.get("reasons", [])
    )

    reasons.extend(
        domain_result.get("reasons", [])
    )

    reasons.extend(
        cti_result.get("reasons", [])
    )

    if ml_result:

        reasons.extend(
            ml_result.get("reasons", [])
        )

    reasons = list(dict.fromkeys(reasons))

    # --------------------------------------------------------
    # RETURN RESULT
    # --------------------------------------------------------

    return {
        "prediction": prediction,
        "threat_level": threat_level,
        "risk_score": final_score,

        "components": {
            "url_score": url_score,
            "domain_score": domain_score,
            "cti_score": cti_score,
            "ml_score": ml_score
        },

        "cti": cti_result,

        "reasons": reasons
    }