# app.py

from flask import Flask, request, jsonify, Response, send_file
from flask_cors import CORS
from flask import Flask, send_from_directory
from flask_socketio import SocketIO

import socket
from urllib.parse import urlparse

import sqlite3
import csv
import io
import os

from datetime import datetime

import database


from services.url_features import (
    analyze_url,
    is_valid_url
)

from services.email_model import (
    predict_email
)

from services.domain_analysis import (
    analyze_domain
)

from services.cti_engine import (
    analyze_cti
)

from services.risk_fusion import (
    calculate_hybrid_risk
)

from report_generator import (
    generate_report
)
# app.py

from flask import Flask, request, jsonify, Response, send_file
from flask_cors import CORS
from flask_socketio import SocketIO

import socket
from urllib.parse import urlparse

import sqlite3
import csv
import io
import os

from datetime import datetime

import database


from services.url_features import (
    analyze_url,
    is_valid_url
)

from services.email_model import (
    predict_email
)

from services.domain_analysis import (
    analyze_domain
)

from services.cti_engine import (
    analyze_cti
)

from services.risk_fusion import (
    calculate_hybrid_risk
)

from report_generator import (
    generate_report
)
from flask import Flask, jsonify

from email_processor import process_email_dataset

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.route("/saved_models/evaluation/<path:filename>")
def evaluation_file(filename):
    evaluation_folder = os.path.join(
        BASE_DIR,
        "saved_models",
        "evaluation"
    )

    return send_from_directory(
        evaluation_folder,
        filename
    )


@app.route("/automatic-email-scan", methods=["GET"])
def automatic_email_scan():

    try:

        results = process_email_dataset()

        total = len(results)

        safe = sum(
            1 for email in results
            if email["prediction"] == "Safe"
        )

        suspicious = sum(
            1 for email in results
            if email["prediction"] == "Suspicious"
        )

        phishing = sum(
            1 for email in results
            if email["prediction"] == "Phishing"
        )

        return jsonify({
            "success": True,

            "statistics": {
                "total_emails": total,
                "safe": safe,
                "suspicious": suspicious,
                "phishing": phishing
            },

            "emails": results
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ============================================================
# BASE DIRECTORY
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATABASE_PATH = os.path.join(
    BASE_DIR,
    "phishing.db"
)


print(
    "============================================"
)

print(
    "AI PHISHING DETECTION SYSTEM"
)

print(
    "DATABASE PATH:"
)

print(
    DATABASE_PATH
)

print(
    "============================================"
)
#==============================================
# ============================================================
# MODEL EVALUATION DATA
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EVALUATION_DIR = os.path.join(
    BASE_DIR,
    "saved_models",
    "evaluation"
)


@app.route("/api/model-evaluation", methods=["GET"])
def model_evaluation():

    try:

        results_path = os.path.join(
            EVALUATION_DIR,
            "evaluation_results.json"
        )

        with open(
            results_path,
            "r",
            encoding="utf-8"
        ) as file:

            results = json.load(file)

        return jsonify(results)

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# MODEL EVALUATION IMAGES
# ============================================================

@app.route(
    "/api/evaluation-image/<path:filename>",
    methods=["GET"]
)
def evaluation_image(filename):

    return send_from_directory(
        EVALUATION_DIR,
        filename
    )

# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/*": {
            "origins": "*"
        }
    }
)


# ============================================================
# SOCKET.IO
# ============================================================

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)


# ============================================================
# DATABASE
# ============================================================

def get_db_connection():

    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=30
    )

    conn.row_factory = sqlite3.Row

    return conn


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def ensure_database():

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            scan_type TEXT NOT NULL,

            content TEXT NOT NULL,

            prediction TEXT NOT NULL,

            threat_level TEXT NOT NULL,

            risk_score REAL DEFAULT 0,

            scan_time TEXT NOT NULL

        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS trusted_domains (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            domain TEXT UNIQUE,

            organization TEXT,

            verification_source TEXT,

            verified_at TEXT,

            status TEXT DEFAULT 'VERIFIED'

        )
        """
    )

    trusted_domains = [

        (
            "google.com",
            "Google",
            "Manual Verification"
        ),

        (
            "microsoft.com",
            "Microsoft",
            "Manual Verification"
        ),

        (
            "github.com",
            "GitHub",
            "Manual Verification"
        ),

        (
            "wikipedia.org",
            "Wikipedia",
            "Manual Verification"
        )

    ]

    for (
        domain,
        organization,
        source
    ) in trusted_domains:

        cursor.execute(
            """
            INSERT OR IGNORE INTO trusted_domains
            (
                domain,
                organization,
                verification_source,
                verified_at,
                status
            )
            VALUES (?, ?, ?, ?, 'VERIFIED')
            """,
            (
                domain,
                organization,
                source,
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

    conn.commit()

    conn.close()


ensure_database()


# ============================================================
# NORMALIZE PREDICTION
# ============================================================

def normalize_prediction(
    prediction
):

    if prediction is None:

        return "Suspicious"

    value = str(
        prediction
    ).strip().lower()

    if value == "phishing":

        return "Phishing"

    if value == "safe":

        return "Safe"

    if value == "suspicious":

        return "Suspicious"

    return str(
        prediction
    ).strip()


# ============================================================
# DATABASE STATISTICS
# ============================================================

def get_database_statistics():

    conn = get_db_connection()

    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            """
        )

        threats_analyzed = (
            cursor.fetchone()[0]
            or 0
        )

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE LOWER(
                TRIM(prediction)
            ) = 'phishing'
            """
        )

        phishing_detected = (
            cursor.fetchone()[0]
            or 0
        )

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE LOWER(
                TRIM(prediction)
            ) = 'safe'
            """
        )

        safe_scans = (
            cursor.fetchone()[0]
            or 0
        )

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE LOWER(
                TRIM(prediction)
            ) = 'suspicious'
            """
        )

        suspicious_scans = (
            cursor.fetchone()[0]
            or 0
        )

        detection_rate = 0

        if threats_analyzed > 0:

            detection_rate = (
                phishing_detected
                / threats_analyzed
            ) * 100

        return {

            "threats_analyzed":
                threats_analyzed,

            "phishing_detected":
                phishing_detected,

            "safe_scans":
                safe_scans,

            "suspicious_scans":
                suspicious_scans,

            "detection_rate":
                round(
                    detection_rate,
                    1
                )
        }

    finally:

        conn.close()


# ============================================================
# SOCKET STATISTICS
# ============================================================

def broadcast_statistics():

    try:

        statistics = (
            get_database_statistics()
        )

        socketio.emit(
            "stats_update",
            statistics
        )

    except Exception as e:

        print(
            "STATISTICS BROADCAST ERROR:",
            e
        )


# ============================================================
# IP / DNS INFORMATION
# ============================================================

def get_ip_information(url):

    try:

        hostname = (
            urlparse(url).hostname
        )

        if not hostname:

            return {
                "dns_exists": False,
                "hostname": None,
                "ip_addresses": []
            }

        ip_addresses = list({

            item[4][0]

            for item in socket.getaddrinfo(
                hostname,
                None
            )

        })

        return {

            "dns_exists": True,

            "hostname": hostname,

            "ip_addresses":
                ip_addresses

        }

    except Exception as e:

        print(
            "IP / DNS LOOKUP ERROR:",
            e
        )

        return {

            "dns_exists": False,

            "hostname": None,

            "ip_addresses": [],

            "error": str(e)

        }


# ============================================================
# TRUSTED DOMAIN
# ============================================================

def check_trusted_domain(url):

    try:

        hostname = (
            urlparse(url).hostname
        )

        if not hostname:

            return {

                "trusted": False,

                "domain": None

            }

        hostname = hostname.lower()

        if hostname.startswith("www."):

            hostname = hostname[4:]

        conn = get_db_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                domain,
                organization,
                verification_source,
                status
            FROM trusted_domains
            WHERE domain = ?
            AND status = 'VERIFIED'
            LIMIT 1
            """,
            (
                hostname,
            )
        )

        row = cursor.fetchone()

        conn.close()

        if row:

            return {

                "trusted": True,

                "domain":
                    row["domain"],

                "organization":
                    row["organization"],

                "verification_source":
                    row["verification_source"]

            }

        return {

            "trusted": False,

            "domain": hostname

        }

    except Exception as e:

        print(
            "TRUSTED DOMAIN ERROR:",
            e
        )

        return {

            "trusted": False,

            "domain": None

        }


# ============================================================
# URL PREVENTION
# ============================================================

def get_url_prevention(
    threat_level
):

    threat_level = str(
        threat_level
    ).upper()

    if threat_level == "HIGH":

        return [

            "Block URL immediately",

            "Do not enter credentials",

            "Do not download files",

            "Do not provide OTP or password",

            "Report the URL to the security team"

        ]

    elif threat_level == "MEDIUM":

        return [

            "Verify website authenticity",

            "Avoid entering sensitive information",

            "Do not download files",

            "Check the domain reputation"

        ]

    return [

        "No major threats detected",

        "Continue normal security precautions"

    ]


# ============================================================
# EMAIL PREVENTION
# ============================================================

def get_email_prevention(
    prediction
):

    if (
        normalize_prediction(
            prediction
        )
        == "Phishing"
    ):

        return [

            "Do not click suspicious links",

            "Verify sender identity",

            "Never share passwords or OTPs",

            "Report suspicious email"

        ]

    return [

        "No major phishing indicators detected",

        "Still verify unexpected messages before acting"

    ]


# ============================================================
# URL ACTION
# ============================================================

def get_url_action(
    threat_level,
    risk_score,
    trusted_result=None,
    cti_result=None
):

    threat_level = str(
        threat_level or ""
    ).upper()

    risk_score = float(
        risk_score or 0
    )

    trusted = bool(
        trusted_result
        and trusted_result.get(
            "trusted",
            False
        )
    )

    cti_matched = bool(
        cti_result
        and cti_result.get(
            "matched",
            False
        )
    )

    # --------------------------------------------------------
    # NEVER ALLOW STRONG CTI EVIDENCE
    # --------------------------------------------------------

    if (
        cti_matched
        and risk_score >= 60
    ):

        return {

            "action": "BLOCK",

            "message":
                "URL blocked because threat intelligence "
                "and risk analysis indicate malicious activity.",

            "severity": "HIGH"

        }

    # --------------------------------------------------------
    # VERY HIGH RISK
    # --------------------------------------------------------

    if (
        risk_score >= 80
        and not trusted
    ):

        return {

            "action": "BLOCK",

            "message":
                "URL blocked because the calculated "
                "risk is very high.",

            "severity": "HIGH"

        }

    # --------------------------------------------------------
    # HIGH
    # --------------------------------------------------------

    if threat_level == "HIGH":

        return {

            "action": "BLOCK",

            "message":
                "URL blocked because multiple phishing "
                "indicators were detected.",

            "severity": "HIGH"

        }

    # --------------------------------------------------------
    # MEDIUM
    # --------------------------------------------------------

    if (
        risk_score >= 31
        or threat_level == "MEDIUM"
    ):

        return {

            "action": "WARN",

            "message":
                "This URL is suspicious. Verify the "
                "website before continuing.",

            "severity": "MEDIUM"

        }

    # --------------------------------------------------------
    # SAFE
    # --------------------------------------------------------

    return {

        "action": "ALLOW",

        "message":
            "This URL appears to be safe.",

        "severity": "LOW"

    }


# ============================================================
# STRONG URL EVIDENCE CHECK
#
# THIS IS THE IMPORTANT FIX
# ============================================================

def enforce_url_evidence(
    result,
    url_result,
    trusted_result,
    cti_result
):

    if not isinstance(
        result,
        dict
    ):

        result = {}

    if not isinstance(
        url_result,
        dict
    ):

        return result

    url_score = float(
        url_result.get(
            "risk_score",
            0
        )
        or 0
    )

    url_prediction = normalize_prediction(
        url_result.get(
            "prediction"
        )
    )

    url_threat = str(
        url_result.get(
            "threat_level",
            ""
        )
    ).upper()

    features = url_result.get(
        "features",
        {}
    )

    if not isinstance(
        features,
        dict
    ):

        features = {}

    keywords = features.get(
        "suspicious_keywords",
        []
    )

    if not isinstance(
        keywords,
        list
    ):

        keywords = []

    uses_ip = bool(
        features.get(
            "uses_ip",
            False
        )
    )

    contains_at = bool(
        features.get(
            "contains_at_symbol",
            False
        )
    )

    punycode = bool(
        features.get(
            "punycode",
            False
        )
    )

    suspicious_tld = bool(
        features.get(
            "suspicious_tld",
            False
        )
    )

    lookalike = features.get(
        "lookalike",
        {}
    )

    if not isinstance(
        lookalike,
        dict
    ):

        lookalike = {}

    lookalike_score = float(
        lookalike.get(
            "risk_score",
            0
        )
        or 0
    )

    strong_signals = 0

    if uses_ip:

        strong_signals += 1

    if contains_at:

        strong_signals += 1

    if punycode:

        strong_signals += 1

    if suspicious_tld:

        strong_signals += 1

    if lookalike_score >= 45:

        strong_signals += 1

    if len(keywords) >= 2:

        strong_signals += 1

    # --------------------------------------------------------
    # TRUSTED DOMAIN EXCEPTION
    # --------------------------------------------------------

    trusted = bool(
        trusted_result
        and trusted_result.get(
            "trusted",
            False
        )
    )

    # --------------------------------------------------------
    # CTI
    # --------------------------------------------------------

    cti_matched = bool(
        cti_result
        and cti_result.get(
            "matched",
            False
        )
    )

    # --------------------------------------------------------
    # DO NOT DOWNGRADE STRONG EVIDENCE
    # --------------------------------------------------------

    if not trusted:

        # URL detector already says phishing
        if url_prediction == "Phishing":

            result["prediction"] = "Phishing"

            result["threat_level"] = "HIGH"

            result["risk_score"] = max(
                float(
                    result.get(
                        "risk_score",
                        0
                    )
                    or 0
                ),
                url_score,
                70
            )

        # High URL score
        elif url_score >= 70:

            result["prediction"] = "Phishing"

            result["threat_level"] = "HIGH"

            result["risk_score"] = max(
                float(
                    result.get(
                        "risk_score",
                        0
                    )
                    or 0
                ),
                url_score,
                70
            )

        # Multiple strong signals
        elif strong_signals >= 3:

            result["prediction"] = "Phishing"

            result["threat_level"] = "HIGH"

            result["risk_score"] = max(
                float(
                    result.get(
                        "risk_score",
                        0
                    )
                    or 0
                ),
                url_score,
                70
            )

        # CTI match
        elif cti_matched:

            result["prediction"] = "Phishing"

            result["threat_level"] = "HIGH"

            result["risk_score"] = max(
                float(
                    result.get(
                        "risk_score",
                        0
                    )
                    or 0
                ),
                70
            )

        # URL says suspicious
        elif (
            url_prediction == "Suspicious"
            and url_score >= 40
        ):

            current_score = float(
                result.get(
                    "risk_score",
                    0
                )
                or 0
            )

            result["risk_score"] = max(
                current_score,
                url_score
            )

            if result[
                "risk_score"
            ] >= 70:

                result[
                    "prediction"
                ] = "Phishing"

                result[
                    "threat_level"
                ] = "HIGH"

            else:

                result[
                    "prediction"
                ] = "Suspicious"

                result[
                    "threat_level"
                ] = "MEDIUM"

    return result


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return jsonify({

        "message":
            "AI Phishing Detection API Running",

        "status":
            "online",

        "database":
            DATABASE_PATH

    })


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():

    try:

        statistics = (
            get_database_statistics()
        )

        return jsonify({

            "status":
                "healthy",

            "service":
                "AI-ML Phishing Detection System",

            "database":
                "connected",

            "total_scans":
                statistics[
                    "threats_analyzed"
                ]

        })

    except Exception as e:

        return jsonify({

            "status":
                "unhealthy",

            "error":
                str(e)

        }), 500


# ============================================================
# ANALYZE URL
# ============================================================

@app.route(
    "/analyze-url",
    methods=["POST"]
)
def analyze_url_route():

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({

            "error":
                "Invalid JSON request"

        }), 400

    url = str(
        data.get(
            "url",
            ""
        )
    ).strip()

    if not url:

        return jsonify({

            "error":
                "Please enter a URL"

        }), 400

    # ========================================================
    # VALIDATION
    # ========================================================

    if not is_valid_url(url):

        return jsonify({

            "error":
                "Invalid URL format. "
                "Example: https://google.com"

        }), 400

    # ========================================================
    # DUPLICATE
    # ========================================================

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM scans
        WHERE scan_type = ?
        AND content = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            "URL",
            url
        )
    )

    existing = cursor.fetchone()

    conn.close()

    is_duplicate = (
        existing is not None
    )

    # ========================================================
    # URL FEATURE ANALYSIS
    # ========================================================

    try:

        url_result = analyze_url(
            url
        )

    except Exception as e:

        print(
            "URL ANALYSIS ERROR:",
            e
        )

        return jsonify({

            "error":
                "URL feature analysis failed",

            "details":
                str(e)

        }), 500

    # ========================================================
    # DOMAIN ANALYSIS
    # ========================================================

    try:

        domain_result = analyze_domain(
            url
        )

    except Exception as e:

        print(
            "DOMAIN ANALYSIS ERROR:",
            e
        )

        domain_result = {

            "risk_score": 0,

            "reasons": [

                "Domain analysis unavailable"

            ]

        }

    # ========================================================
    # CTI ANALYSIS
    # ========================================================

    try:

        cti_result = analyze_cti(
            url
        )

    except Exception as e:

        print(
            "CTI ANALYSIS ERROR:",
            e
        )

        cti_result = {

            "matched": False,

            "risk_score": 0,

            "reasons": []

        }

    # ========================================================
    # HYBRID RISK
    # ========================================================

    try:

        result = calculate_hybrid_risk(

            url_result=url_result,

            domain_result=domain_result,

            cti_result=cti_result

        )

    except Exception as e:

        print(
            "RISK FUSION ERROR:",
            e
        )

        # IMPORTANT:
        # Even if fusion fails, use URL analysis.

        result = {

            "prediction":
                url_result.get(
                    "prediction",
                    "Suspicious"
                ),

            "risk_score":
                url_result.get(
                    "risk_score",
                    0
                ),

            "threat_level":
                url_result.get(
                    "threat_level",
                    "MEDIUM"
                ),

            "reasons":
                url_result.get(
                    "reasons",
                    []
                ),

            "components": {}

        }

    if not isinstance(
        result,
        dict
    ):

        result = {}

    # ========================================================
    # IP INFORMATION
    # ========================================================

    result[
        "ip_information"
    ] = get_ip_information(
        url
    )

    # ========================================================
    # DEFAULT VALUES
    # ========================================================

    result.setdefault(
        "prediction",
        "Suspicious"
    )

    result.setdefault(
        "risk_score",
        0
    )

    result.setdefault(
        "threat_level",
        "MEDIUM"
    )

    result.setdefault(
        "reasons",
        []
    )

    result[
        "prediction"
    ] = normalize_prediction(
        result[
            "prediction"
        ]
    )

    # ========================================================
    # TRUSTED DOMAIN
    # ========================================================

    trusted_result = (
        check_trusted_domain(
            url
        )
    )

    result[
        "trusted_domain"
    ] = trusted_result

    # ========================================================
    # IMPORTANT:
    # ENFORCE URL EVIDENCE AFTER FUSION
    # ========================================================

    result = enforce_url_evidence(

        result,

        url_result,

        trusted_result,

        cti_result

    )

    # Normalize once again
    result[
        "prediction"
    ] = normalize_prediction(
        result[
            "prediction"
        ]
    )

    result[
        "risk_score"
    ] = min(
        max(
            float(
                result.get(
                    "risk_score",
                    0
                )
                or 0
            ),
            0
        ),
        100
    )

    # ========================================================
    # THREAT LEVEL CONSISTENCY
    # ========================================================

    if result[
        "risk_score"
    ] >= 70:

        result[
            "threat_level"
        ] = "HIGH"

        result[
            "prediction"
        ] = "Phishing"

    elif result[
        "risk_score"
    ] >= 40:

        result[
            "threat_level"
        ] = "MEDIUM"

        if result[
            "prediction"
        ] == "Safe":

            result[
                "prediction"
            ] = "Suspicious"

    else:

        result[
            "threat_level"
        ] = "LOW"

        if result[
            "prediction"
        ] not in (
            "Phishing",
            "Suspicious"
        ):

            result[
                "prediction"
            ] = "Safe"

    # ========================================================
    # COMPONENTS
    # ========================================================

    if not isinstance(
        result.get(
            "components"
        ),
        dict
    ):

        result[
            "components"
        ] = {}

    result[
        "components"
    ].setdefault(
        "ml_score",
        0
    )

    result[
        "components"
    ].setdefault(
        "url_score",
        url_result.get(
            "risk_score",
            0
        )
    )

    result[
        "components"
    ].setdefault(
        "domain_score",
        domain_result.get(
            "risk_score",
            0
        )
        if isinstance(
            domain_result,
            dict
        )
        else 0
    )

    result[
        "components"
    ].setdefault(
        "cti_score",
        cti_result.get(
            "risk_score",
            0
        )
        if isinstance(
            cti_result,
            dict
        )
        else 0
    )

    # ========================================================
    # PREVENTION
    # ========================================================

    result[
        "prevention"
    ] = get_url_prevention(
        result[
            "threat_level"
        ]
    )

    # ========================================================
    # ACTION
    # ========================================================

    result[
        "prevention_action"
    ] = get_url_action(

        result[
            "threat_level"
        ],

        result[
            "risk_score"
        ],

        trusted_result,

        cti_result

    )

    # ========================================================
    # FEATURES
    # ========================================================

    result[
        "features"
    ] = url_result.get(
        "features",
        {}
    )

    # ========================================================
    # CTI
    # ========================================================

    result[
        "cti"
    ] = cti_result

    # ========================================================
    # REASONS
    # ========================================================

    combined_reasons = []

    for source in (
        url_result,
        domain_result,
        cti_result,
        result
    ):

        if isinstance(
            source,
            dict
        ):

            source_reasons = source.get(
                "reasons",
                []
            )

            if isinstance(
                source_reasons,
                list
            ):

                combined_reasons.extend(
                    source_reasons
                )

    result[
        "reasons"
    ] = list(
        dict.fromkeys(
            combined_reasons
        )
    )

    # ========================================================
    # DUPLICATE
    # ========================================================

    result[
        "duplicate"
    ] = is_duplicate

    if is_duplicate:

        result[
            "message"
        ] = (
            "This URL has already been scanned. "
            "Showing the current analysis."
        )

    # ========================================================
    # SAVE SCAN
    # ========================================================

    if not is_duplicate:

        current_time = (
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        conn = get_db_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO scans
            (
                scan_type,
                content,
                prediction,
                threat_level,
                risk_score,
                scan_time
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "URL",

                url,

                result[
                    "prediction"
                ],

                result[
                    "threat_level"
                ],

                float(
                    result[
                        "risk_score"
                    ]
                    or 0
                ),

                current_time

            )
        )

        new_scan_id = (
            cursor.lastrowid
        )

        conn.commit()

        conn.close()

        # Socket event
        socketio.emit(
            "new_scan",
            {

                "id":
                    new_scan_id,

                "type":
                    "URL",

                "scan_type":
                    "URL",

                "prediction":
                    result[
                        "prediction"
                    ],

                "threat_level":
                    result[
                        "threat_level"
                    ],

                "risk_score":
                    result[
                        "risk_score"
                    ],

                "timestamp":
                    current_time

            }
        )

        broadcast_statistics()

    # ========================================================
    # STATISTICS
    # ========================================================

    result[
        "statistics"
    ] = get_database_statistics()

    # ========================================================
    # DEBUG
    # ========================================================

    print(
        "============================================"
    )

    print(
        "URL ANALYSIS RESULT"
    )

    print(
        "URL:",
        url
    )

    print(
        "Prediction:",
        result[
            "prediction"
        ]
    )

    print(
        "Threat Level:",
        result[
            "threat_level"
        ]
    )

    print(
        "Risk Score:",
        result[
            "risk_score"
        ]
    )

    print(
        "URL Feature Score:",
        url_result.get(
            "risk_score",
            0
        )
    )

    print(
        "URL Feature Prediction:",
        url_result.get(
            "prediction"
        )
    )

    print(
        "Trusted:",
        trusted_result.get(
            "trusted",
            False
        )
    )

    print(
        "CTI Matched:",
        cti_result.get(
            "matched",
            False
        )
    )

    print(
        "Prevention Action:",
        result[
            "prevention_action"
        ].get(
            "action"
        )
    )

    print(
        "============================================"
    )

    return jsonify(
        result
    )


# ============================================================
# EMAIL ANALYSIS
# ============================================================

@app.route("/analyze-email", methods=["POST"])
def analyze_email():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "Invalid JSON request"
        }), 400

    email = str(data.get("email", "")).strip()

    if not email:
        return jsonify({
            "error": "Please enter email content"
        }), 400

    try:
        result = predict_email(email)

        if not isinstance(result, dict):
            return jsonify({
                "error": "Invalid ML result"
            }), 500

        result.setdefault("prediction", "Suspicious")
        result.setdefault("threat_level", "MEDIUM")
        result.setdefault("risk_score", 0)
        result.setdefault("reasons", [])
        result.setdefault("prevention", [])
        result.setdefault("model_results", [])

        return jsonify(result)

    except Exception as e:

        print("EMAIL ML ERROR:", e)

        return jsonify({
            "error": "Email ML prediction failed",
            "details": str(e)
        }), 500

    # --------------------------------------------------------
    # DUPLICATE
    # --------------------------------------------------------

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM scans
        WHERE scan_type = ?
        AND content = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            "EMAIL",
            email
        )
    )

    existing = cursor.fetchone()

    conn.close()

    is_duplicate = (
        existing is not None
    )

    # --------------------------------------------------------
    # ML
    # --------------------------------------------------------

    try:

        result = predict_email(
            email
        )

    except Exception as e:

        print(
            "EMAIL ML ERROR:",
            e
        )

        return jsonify({

            "error":
                "Email ML prediction failed",

            "details":
                str(e)

        }), 500

    if not isinstance(
        result,
        dict
    ):

        result = {}

    result.setdefault(
        "prediction",
        "Suspicious"
    )

    result.setdefault(
        "threat_level",
        "MEDIUM"
    )

    result.setdefault(
        "risk_score",
        0
    )

    result.setdefault(
        "reasons",
        []
    )

    result[
        "prediction"
    ] = normalize_prediction(
        result[
            "prediction"
        ]
    )

    result[
        "prevention"
    ] = get_email_prevention(
        result[
            "prediction"
        ]
    )

    result[
        "duplicate"
    ] = is_duplicate

    if is_duplicate:

        result[
            "message"
        ] = (
            "This email has already been scanned. "
            "Showing the current analysis."
        )

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    if not is_duplicate:

        current_time = (
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        conn = get_db_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO scans
            (
                scan_type,
                content,
                prediction,
                threat_level,
                risk_score,
                scan_time
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "EMAIL",

                email,

                result[
                    "prediction"
                ],

                result[
                    "threat_level"
                ],

                float(
                    result[
                        "risk_score"
                    ]
                    or 0
                ),

                current_time

            )
        )

        new_scan_id = (
            cursor.lastrowid
        )

        conn.commit()

        conn.close()

        socketio.emit(
            "new_scan",
            {

                "id":
                    new_scan_id,

                "type":
                    "EMAIL",

                "scan_type":
                    "EMAIL",

                "prediction":
                    result[
                        "prediction"
                    ],

                "threat_level":
                    result[
                        "threat_level"
                    ],

                "risk_score":
                    result[
                        "risk_score"
                    ],

                "timestamp":
                    current_time

            }
        )

        broadcast_statistics()

    result[
        "statistics"
    ] = get_database_statistics()

    return jsonify(
        result
    )


# ============================================================
# HISTORY
# ============================================================

@app.route(
    "/history"
)
def get_history():

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            scan_type,
            content,
            prediction,
            threat_level,
            risk_score,
            scan_time
        FROM scans
        ORDER BY id DESC
        LIMIT 20
        """
    )

    rows = cursor.fetchall()

    conn.close()

    history = []

    for row in rows:

        history.append([

            row["id"],

            row["scan_type"],

            row["content"],

            row["prediction"],

            row["threat_level"],

            row["risk_score"],

            row["scan_time"]

        ])

    return jsonify(
        history
    )


# ============================================================
# STATS
# ============================================================

@app.route(
    "/stats",
    methods=["GET"]
)
def get_stats():

    try:

        return jsonify(
            get_database_statistics()
        )

    except Exception as e:

        return jsonify({

            "threats_analyzed": 0,

            "phishing_detected": 0,

            "safe_scans": 0,

            "suspicious_scans": 0,

            "detection_rate": 0,

            "error":
                str(e)

        }), 500


# ============================================================
# CHART DATA
# ============================================================

@app.route(
    "/chart-data",
    methods=["GET"]
)
def chart_data():

    try:

        statistics = (
            get_database_statistics()
        )

        return jsonify({

            "phishing":
                statistics[
                    "phishing_detected"
                ],

            "safe":
                statistics[
                    "safe_scans"
                ],

            "suspicious":
                statistics[
                    "suspicious_scans"
                ],

            "total":
                statistics[
                    "threats_analyzed"
                ]

        })

    except Exception as e:

        return jsonify({

            "phishing": 0,

            "safe": 0,

            "suspicious": 0,

            "total": 0,

            "error":
                str(e)

        }), 500


# ============================================================
# DELETE SCAN
# ============================================================

@app.route(
    "/delete-scan/<int:scan_id>",
    methods=["DELETE"]
)
def delete_scan(scan_id):

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM scans
        WHERE id = ?
        """,
        (
            scan_id,
        )
    )

    deleted = cursor.rowcount

    conn.commit()

    conn.close()

    if deleted == 0:

        return jsonify({

            "error":
                "Scan not found"

        }), 404

    broadcast_statistics()

    return jsonify({

        "message":
            "Scan deleted successfully",

        "statistics":
            get_database_statistics()

    })


# ============================================================
# CLEAR HISTORY
# ============================================================

@app.route(
    "/clear-history",
    methods=["DELETE"]
)
def clear_history():

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM scans"
    )

    try:

        cursor.execute(
            """
            DELETE FROM sqlite_sequence
            WHERE name = 'scans'
            """
        )

    except sqlite3.OperationalError:

        pass

    conn.commit()

    conn.close()

    broadcast_statistics()

    socketio.emit(
        "history_cleared",
        {
            "message":
                "All scan history cleared"
        }
    )

    return jsonify({

        "message":
            "All scan history cleared",

        "statistics":
            get_database_statistics()

    })


# ============================================================
# EXPORT HISTORY
# ============================================================
@app.route("/export-history", methods=["GET"])
def export_history():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                scan_type,
                content,
                prediction,
                threat_level,
                risk_score,
                scan_time
            FROM scans
            ORDER BY id ASC
        """)

        rows = cursor.fetchall()

        conn.close()

        # Create CSV in memory
        output = io.StringIO()

        writer = csv.writer(output)

        # CSV Header
        writer.writerow([
            "ID",
            "Scan Type",
            "Content",
            "Prediction",
            "Threat Level",
            "Risk Score",
            "Scan Time"
        ])

        # CSV Data
        for row in rows:
            writer.writerow([
                row["id"],
                row["scan_type"],
                row["content"],
                row["prediction"],
                row["threat_level"],
                row["risk_score"],
                row["scan_time"]
            ])

        # Return CSV file
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=scan_history.csv"
            }
        )

    except Exception as e:
        print("Export History Error:", e)

        return jsonify({
            "error": "Unable to export scan history",
            "details": str(e)
        }), 500


# ============================================================
# PDF
# ============================================================

@app.route(
    "/download-pdf",
    methods=["POST"]
)
def download_pdf():

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({

            "error":
                "Invalid report data"

        }), 400

    report_path = os.path.join(
        BASE_DIR,
        "scan_report.pdf"
    )

    try:

        generate_report(
            data,
            report_path
        )

    except Exception as e:

        print(
            "PDF GENERATION ERROR:",
            e
        )

        return jsonify({

            "error":
                "PDF generation failed",

            "details":
                str(e)

        }), 500

    return send_file(

        report_path,

        as_attachment=True,

        download_name=
            "url_scan_report.pdf",

        mimetype=
            "application/pdf"

    )


# ============================================================
# CTI STATISTICS
# ============================================================

@app.route(
    "/cti-stats",
    methods=["GET"]
)
def cti_stats():

    conn = get_db_connection()

    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            SELECT

                COUNT(*) AS total_indicators,

                SUM(
                    CASE
                        WHEN LOWER(severity) = 'high'
                        THEN 1
                        ELSE 0
                    END
                ) AS high_severity,

                SUM(
                    CASE
                        WHEN LOWER(severity) = 'medium'
                        THEN 1
                        ELSE 0
                    END
                ) AS medium_severity,

                SUM(
                    CASE
                        WHEN LOWER(severity) = 'low'
                        THEN 1
                        ELSE 0
                    END
                ) AS low_severity

            FROM threat_indicators
            """
        )

        row = cursor.fetchone()

        return jsonify({

            "total_indicators":
                row["total_indicators"]
                or 0,

            "high_severity":
                row["high_severity"]
                or 0,

            "medium_severity":
                row["medium_severity"]
                or 0,

            "low_severity":
                row["low_severity"]
                or 0

        })

    except sqlite3.OperationalError:

        return jsonify({

            "total_indicators": 0,

            "high_severity": 0,

            "medium_severity": 0,

            "low_severity": 0

        })

    finally:

        conn.close()


# ============================================================
# ROUTES
# ============================================================

print(
    "============================================"
)

print(
    "AVAILABLE ROUTES"
)

print(
    app.url_map
)

print(
    "============================================"
)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    print(
        "Starting server on port 5000..."
    )

    socketio.run(

        app,

        host="0.0.0.0",

        port=5000,

        debug=False,

        allow_unsafe_werkzeug=True

    )
    CORS(
    app,
    resources={
        r"/*": {
            "origins": "*"
        }
    }
)
    
    
def automatic_email_scan():

    try:

        results = process_email_dataset()

        total = len(results)

        safe = sum(
            1 for email in results
            if email["prediction"] == "Safe"
        )

        suspicious = sum(
            1 for email in results
            if email["prediction"] == "Suspicious"
        )

        phishing = sum(
            1 for email in results
            if email["prediction"] == "Phishing"
        )

        return jsonify({
            "success": True,

            "statistics": {
                "total_emails": total,
                "safe": safe,
                "suspicious": suspicious,
                "phishing": phishing
            },

            "emails": results
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ============================================================
# BASE DIRECTORY
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATABASE_PATH = os.path.join(
    BASE_DIR,
    "phishing.db"
)


print(
    "============================================"
)

print(
    "AI PHISHING DETECTION SYSTEM"
)

print(
    "DATABASE PATH:"
)

print(
    DATABASE_PATH
)

print(
    "============================================"
)


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/*": {
            "origins": "*"
        }
    }
)


# ============================================================
# SOCKET.IO
# ============================================================

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)


# ============================================================
# DATABASE
# ============================================================

def get_db_connection():

    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=30
    )

    conn.row_factory = sqlite3.Row

    return conn


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def ensure_database():

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            scan_type TEXT NOT NULL,

            content TEXT NOT NULL,

            prediction TEXT NOT NULL,

            threat_level TEXT NOT NULL,

            risk_score REAL DEFAULT 0,

            scan_time TEXT NOT NULL

        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS trusted_domains (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            domain TEXT UNIQUE,

            organization TEXT,

            verification_source TEXT,

            verified_at TEXT,

            status TEXT DEFAULT 'VERIFIED'

        )
        """
    )

    trusted_domains = [

        (
            "google.com",
            "Google",
            "Manual Verification"
        ),

        (
            "microsoft.com",
            "Microsoft",
            "Manual Verification"
        ),

        (
            "github.com",
            "GitHub",
            "Manual Verification"
        ),

        (
            "wikipedia.org",
            "Wikipedia",
            "Manual Verification"
        )

    ]

    for (
        domain,
        organization,
        source
    ) in trusted_domains:

        cursor.execute(
            """
            INSERT OR IGNORE INTO trusted_domains
            (
                domain,
                organization,
                verification_source,
                verified_at,
                status
            )
            VALUES (?, ?, ?, ?, 'VERIFIED')
            """,
            (
                domain,
                organization,
                source,
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

    conn.commit()

    conn.close()


ensure_database()


# ============================================================
# NORMALIZE PREDICTION
# ============================================================

def normalize_prediction(
    prediction
):

    if prediction is None:

        return "Suspicious"

    value = str(
        prediction
    ).strip().lower()

    if value == "phishing":

        return "Phishing"

    if value == "safe":

        return "Safe"

    if value == "suspicious":

        return "Suspicious"

    return str(
        prediction
    ).strip()


# ============================================================
# DATABASE STATISTICS
# ============================================================

def get_database_statistics():

    conn = get_db_connection()

    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            """
        )

        threats_analyzed = (
            cursor.fetchone()[0]
            or 0
        )

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE LOWER(
                TRIM(prediction)
            ) = 'phishing'
            """
        )

        phishing_detected = (
            cursor.fetchone()[0]
            or 0
        )

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE LOWER(
                TRIM(prediction)
            ) = 'safe'
            """
        )

        safe_scans = (
            cursor.fetchone()[0]
            or 0
        )

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE LOWER(
                TRIM(prediction)
            ) = 'suspicious'
            """
        )

        suspicious_scans = (
            cursor.fetchone()[0]
            or 0
        )

        detection_rate = 0

        if threats_analyzed > 0:

            detection_rate = (
                phishing_detected
                / threats_analyzed
            ) * 100

        return {

            "threats_analyzed":
                threats_analyzed,

            "phishing_detected":
                phishing_detected,

            "safe_scans":
                safe_scans,

            "suspicious_scans":
                suspicious_scans,

            "detection_rate":
                round(
                    detection_rate,
                    1
                )
        }

    finally:

        conn.close()


# ============================================================
# SOCKET STATISTICS
# ============================================================

def broadcast_statistics():

    try:

        statistics = (
            get_database_statistics()
        )

        socketio.emit(
            "stats_update",
            statistics
        )

    except Exception as e:

        print(
            "STATISTICS BROADCAST ERROR:",
            e
        )


# ============================================================
# IP / DNS INFORMATION
# ============================================================

def get_ip_information(url):

    try:

        hostname = (
            urlparse(url).hostname
        )

        if not hostname:

            return {
                "dns_exists": False,
                "hostname": None,
                "ip_addresses": []
            }

        ip_addresses = list({

            item[4][0]

            for item in socket.getaddrinfo(
                hostname,
                None
            )

        })

        return {

            "dns_exists": True,

            "hostname": hostname,

            "ip_addresses":
                ip_addresses

        }

    except Exception as e:

        print(
            "IP / DNS LOOKUP ERROR:",
            e
        )

        return {

            "dns_exists": False,

            "hostname": None,

            "ip_addresses": [],

            "error": str(e)

        }


# ============================================================
# TRUSTED DOMAIN
# ============================================================

def check_trusted_domain(url):

    try:

        hostname = (
            urlparse(url).hostname
        )

        if not hostname:

            return {

                "trusted": False,

                "domain": None

            }

        hostname = hostname.lower()

        if hostname.startswith("www."):

            hostname = hostname[4:]

        conn = get_db_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                domain,
                organization,
                verification_source,
                status
            FROM trusted_domains
            WHERE domain = ?
            AND status = 'VERIFIED'
            LIMIT 1
            """,
            (
                hostname,
            )
        )

        row = cursor.fetchone()

        conn.close()

        if row:

            return {

                "trusted": True,

                "domain":
                    row["domain"],

                "organization":
                    row["organization"],

                "verification_source":
                    row["verification_source"]

            }

        return {

            "trusted": False,

            "domain": hostname

        }

    except Exception as e:

        print(
            "TRUSTED DOMAIN ERROR:",
            e
        )

        return {

            "trusted": False,

            "domain": None

        }


# ============================================================
# URL PREVENTION
# ============================================================

def get_url_prevention(
    threat_level
):

    threat_level = str(
        threat_level
    ).upper()

    if threat_level == "HIGH":

        return [

            "Block URL immediately",

            "Do not enter credentials",

            "Do not download files",

            "Do not provide OTP or password",

            "Report the URL to the security team"

        ]

    elif threat_level == "MEDIUM":

        return [

            "Verify website authenticity",

            "Avoid entering sensitive information",

            "Do not download files",

            "Check the domain reputation"

        ]

    return [

        "No major threats detected",

        "Continue normal security precautions"

    ]


# ============================================================
# EMAIL PREVENTION
# ============================================================

def get_email_prevention(
    prediction
):

    if (
        normalize_prediction(
            prediction
        )
        == "Phishing"
    ):

        return [

            "Do not click suspicious links",

            "Verify sender identity",

            "Never share passwords or OTPs",

            "Report suspicious email"

        ]

    return [

        "No major phishing indicators detected",

        "Still verify unexpected messages before acting"

    ]


# ============================================================
# URL ACTION
# ============================================================

def get_url_action(
    threat_level,
    risk_score,
    trusted_result=None,
    cti_result=None
):

    threat_level = str(
        threat_level or ""
    ).upper()

    risk_score = float(
        risk_score or 0
    )

    trusted = bool(
        trusted_result
        and trusted_result.get(
            "trusted",
            False
        )
    )

    cti_matched = bool(
        cti_result
        and cti_result.get(
            "matched",
            False
        )
    )

    # --------------------------------------------------------
    # NEVER ALLOW STRONG CTI EVIDENCE
    # --------------------------------------------------------

    if (
        cti_matched
        and risk_score >= 60
    ):

        return {

            "action": "BLOCK",

            "message":
                "URL blocked because threat intelligence "
                "and risk analysis indicate malicious activity.",

            "severity": "HIGH"

        }

    # --------------------------------------------------------
    # VERY HIGH RISK
    # --------------------------------------------------------

    if (
        risk_score >= 80
        and not trusted
    ):

        return {

            "action": "BLOCK",

            "message":
                "URL blocked because the calculated "
                "risk is very high.",

            "severity": "HIGH"

        }

    # --------------------------------------------------------
    # HIGH
    # --------------------------------------------------------

    if threat_level == "HIGH":

        return {

            "action": "BLOCK",

            "message":
                "URL blocked because multiple phishing "
                "indicators were detected.",

            "severity": "HIGH"

        }

    # --------------------------------------------------------
    # MEDIUM
    # --------------------------------------------------------

    if (
        risk_score >= 31
        or threat_level == "MEDIUM"
    ):

        return {

            "action": "WARN",

            "message":
                "This URL is suspicious. Verify the "
                "website before continuing.",

            "severity": "MEDIUM"

        }

    # --------------------------------------------------------
    # SAFE
    # --------------------------------------------------------

    return {

        "action": "ALLOW",

        "message":
            "This URL appears to be safe.",

        "severity": "LOW"

    }


# ============================================================
# STRONG URL EVIDENCE CHECK
#
# THIS IS THE IMPORTANT FIX
# ============================================================

def enforce_url_evidence(
    result,
    url_result,
    trusted_result,
    cti_result
):

    if not isinstance(
        result,
        dict
    ):

        result = {}

    if not isinstance(
        url_result,
        dict
    ):

        return result

    url_score = float(
        url_result.get(
            "risk_score",
            0
        )
        or 0
    )

    url_prediction = normalize_prediction(
        url_result.get(
            "prediction"
        )
    )

    url_threat = str(
        url_result.get(
            "threat_level",
            ""
        )
    ).upper()

    features = url_result.get(
        "features",
        {}
    )

    if not isinstance(
        features,
        dict
    ):

        features = {}

    keywords = features.get(
        "suspicious_keywords",
        []
    )

    if not isinstance(
        keywords,
        list
    ):

        keywords = []

    uses_ip = bool(
        features.get(
            "uses_ip",
            False
        )
    )

    contains_at = bool(
        features.get(
            "contains_at_symbol",
            False
        )
    )

    punycode = bool(
        features.get(
            "punycode",
            False
        )
    )

    suspicious_tld = bool(
        features.get(
            "suspicious_tld",
            False
        )
    )

    lookalike = features.get(
        "lookalike",
        {}
    )

    if not isinstance(
        lookalike,
        dict
    ):

        lookalike = {}

    lookalike_score = float(
        lookalike.get(
            "risk_score",
            0
        )
        or 0
    )

    strong_signals = 0

    if uses_ip:

        strong_signals += 1

    if contains_at:

        strong_signals += 1

    if punycode:

        strong_signals += 1

    if suspicious_tld:

        strong_signals += 1

    if lookalike_score >= 45:

        strong_signals += 1

    if len(keywords) >= 2:

        strong_signals += 1

    # --------------------------------------------------------
    # TRUSTED DOMAIN EXCEPTION
    # --------------------------------------------------------

    trusted = bool(
        trusted_result
        and trusted_result.get(
            "trusted",
            False
        )
    )

    # --------------------------------------------------------
    # CTI
    # --------------------------------------------------------

    cti_matched = bool(
        cti_result
        and cti_result.get(
            "matched",
            False
        )
    )

    # --------------------------------------------------------
    # DO NOT DOWNGRADE STRONG EVIDENCE
    # --------------------------------------------------------

    if not trusted:

        # URL detector already says phishing
        if url_prediction == "Phishing":

            result["prediction"] = "Phishing"

            result["threat_level"] = "HIGH"

            result["risk_score"] = max(
                float(
                    result.get(
                        "risk_score",
                        0
                    )
                    or 0
                ),
                url_score,
                70
            )

        # High URL score
        elif url_score >= 70:

            result["prediction"] = "Phishing"

            result["threat_level"] = "HIGH"

            result["risk_score"] = max(
                float(
                    result.get(
                        "risk_score",
                        0
                    )
                    or 0
                ),
                url_score,
                70
            )

        # Multiple strong signals
        elif strong_signals >= 3:

            result["prediction"] = "Phishing"

            result["threat_level"] = "HIGH"

            result["risk_score"] = max(
                float(
                    result.get(
                        "risk_score",
                        0
                    )
                    or 0
                ),
                url_score,
                70
            )

        # CTI match
        elif cti_matched:

            result["prediction"] = "Phishing"

            result["threat_level"] = "HIGH"

            result["risk_score"] = max(
                float(
                    result.get(
                        "risk_score",
                        0
                    )
                    or 0
                ),
                70
            )

        # URL says suspicious
        elif (
            url_prediction == "Suspicious"
            and url_score >= 40
        ):

            current_score = float(
                result.get(
                    "risk_score",
                    0
                )
                or 0
            )

            result["risk_score"] = max(
                current_score,
                url_score
            )

            if result[
                "risk_score"
            ] >= 70:

                result[
                    "prediction"
                ] = "Phishing"

                result[
                    "threat_level"
                ] = "HIGH"

            else:

                result[
                    "prediction"
                ] = "Suspicious"

                result[
                    "threat_level"
                ] = "MEDIUM"

    return result


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return jsonify({

        "message":
            "AI Phishing Detection API Running",

        "status":
            "online",

        "database":
            DATABASE_PATH

    })


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():

    try:

        statistics = (
            get_database_statistics()
        )

        return jsonify({

            "status":
                "healthy",

            "service":
                "AI-ML Phishing Detection System",

            "database":
                "connected",

            "total_scans":
                statistics[
                    "threats_analyzed"
                ]

        })

    except Exception as e:

        return jsonify({

            "status":
                "unhealthy",

            "error":
                str(e)

        }), 500


# ============================================================
# ANALYZE URL
# ============================================================

@app.route(
    "/analyze-url",
    methods=["POST"]
)
def analyze_url_route():

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({

            "error":
                "Invalid JSON request"

        }), 400

    url = str(
        data.get(
            "url",
            ""
        )
    ).strip()

    if not url:

        return jsonify({

            "error":
                "Please enter a URL"

        }), 400

    # ========================================================
    # VALIDATION
    # ========================================================

    if not is_valid_url(url):

        return jsonify({

            "error":
                "Invalid URL format. "
                "Example: https://google.com"

        }), 400

    # ========================================================
    # DUPLICATE
    # ========================================================

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM scans
        WHERE scan_type = ?
        AND content = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            "URL",
            url
        )
    )

    existing = cursor.fetchone()

    conn.close()

    is_duplicate = (
        existing is not None
    )

    # ========================================================
    # URL FEATURE ANALYSIS
    # ========================================================

    try:

        url_result = analyze_url(
            url
        )

    except Exception as e:

        print(
            "URL ANALYSIS ERROR:",
            e
        )

        return jsonify({

            "error":
                "URL feature analysis failed",

            "details":
                str(e)

        }), 500

    # ========================================================
    # DOMAIN ANALYSIS
    # ========================================================

    try:

        domain_result = analyze_domain(
            url
        )

    except Exception as e:

        print(
            "DOMAIN ANALYSIS ERROR:",
            e
        )

        domain_result = {

            "risk_score": 0,

            "reasons": [

                "Domain analysis unavailable"

            ]

        }

    # ========================================================
    # CTI ANALYSIS
    # ========================================================

    try:

        cti_result = analyze_cti(
            url
        )

    except Exception as e:

        print(
            "CTI ANALYSIS ERROR:",
            e
        )

        cti_result = {

            "matched": False,

            "risk_score": 0,

            "reasons": []

        }

    # ========================================================
    # HYBRID RISK
    # ========================================================

    try:

        result = calculate_hybrid_risk(

            url_result=url_result,

            domain_result=domain_result,

            cti_result=cti_result

        )

    except Exception as e:

        print(
            "RISK FUSION ERROR:",
            e
        )

        # IMPORTANT:
        # Even if fusion fails, use URL analysis.

        result = {

            "prediction":
                url_result.get(
                    "prediction",
                    "Suspicious"
                ),

            "risk_score":
                url_result.get(
                    "risk_score",
                    0
                ),

            "threat_level":
                url_result.get(
                    "threat_level",
                    "MEDIUM"
                ),

            "reasons":
                url_result.get(
                    "reasons",
                    []
                ),

            "components": {}

        }

    if not isinstance(
        result,
        dict
    ):

        result = {}

    # ========================================================
    # IP INFORMATION
    # ========================================================

    result[
        "ip_information"
    ] = get_ip_information(
        url
    )

    # ========================================================
    # DEFAULT VALUES
    # ========================================================

    result.setdefault(
        "prediction",
        "Suspicious"
    )

    result.setdefault(
        "risk_score",
        0
    )

    result.setdefault(
        "threat_level",
        "MEDIUM"
    )

    result.setdefault(
        "reasons",
        []
    )

    result[
        "prediction"
    ] = normalize_prediction(
        result[
            "prediction"
        ]
    )

    # ========================================================
    # TRUSTED DOMAIN
    # ========================================================

    trusted_result = (
        check_trusted_domain(
            url
        )
    )

    result[
        "trusted_domain"
    ] = trusted_result

    # ========================================================
    # IMPORTANT:
    # ENFORCE URL EVIDENCE AFTER FUSION
    # ========================================================

    result = enforce_url_evidence(

        result,

        url_result,

        trusted_result,

        cti_result

    )

    # Normalize once again
    result[
        "prediction"
    ] = normalize_prediction(
        result[
            "prediction"
        ]
    )

    result[
        "risk_score"
    ] = min(
        max(
            float(
                result.get(
                    "risk_score",
                    0
                )
                or 0
            ),
            0
        ),
        100
    )

    # ========================================================
    # THREAT LEVEL CONSISTENCY
    # ========================================================

    if result[
        "risk_score"
    ] >= 70:

        result[
            "threat_level"
        ] = "HIGH"

        result[
            "prediction"
        ] = "Phishing"

    elif result[
        "risk_score"
    ] >= 40:

        result[
            "threat_level"
        ] = "MEDIUM"

        if result[
            "prediction"
        ] == "Safe":

            result[
                "prediction"
            ] = "Suspicious"

    else:

        result[
            "threat_level"
        ] = "LOW"

        if result[
            "prediction"
        ] not in (
            "Phishing",
            "Suspicious"
        ):

            result[
                "prediction"
            ] = "Safe"

    # ========================================================
    # COMPONENTS
    # ========================================================

    if not isinstance(
        result.get(
            "components"
        ),
        dict
    ):

        result[
            "components"
        ] = {}

    result[
        "components"
    ].setdefault(
        "ml_score",
        0
    )

    result[
        "components"
    ].setdefault(
        "url_score",
        url_result.get(
            "risk_score",
            0
        )
    )

    result[
        "components"
    ].setdefault(
        "domain_score",
        domain_result.get(
            "risk_score",
            0
        )
        if isinstance(
            domain_result,
            dict
        )
        else 0
    )

    result[
        "components"
    ].setdefault(
        "cti_score",
        cti_result.get(
            "risk_score",
            0
        )
        if isinstance(
            cti_result,
            dict
        )
        else 0
    )

    # ========================================================
    # PREVENTION
    # ========================================================

    result[
        "prevention"
    ] = get_url_prevention(
        result[
            "threat_level"
        ]
    )

    # ========================================================
    # ACTION
    # ========================================================

    result[
        "prevention_action"
    ] = get_url_action(

        result[
            "threat_level"
        ],

        result[
            "risk_score"
        ],

        trusted_result,

        cti_result

    )

    # ========================================================
    # FEATURES
    # ========================================================

    result[
        "features"
    ] = url_result.get(
        "features",
        {}
    )

    # ========================================================
    # CTI
    # ========================================================

    result[
        "cti"
    ] = cti_result

    # ========================================================
    # REASONS
    # ========================================================

    combined_reasons = []

    for source in (
        url_result,
        domain_result,
        cti_result,
        result
    ):

        if isinstance(
            source,
            dict
        ):

            source_reasons = source.get(
                "reasons",
                []
            )

            if isinstance(
                source_reasons,
                list
            ):

                combined_reasons.extend(
                    source_reasons
                )

    result[
        "reasons"
    ] = list(
        dict.fromkeys(
            combined_reasons
        )
    )

    # ========================================================
    # DUPLICATE
    # ========================================================

    result[
        "duplicate"
    ] = is_duplicate

    if is_duplicate:

        result[
            "message"
        ] = (
            "This URL has already been scanned. "
            "Showing the current analysis."
        )

    # ========================================================
    # SAVE SCAN
    # ========================================================

    if not is_duplicate:

        current_time = (
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        conn = get_db_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO scans
            (
                scan_type,
                content,
                prediction,
                threat_level,
                risk_score,
                scan_time
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "URL",

                url,

                result[
                    "prediction"
                ],

                result[
                    "threat_level"
                ],

                float(
                    result[
                        "risk_score"
                    ]
                    or 0
                ),

                current_time

            )
        )

        new_scan_id = (
            cursor.lastrowid
        )

        conn.commit()

        conn.close()

        # Socket event
        socketio.emit(
            "new_scan",
            {

                "id":
                    new_scan_id,

                "type":
                    "URL",

                "scan_type":
                    "URL",

                "prediction":
                    result[
                        "prediction"
                    ],

                "threat_level":
                    result[
                        "threat_level"
                    ],

                "risk_score":
                    result[
                        "risk_score"
                    ],

                "timestamp":
                    current_time

            }
        )

        broadcast_statistics()

    # ========================================================
    # STATISTICS
    # ========================================================

    result[
        "statistics"
    ] = get_database_statistics()

    # ========================================================
    # DEBUG
    # ========================================================

    print(
        "============================================"
    )

    print(
        "URL ANALYSIS RESULT"
    )

    print(
        "URL:",
        url
    )

    print(
        "Prediction:",
        result[
            "prediction"
        ]
    )

    print(
        "Threat Level:",
        result[
            "threat_level"
        ]
    )

    print(
        "Risk Score:",
        result[
            "risk_score"
        ]
    )

    print(
        "URL Feature Score:",
        url_result.get(
            "risk_score",
            0
        )
    )

    print(
        "URL Feature Prediction:",
        url_result.get(
            "prediction"
        )
    )

    print(
        "Trusted:",
        trusted_result.get(
            "trusted",
            False
        )
    )

    print(
        "CTI Matched:",
        cti_result.get(
            "matched",
            False
        )
    )

    print(
        "Prevention Action:",
        result[
            "prevention_action"
        ].get(
            "action"
        )
    )

    print(
        "============================================"
    )

    return jsonify(
        result
    )


# ============================================================
# EMAIL ANALYSIS
# ============================================================

@app.route(
    "/analyze-email",
    methods=["POST"]
)
def analyze_email():

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({

            "error":
                "Invalid JSON request"

        }), 400

    email = str(
        data.get(
            "email",
            ""
        )
    ).strip()

    if not email:

        return jsonify({

            "error":
                "Please enter email content"

        }), 400

    # --------------------------------------------------------
    # DUPLICATE
    # --------------------------------------------------------

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM scans
        WHERE scan_type = ?
        AND content = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            "EMAIL",
            email
        )
    )

    existing = cursor.fetchone()

    conn.close()

    is_duplicate = (
        existing is not None
    )

    # --------------------------------------------------------
    # ML
    # --------------------------------------------------------

    try:

        result = predict_email(
            email
        )

    except Exception as e:

        print(
            "EMAIL ML ERROR:",
            e
        )

        return jsonify({

            "error":
                "Email ML prediction failed",

            "details":
                str(e)

        }), 500

    if not isinstance(
        result,
        dict
    ):

        result = {}

    result.setdefault(
        "prediction",
        "Suspicious"
    )

    result.setdefault(
        "threat_level",
        "MEDIUM"
    )

    result.setdefault(
        "risk_score",
        0
    )

    result.setdefault(
        "reasons",
        []
    )

    result[
        "prediction"
    ] = normalize_prediction(
        result[
            "prediction"
        ]
    )

    result[
        "prevention"
    ] = get_email_prevention(
        result[
            "prediction"
        ]
    )

    result[
        "duplicate"
    ] = is_duplicate

    if is_duplicate:

        result[
            "message"
        ] = (
            "This email has already been scanned. "
            "Showing the current analysis."
        )

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    if not is_duplicate:

        current_time = (
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        conn = get_db_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO scans
            (
                scan_type,
                content,
                prediction,
                threat_level,
                risk_score,
                scan_time
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "EMAIL",

                email,

                result[
                    "prediction"
                ],

                result[
                    "threat_level"
                ],

                float(
                    result[
                        "risk_score"
                    ]
                    or 0
                ),

                current_time

            )
        )

        new_scan_id = (
            cursor.lastrowid
        )

        conn.commit()

        conn.close()

        socketio.emit(
            "new_scan",
            {

                "id":
                    new_scan_id,

                "type":
                    "EMAIL",

                "scan_type":
                    "EMAIL",

                "prediction":
                    result[
                        "prediction"
                    ],

                "threat_level":
                    result[
                        "threat_level"
                    ],

                "risk_score":
                    result[
                        "risk_score"
                    ],

                "timestamp":
                    current_time

            }
        )

        broadcast_statistics()

    result[
        "statistics"
    ] = get_database_statistics()

    return jsonify(
        result
    )


# ============================================================
# HISTORY
# ============================================================

@app.route(
    "/history"
)
def get_history():

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            scan_type,
            content,
            prediction,
            threat_level,
            risk_score,
            scan_time
        FROM scans
        ORDER BY id DESC
        LIMIT 20
        """
    )

    rows = cursor.fetchall()

    conn.close()

    history = []

    for row in rows:

        history.append([

            row["id"],

            row["scan_type"],

            row["content"],

            row["prediction"],

            row["threat_level"],

            row["risk_score"],

            row["scan_time"]

        ])

    return jsonify(
        history
    )


# ============================================================
# STATS
# ============================================================

@app.route(
    "/stats",
    methods=["GET"]
)
def get_stats():

    try:

        return jsonify(
            get_database_statistics()
        )

    except Exception as e:

        return jsonify({

            "threats_analyzed": 0,

            "phishing_detected": 0,

            "safe_scans": 0,

            "suspicious_scans": 0,

            "detection_rate": 0,

            "error":
                str(e)

        }), 500


# ============================================================
# CHART DATA
# ============================================================

@app.route(
    "/chart-data",
    methods=["GET"]
)
def chart_data():

    try:

        statistics = (
            get_database_statistics()
        )

        return jsonify({

            "phishing":
                statistics[
                    "phishing_detected"
                ],

            "safe":
                statistics[
                    "safe_scans"
                ],

            "suspicious":
                statistics[
                    "suspicious_scans"
                ],

            "total":
                statistics[
                    "threats_analyzed"
                ]

        })

    except Exception as e:

        return jsonify({

            "phishing": 0,

            "safe": 0,

            "suspicious": 0,

            "total": 0,

            "error":
                str(e)

        }), 500


# ============================================================
# DELETE SCAN
# ============================================================

@app.route(
    "/delete-scan/<int:scan_id>",
    methods=["DELETE"]
)
def delete_scan(scan_id):

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM scans
        WHERE id = ?
        """,
        (
            scan_id,
        )
    )

    deleted = cursor.rowcount

    conn.commit()

    conn.close()

    if deleted == 0:

        return jsonify({

            "error":
                "Scan not found"

        }), 404

    broadcast_statistics()

    return jsonify({

        "message":
            "Scan deleted successfully",

        "statistics":
            get_database_statistics()

    })


# ============================================================
# CLEAR HISTORY
# ============================================================

@app.route(
    "/clear-history",
    methods=["DELETE"]
)
def clear_history():

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM scans"
    )

    try:

        cursor.execute(
            """
            DELETE FROM sqlite_sequence
            WHERE name = 'scans'
            """
        )

    except sqlite3.OperationalError:

        pass

    conn.commit()

    conn.close()

    broadcast_statistics()

    socketio.emit(
        "history_cleared",
        {
            "message":
                "All scan history cleared"
        }
    )

    return jsonify({

        "message":
            "All scan history cleared",

        "statistics":
            get_database_statistics()

    })


# ============================================================
# EXPORT HISTORY
# ============================================================

@app.route(
    "/export-history",
    methods=["GET"]
)
def export_history():

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            scan_type,
            content,
            prediction,
            threat_level,
            risk_score,
            scan_time
        FROM scans
        ORDER BY id ASC
        """
    )

    rows = cursor.fetchall()

    conn.close()

    output = io.StringIO()

    writer = csv.writer(
        output
    )

    writer.writerow([

        "ID",

        "Scan Type",

        "Content",

        "Prediction",

        "Threat Level",

        "Risk Score",

        "Scan Time"

    ])

    for row in rows:

        writer.writerow([

            row["id"],

            row["scan_type"],

            row["content"],

            row["prediction"],

            row["threat_level"],

            row["risk_score"],

            row["scan_time"]

        ])

    return Response(

        output.getvalue(),

        mimetype="text/csv",

        headers={

            "Content-Disposition":
                "attachment; "
                "filename=scan_history.csv"

        }

    )


# ============================================================
# PDF
# ============================================================

@app.route(
    "/download-pdf",
    methods=["POST"]
)
def download_pdf():

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({

            "error":
                "Invalid report data"

        }), 400

    report_path = os.path.join(
        BASE_DIR,
        "scan_report.pdf"
    )

    try:

        generate_report(
            data,
            report_path
        )

    except Exception as e:

        print(
            "PDF GENERATION ERROR:",
            e
        )

        return jsonify({

            "error":
                "PDF generation failed",

            "details":
                str(e)

        }), 500

    return send_file(

        report_path,

        as_attachment=True,

        download_name=
            "url_scan_report.pdf",

        mimetype=
            "application/pdf"

    )


# ============================================================
# CTI STATISTICS
# ============================================================

@app.route(
    "/cti-stats",
    methods=["GET"]
)
def cti_stats():

    conn = get_db_connection()

    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            SELECT

                COUNT(*) AS total_indicators,

                SUM(
                    CASE
                        WHEN LOWER(severity) = 'high'
                        THEN 1
                        ELSE 0
                    END
                ) AS high_severity,

                SUM(
                    CASE
                        WHEN LOWER(severity) = 'medium'
                        THEN 1
                        ELSE 0
                    END
                ) AS medium_severity,

                SUM(
                    CASE
                        WHEN LOWER(severity) = 'low'
                        THEN 1
                        ELSE 0
                    END
                ) AS low_severity

            FROM threat_indicators
            """
        )

        row = cursor.fetchone()

        return jsonify({

            "total_indicators":
                row["total_indicators"]
                or 0,

            "high_severity":
                row["high_severity"]
                or 0,

            "medium_severity":
                row["medium_severity"]
                or 0,

            "low_severity":
                row["low_severity"]
                or 0

        })

    except sqlite3.OperationalError:

        return jsonify({

            "total_indicators": 0,

            "high_severity": 0,

            "medium_severity": 0,

            "low_severity": 0

        })

    finally:

        conn.close()


# ============================================================
# ROUTES
# ============================================================

print(
    "============================================"
)

print(
    "AVAILABLE ROUTES"
)

print(
    app.url_map
)

print(
    "============================================"
)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    print(
        "Starting server on port 5000..."
    )

    socketio.run(

        app,

        host="0.0.0.0",

        port=5000,

        debug=False,

        allow_unsafe_werkzeug=True

    )