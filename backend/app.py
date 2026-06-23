from flask import Flask, request, jsonify, Response, send_file
import database
from flask_cors import CORS
from services.url_features import analyze_url, is_valid_url
from services.email_model import predict_email
import sqlite3
import csv
import io
from report_generator import generate_report
import os
from flask_socketio import SocketIO
from datetime import datetime

print("DATABASE PATH:")
print(os.path.abspath("phishing.db"))



app = Flask(__name__)
CORS(app)

socketio = SocketIO(
    app,
    cors_allowed_origins="*"
)

stats = {
    "threats_analyzed": 0,
    "phishing_detected": 0
}


@app.route("/")
def home():
    return jsonify({
        "message": "Phishing Detection API Running"
    })


@app.route("/analyze-url", methods=["POST"])
def analyze_url_route():

    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "error": "Please enter a URL"
        }), 400

    if not is_valid_url(url):
        return jsonify({
            "error": "Invalid URL format. Example: https://google.com"
        }), 400

    result = analyze_url(url)

    stats["threats_analyzed"] += 1

    if result["threat_level"] == "HIGH":
        stats["phishing_detected"] += 1

    if result["threat_level"] == "HIGH":
        prevention = [
            "Block URL immediately",
            "Do not enter credentials",
            "Report to security team"
        ]
    elif result["threat_level"] == "MEDIUM":
        prevention = [
            "Verify website authenticity",
            "Avoid entering sensitive information"
        ]
    else:
        prevention = [
            "No major threats detected"
        ]

    result["prevention"] = prevention

    conn = sqlite3.connect("phishing.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM scans WHERE scan_type=? AND content=?",
        ("URL", url)
    )

    existing = cursor.fetchone()
    if existing:
        conn.close()
        return jsonify({
        "duplicate": True,
        "message": "This URL has already been scanned.",
        "prediction": existing[3],
        "threat_level": existing[4],
        "risk_score": existing[5],
        "reasons": ["Duplicate scan found in database"]
    })
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
                   INSERT INTO scans
                   (scan_type, content, prediction, threat_level, risk_score, scan_time)
                   VALUES (?, ?, ?, ?, ?, ?)
                   """, (
                       "URL",
                       url,
                       result["prediction"],
                       result["threat_level"],
                       result["risk_score"],
                       current_time
                       ))
    conn.commit()
    socketio.emit("new_scan", {
    "type": "URL",
    "prediction": result["prediction"],
    "threat_level": result["threat_level"],
    "risk_score": result["risk_score"]
})
    conn.close()
    return jsonify(result)


@app.route("/analyze-email", methods=["POST"])
def analyze_email():

    data = request.get_json()
    email = data.get("email", "").strip()

    if not email:
        return jsonify({
            "error": "Please enter email content"
        }), 400

    result = predict_email(email)

    stats["threats_analyzed"] += 1

    if result["prediction"] == "Phishing":
        stats["phishing_detected"] += 1

    result["prevention"] = [
        "Do not click suspicious links",
        "Verify sender identity",
        "Never share passwords or OTPs",
        "Report suspicious emails to security team"
    ]

    conn = sqlite3.connect("phishing.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM scans WHERE scan_type=? AND content=?",
        ("EMAIL", email)
    )

    existing = cursor.fetchone()

    if existing:
        conn.close()

        return jsonify({
            "duplicate": True,
            "message": "This email has already been scanned.",
            "prediction": existing[3],
            "threat_level": existing[4],
            "risk_score": existing[5],
            "reasons": ["Duplicate scan found in database"]
        })
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
                   INSERT INTO scans
                   (scan_type, content, prediction, threat_level, risk_score, scan_time)
                   VALUES (?, ?, ?, ?, ?, ?)
                   """, (
                       "EMAIL",
                       email,
                       result["prediction"],
                       result["threat_level"],
                       result["risk_score"],
                       current_time
                       ))
    conn.commit()
    socketio.emit("new_scan", {
    "type": "EMAIL",
    "prediction": result["prediction"],
    "threat_level": result["threat_level"],
    "risk_score": result["risk_score"]
})
    conn.close()
    return jsonify(result)

@app.route("/history")
def get_history():

    conn = sqlite3.connect("phishing.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM scans
    ORDER BY id ASC
    LIMIT 20
    """)

    rows = cursor.fetchall()

    conn.close()

    return jsonify(rows)



@app.route("/stats")
def get_stats():

    accuracy = 0

    if stats["threats_analyzed"] > 0:
        accuracy = (
            stats["phishing_detected"] /
            stats["threats_analyzed"]
        ) * 100

    return jsonify({
        "threats_analyzed": stats["threats_analyzed"],
        "phishing_detected": stats["phishing_detected"],
        "accuracy": round(accuracy, 1)
    })


@app.route("/delete-scan/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):

    conn = sqlite3.connect("phishing.db")
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM scans WHERE id=?",
        (scan_id,)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Scan deleted successfully"
    })


@app.route("/clear-history", methods=["DELETE"])
def clear_history():

    conn = sqlite3.connect("phishing.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM scans")

    # Reset Auto Increment ID
    cursor.execute(
        "DELETE FROM sqlite_sequence WHERE name='scans'"
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "All scan history cleared"
    })
@app.route("/export-history")
def export_history():

    conn = sqlite3.connect("phishing.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT * FROM scans
    ORDER BY id ASC
    """)

    rows = cursor.fetchall()

    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Scan Type",
        "Content",
        "Prediction",
        "Threat Level",
        "Risk Score"
    ])

    for row in rows:
        writer.writerow(row)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=scan_history.csv"
        }
    )

from flask import send_file

@app.route("/download-pdf", methods=["POST"])
def download_pdf():

    data = request.get_json()

    print("================================")
    print("PDF DATA RECEIVED:")
    print(data)
    print("================================")

    generate_report(
        data,
        "scan_report.pdf"
    )

    return send_file(
        "scan_report.pdf",
        as_attachment=True
    )

@app.route("/chart-data")
def chart_data():

    conn = sqlite3.connect("phishing.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT prediction, COUNT(*)
    FROM scans
    GROUP BY prediction
    """)

    rows = cursor.fetchall()

    conn.close()

    return jsonify(rows)

    
print(app.url_map)

if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False
    )
