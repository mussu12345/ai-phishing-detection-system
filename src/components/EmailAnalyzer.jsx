import { useState } from "react";
import axios from "axios";
import { FaEnvelope } from "react-icons/fa";
import { toast } from "react-toastify";
function EmailAnalyzer() {
  const [emailText, setEmailText] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const analyzeEmail = async () => {
  try {
    setError("");
    setResult(null);

    const response = await axios.post(
      "https://ai-phishing-detection-system3.onrender.com/analyze-email",
      {
        email: emailText,
      }
    );

    setResult(response.data);

    if (response.data.prediction === "Phishing") {
      toast.error("⚠️ Phishing Email Detected!");
    } else {
      toast.success("✅ Safe Email");
    }

  } catch (err) {
    if (err.response) {
      setError(err.response.data.error);
      toast.error(err.response.data.error);
    } else {
      setError("Server connection failed");
      toast.error("Server connection failed");
    }
  }
};

  return (
    <div className="cyber-card">
      <div className="card-header">
        <FaEnvelope />
        <h2>Email Analysis</h2>
      </div>

      <textarea
        rows="8"
        placeholder="Paste email content here..."
        value={emailText}
        onChange={(e) => setEmailText(e.target.value)}
      />

      <button className="scan-btn" onClick={analyzeEmail}>
        Analyze Email
      </button>

      {error && <div className="error-box">{error}</div>}

      {result && (
        <div className="result-card">
          <div
            className={`threat-badge ${
              result.threat_level === "HIGH"
                ? "high"
                : result.threat_level === "MEDIUM"
                ? "medium"
                : "low"
            }`}
          >
            Threat Level: {result.threat_level}
          </div>

          <p>
            <strong>Prediction:</strong> {result.prediction}
          </p>

          <p>
            <strong>Risk Score:</strong> {result.risk_score}%
          </p>

          <div className="risk-bar">
            <div
              className={`risk-fill ${
                result.threat_level === "HIGH"
                  ? "risk-high"
                  : result.threat_level === "MEDIUM"
                  ? "risk-medium"
                  : "risk-low"
              }`}
              style={{ width: `${result.risk_score}%` }}
            ></div>
          </div>

          <h4>Reasons</h4>

          <ul>
            {result.reasons.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>

          {result.prevention && (
            <>
              <h4>Prevention</h4>

              <ul>
                {result.prevention.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
      {result && (
  <button
    className="download-btn"
    onClick={async () => {
      const pdfResponse = await axios.post(
        "https://ai-phishing-detection-system3.onrender.com/download-pdf",
        result,
        {
    responseType: "blob",
  }
);

const fileURL = window.URL.createObjectURL(
  new Blob([pdfResponse.data])
);

      const link = document.createElement("a");

      link.href = fileURL;

      link.setAttribute(
        "download",
        "email_scan_report.pdf"
      );

      document.body.appendChild(link);

      link.click();
    }}
  >
    📄 Download Email Report
  </button>
)}
    </div>
  );
}

export default EmailAnalyzer;