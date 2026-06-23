import { useState } from "react";
import axios from "axios";
import { FaLink } from "react-icons/fa";

function UrlAnalyzer() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const analyzeUrl = async () => {
    try {
      setError("");
      setResult(null);

      const response = await axios.post(
        "https://ai-phishing-detection-system3.onrender.com/analyze-url",
        {
          url: url,
        }
      );

      setResult(response.data);
    } catch (err) {
      if (err.response) {
        setError(err.response.data.error);
      } else {
        setError("Server connection failed");
      }
    }
  };

  return (
    <div className="cyber-card">
      <div className="card-header">
        <FaLink />
        <h2>URL Analysis</h2>
      </div>

      <input
        type="text"
        placeholder="Enter URL (e.g. https://google.com)"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />

      <button className="scan-btn" onClick={analyzeUrl}>
        Analyze URL
      </button>

      {error && (
        <div className="error-box">
          {error}
        </div>
      )}

      {result && (
        <div className="result-card">

          {result.duplicate && (
            <div className="warning-box">
              ⚠️ {result.message}
            </div>
          )}

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
            {result.reasons && result.reasons.length > 0 ? (
              result.reasons.map((reason, index) => (
                <li key={index}>{reason}</li>
              ))
            ) : (
              <li>No suspicious indicators detected.</li>
            )}
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
      <button
  className="download-btn"
  onClick={async () => {

    const response = await axios.post(
      "http://127.0.0.1:5000/download-pdf",
      result,
      {
        responseType: "blob"
      }
    );

    const fileURL = window.URL.createObjectURL(
      new Blob([response.data])
    );

    const link = document.createElement("a");

    link.href = fileURL;

    link.setAttribute(
      "download",
      "url_scan_report.pdf"
    );

    document.body.appendChild(link);

    link.click();
  }}
>
  📄 Download URL Report
</button>
    </div>
  );
}

export default UrlAnalyzer;
