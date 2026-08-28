import { useState } from "react";
import axios from "axios";
import { FaLink } from "react-icons/fa";
import { toast } from "react-toastify";

function UrlAnalyzer() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // ============================================================
  // BACKEND API
  // ============================================================

  const API_URL = "http://localhost:5000";

  // ============================================================
  // ANALYZE URL
  // ============================================================

  const analyzeUrl = async () => {
    if (!url.trim()) {
      setError("Please enter a URL");
      toast.error("Please enter a URL");
      return;
    }

    try {
      setError("");
      setResult(null);
      setLoading(true);

      const response = await axios.post(
        `${API_URL}/analyze-url`,
        {
          url: url.trim(),
        }
      );

      console.log("COMPLETE BACKEND RESPONSE:");
      console.log(response.data);

      setResult(response.data);

      // ========================================================
      // RESULT TOAST
      // ========================================================

      if (response.data.prediction === "Phishing") {
        toast.error("⚠️ Phishing URL Detected!");
      } else if (
        response.data.prediction === "Suspicious"
      ) {
        toast.warning("⚠️ Suspicious URL Detected!");
      } else {
        toast.success("✅ Safe URL");
      }
    } catch (err) {
      console.error("URL ANALYSIS ERROR:", err);

      if (err.response) {
        const message =
          err.response.data?.error ||
          "URL analysis failed";

        setError(message);
        toast.error(message);
      } else {
        setError(
          "Server connection failed. Make sure Flask is running on port 5000."
        );

        toast.error("Server connection failed");
      }
    } finally {
      setLoading(false);
    }
  };

  // ============================================================
  // DOWNLOAD PDF REPORT
  // ============================================================

  const downloadReport = async () => {
    if (!result) {
      toast.error("No scan result available");
      return;
    }

    try {
      const response = await axios.post(
        `${API_URL}/download-pdf`,
        result,
        {
          responseType: "blob",
        }
      );

      const fileURL = window.URL.createObjectURL(
        new Blob([response.data], {
          type: "application/pdf",
        })
      );

      const link = document.createElement("a");

      link.href = fileURL;
      link.download = "url_scan_report.pdf";

      document.body.appendChild(link);

      link.click();

      link.remove();

      window.URL.revokeObjectURL(fileURL);

      toast.success("PDF report downloaded");
    } catch (err) {
      console.error("PDF ERROR:", err);

      toast.error("Failed to download report");
    }
  };

  // ============================================================
  // THREAT CLASS
  // ============================================================

  const threatClass =
    result?.threat_level === "HIGH"
      ? "high"
      : result?.threat_level === "MEDIUM"
      ? "medium"
      : "low";

  // ============================================================
  // SAFE SCORE VALUE
  // ============================================================

  const riskScore = Math.min(
    Math.max(
      Number(result?.risk_score) || 0,
      0
    ),
    100
  );

  // ============================================================
  // RENDER
  // ============================================================

  return (
    <div className="cyber-card">

      {/* ========================================================
          HEADER
      ======================================================== */}

      <div className="card-header">
        <FaLink />
        <h2>URL Analysis</h2>
      </div>

      {/* ========================================================
          URL INPUT
      ======================================================== */}

      <input
        type="text"
        placeholder="Enter URL (e.g. https://google.com)"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            analyzeUrl();
          }
        }}
      />

      {/* ========================================================
          ANALYZE BUTTON
      ======================================================== */}

      <button
        className="scan-btn"
        onClick={analyzeUrl}
        disabled={loading}
      >
        {loading
          ? "Analyzing..."
          : "Analyze URL"}
      </button>

      {/* ========================================================
          ERROR
      ======================================================== */}

      {error && (
        <div className="error-box">
          {error}
        </div>
      )}

      {/* ========================================================
          COMPLETE RESULT
      ======================================================== */}

      {result && (
        <div className="result-card">

          {/* ====================================================
              DUPLICATE MESSAGE
          ==================================================== */}

          {result.duplicate === true && (
            <div className="warning-box">
              ⚠️ {result.message}
            </div>
          )}

          {/* ====================================================
              THREAT LEVEL
          ==================================================== */}

          <div
            className={`threat-badge ${threatClass}`}
          >
            Threat Level:{" "}
            {result.threat_level || "UNKNOWN"}
          </div>

          {/* ====================================================
              PREDICTION
          ==================================================== */}

          <p>
            <strong>Prediction:</strong>{" "}
            {result.prediction || "Unknown"}
          </p>

          {/* ====================================================
              RISK SCORE
          ==================================================== */}

          <p>
            <strong>Risk Score:</strong>{" "}
            {riskScore}%
          </p>

          {/* ====================================================
              RISK BAR
          ==================================================== */}

          <div className="risk-bar">
            <div
              className={`risk-fill risk-${threatClass}`}
              style={{
                width: `${riskScore}%`,
              }}
            />
          </div>

          {/* ====================================================
              RISK COMPONENTS
          ==================================================== */}

          {result.components && (
            <div className="analysis-section">

              <h4>
                📊 Risk Components
              </h4>

              <ul>

                <li>
                  <strong>
                    URL Analysis:
                  </strong>{" "}
                  {result.components.url_score ?? 0}%
                </li>

                <li>
                  <strong>
                    Domain Analysis:
                  </strong>{" "}
                  {result.components.domain_score ?? 0}%
                </li>

                <li>
                  <strong>
                    CTI / IOC Analysis:
                  </strong>{" "}
                  {result.components.cti_score ?? 0}%
                </li>

                <li>
                  <strong>
                    ML Analysis:
                  </strong>{" "}
                  {result.components.ml_score ?? 0}%
                </li>

              </ul>

            </div>
          )}

          {/* ====================================================
              CTI / THREAT INTELLIGENCE
          ==================================================== */}

          {result.cti && (
            <div className="analysis-section">

              <h4>
                🛡️ Threat Intelligence
              </h4>

              <p>
                <strong>Matched:</strong>{" "}
                {result.cti.matched
                  ? "Yes"
                  : "No"}
              </p>

              {result.cti.matched && (
                <>

                  <p>
                    <strong>
                      Indicator:
                    </strong>{" "}
                    {result.cti.indicator}
                  </p>

                  <p>
                    <strong>
                      Indicator Type:
                    </strong>{" "}
                    {result.cti.indicator_type}
                  </p>

                  <p>
                    <strong>
                      Threat Type:
                    </strong>{" "}
                    {result.cti.threat_type}
                  </p>

                  <p>
                    <strong>
                      Severity:
                    </strong>{" "}
                    {result.cti.severity}
                  </p>

                  <p>
                    <strong>
                      Confidence:
                    </strong>{" "}
                    {result.cti.confidence}%
                  </p>

                  <p>
                    <strong>
                      Source:
                    </strong>{" "}
                    {result.cti.source}
                  </p>

                  <p>
                    <strong>
                      CTI Risk Score:
                    </strong>{" "}
                    {result.cti.risk_score}%
                  </p>

                </>
              )}

            </div>
          )}

          {/* ====================================================
              URL FEATURES
          ==================================================== */}

          {result.features && (
            <div className="analysis-section">

              <h4>
                🔍 URL Features
              </h4>

              <ul>

                <li>
                  <strong>
                    HTTPS:
                  </strong>{" "}
                  {result.features.https
                    ? "Yes"
                    : "No"}
                </li>

                <li>
                  <strong>
                    URL Length:
                  </strong>{" "}
                  {result.features.url_length}
                </li>

                <li>
                  <strong>
                    Domain Length:
                  </strong>{" "}
                  {result.features.domain_length}
                </li>

                <li>
                  <strong>
                    Dot Count:
                  </strong>{" "}
                  {result.features.dot_count}
                </li>

                <li>
                  <strong>
                    Hyphen Count:
                  </strong>{" "}
                  {result.features.hyphen_count}
                </li>

                <li>
                  <strong>
                    Digit Count:
                  </strong>{" "}
                  {result.features.digit_count}
                </li>

                <li>
                  <strong>
                    Subdomain Count:
                  </strong>{" "}
                  {result.features.subdomain_count}
                </li>

                <li>
                  <strong>
                    Uses IP:
                  </strong>{" "}
                  {result.features.uses_ip
                    ? "Yes"
                    : "No"}
                </li>

                <li>
                  <strong>
                    Punycode:
                  </strong>{" "}
                  {result.features.punycode
                    ? "Yes"
                    : "No"}
                </li>

                <li>
                  <strong>
                    DNS Exists:
                  </strong>{" "}
                  {result.features.dns_exists
                    ? "Yes"
                    : "No"}
                </li>

                <li>
                  <strong>
                    Suspicious Keywords:
                  </strong>{" "}
                  {result.features
                    .suspicious_keywords
                    ?.length > 0
                    ? result.features
                        .suspicious_keywords
                        .join(", ")
                    : "None"}
                </li>

              </ul>

            </div>
          )}

          {/* ====================================================
              REASONS
          ==================================================== */}

          <div className="analysis-section">

            <h4>
              ⚠️ Reasons
            </h4>

            {result.reasons &&
            result.reasons.length > 0 ? (

              <ul>

                {result.reasons.map(
                  (reason, index) => (
                    <li key={index}>
                      {reason}
                    </li>
                  )
                )}

              </ul>

            ) : (

              <p>
                No suspicious indicators detected.
              </p>

            )}

          </div>

          {/* ====================================================
              PREVENTION
          ==================================================== */}

          <div className="analysis-section">

            <h4>
              🛡️ Prevention
            </h4>

            {result.prevention &&
            result.prevention.length > 0 ? (

              <ul>

                {result.prevention.map(
                  (item, index) => (
                    <li key={index}>
                      {item}
                    </li>
                  )
                )}

              </ul>

            ) : (

              <p>
                No prevention tips available.
              </p>

            )}

          </div>

          {/* ====================================================
              PDF REPORT
          ==================================================== */}

          <button
            className="download-btn"
            onClick={downloadReport}
          >
            📄 Download URL Report
          </button>

        </div>
      )}

    </div>
  );
}

export default UrlAnalyzer;