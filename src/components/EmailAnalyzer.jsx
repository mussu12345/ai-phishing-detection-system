import { useState } from "react";
import axios from "axios";
import {
  FaEnvelope,
  FaChartBar,
  FaBrain,
  FaCheckCircle,
  FaExclamationTriangle,
  FaShieldAlt,
  FaStar,
} from "react-icons/fa";
import { toast } from "react-toastify";

const API_BASE = "http://localhost:5000";
function EmailAnalyzer() {
  const [emailText, setEmailText] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [downloading, setDownloading] = useState(false);

  /* ============================================================
     EMAIL ANALYSIS
  ============================================================ */

  const analyzeEmail = async () => {
    if (!emailText.trim()) {
      setError("Please enter email content");
      toast.error("Please enter email content");
      return;
    }

    try {
      setError("");
      setResult(null);
      setLoading(true);

      const response = await axios.post(
        `${API_BASE}/analyze-email`,
        {
          email: emailText.trim(),
        }
      );

      console.log("EMAIL ANALYSIS RESPONSE:", response.data);

      setResult(response.data);

      if (response.data.prediction === "Phishing") {
        toast.error("⚠️ Phishing Email Detected!");
      } else if (
        response.data.prediction === "Suspicious"
      ) {
        toast.warning("⚠️ Suspicious Email Detected!");
      } else {
        toast.success("✅ Safe Email");
      }
    } catch (err) {
      console.error(err);

      const message =
        err.response?.data?.error ||
        err.response?.data?.message ||
        "Server connection failed";

      setError(message);
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  /* ============================================================
     DOWNLOAD PDF
  ============================================================ */

  const downloadReport = async () => {
    if (!result) return;

    try {
      setDownloading(true);

      const pdfResponse = await axios.post(
        `${API_BASE}/download-pdf`,
        result,
        {
          responseType: "blob",
        }
      );

      const fileURL = window.URL.createObjectURL(
        new Blob([pdfResponse.data], {
          type: "application/pdf",
        })
      );

      const link = document.createElement("a");

      link.href = fileURL;

      link.setAttribute(
        "download",
        "email_scan_report.pdf"
      );

      document.body.appendChild(link);

      link.click();

      link.remove();

      window.URL.revokeObjectURL(fileURL);

      toast.success("📄 Email report generated");
    } catch (err) {
      console.error(err);
      toast.error("Unable to generate PDF report");
    } finally {
      setDownloading(false);
    }
  };

  /* ============================================================
     THREAT CLASS
  ============================================================ */

  const getThreatClass = () => {
    if (!result) return "low";

    if (result.threat_level === "HIGH") {
      return "high";
    }

    if (result.threat_level === "MEDIUM") {
      return "medium";
    }

    return "low";
  };

  /* ============================================================
     MODEL RESULTS
     
     These values come from BACKEND.
     Nothing is hard-coded here.
  ============================================================ */

  const modelResults = result?.model_results || [];

  /* ============================================================
     FIND BEST MODEL FOR CURRENT EMAIL
     
     Highest confidence = best model for this particular scan.
  ============================================================ */

  const getBestModel = () => {
    if (!modelResults.length) {
      return null;
    }

    return [...modelResults].sort(
      (a, b) =>
        Number(b.confidence || 0) -
        Number(a.confidence || 0)
    )[0];
  };

  const bestModel = getBestModel();

  /* ============================================================
     MODEL COLOR
  ============================================================ */

  const getModelClass = (name) => {
    if (name === "Logistic Regression") {
      return "model-blue";
    }

    if (name === "Naive Bayes") {
      return "model-purple";
    }

    if (name === "SVM") {
      return "model-cyan";
    }

    if (name === "Random Forest") {
      return "model-green";
    }

    return "model-blue";
  };

  /* ============================================================
     PREDICTION CLASS
  ============================================================ */

  const getPredictionClass = (prediction) => {
    if (!prediction) return "prediction-safe";

    const value = prediction.toLowerCase();

    if (value.includes("phishing")) {
      return "prediction-phishing";
    }

    if (value.includes("suspicious")) {
      return "prediction-suspicious";
    }

    return "prediction-safe";
  };

  /* ============================================================
     PREDICTION ICON
  ============================================================ */

  const getPredictionIcon = (prediction) => {
    if (!prediction) {
      return <FaCheckCircle />;
    }

    const value = prediction.toLowerCase();

    if (value.includes("phishing")) {
      return <FaExclamationTriangle />;
    }

    if (value.includes("suspicious")) {
      return <FaExclamationTriangle />;
    }

    return <FaCheckCircle />;
  };

  /* ============================================================
     MODEL CARDS
  ============================================================ */

  const renderModelCards = () => {
    if (!result) {
      return null;
    }

    if (!modelResults.length) {
      return (
        <section className="model-section">
          <div className="model-section-header">
            <h2>
              <FaBrain />
              ML Model Analysis
            </h2>

            <p>
              Model-wise analysis is not available from
              the server response.
            </p>
          </div>

          <div className="model-api-warning">
            <FaExclamationTriangle />

            <div>
              <strong>Model results not returned</strong>

              <p>
                Your Flask API must return predictions
                and confidence values for all four
                trained models.
              </p>
            </div>
          </div>
        </section>
      );
    }

    return (
      <section className="model-section">

        {/* ==================================================
            HEADER
        ================================================== */}

        <div className="model-section-header">

          <div className="model-title-row">
            <FaBrain />

            <div>
              <h2>ML Model Analysis</h2>

              <p>
                Each trained model analyzed this email
                independently
              </p>
            </div>
          </div>

        </div>

        {/* ==================================================
            BEST MODEL SUMMARY
        ================================================== */}

        {bestModel && (
          <div className="best-model-summary">

            <div className="best-summary-icon">
              <FaStar />
            </div>

            <div className="best-summary-content">

              <span className="best-summary-label">
                BEST MODEL FOR THIS EMAIL
              </span>

              <strong>
                {bestModel.name}
              </strong>

              <p>
                Predicted{" "}
                <b>{bestModel.prediction}</b>{" "}
                with{" "}
                <b>
                  {Number(
                    bestModel.confidence || 0
                  ).toFixed(2)}
                  %
                </b>{" "}
                confidence.
              </p>

            </div>

          </div>
        )}

        {/* ==================================================
            FOUR DYNAMIC MODEL CARDS
        ================================================== */}

        <div className="model-cards">

          {modelResults.map((model, index) => {

            const confidence = Math.min(
              Math.max(
                Number(model.confidence || 0),
                0
              ),
              100
            );

            const isBest =
              bestModel &&
              bestModel.name === model.name;

            return (
              <div
                key={`${model.name}-${index}`}
                className={`model-card ${getModelClass(
                  model.name
                )} ${
                  isBest
                    ? "model-card-best"
                    : ""
                }`}
              >

                {/* BEST BADGE */}

                {isBest && (
                  <div className="best-model-badge">
                    <FaStar />
                    BEST FOR THIS EMAIL
                  </div>
                )}

                {/* ICON */}

                <div className="model-icon">
                  <FaBrain />
                </div>

                {/* MODEL NAME */}

                <h3>{model.name}</h3>

                {/* CURRENT PREDICTION */}

                <div
                  className={`model-prediction ${getPredictionClass(
                    model.prediction
                  )}`}
                >
                  <span className="prediction-icon">
                    {getPredictionIcon(
                      model.prediction
                    )}
                  </span>

                  <div>
                    <small>
                      THIS EMAIL
                    </small>

                    <strong>
                      {model.prediction}
                    </strong>
                  </div>
                </div>

                {/* CONFIDENCE */}

                <div className="confidence-section">

                  <div className="confidence-header">

                    <span>
                      Confidence
                    </span>

                    <strong>
                      {confidence.toFixed(2)}%
                    </strong>

                  </div>

                  <div className="confidence-bar">

                    <div
                      className={`confidence-fill ${getPredictionClass(
                        model.prediction
                      )}`}
                      style={{
                        width: `${confidence}%`,
                      }}
                    />

                  </div>

                </div>

                {/* MODEL STATUS */}

                <div className="model-status">

                  {isBest ? (
                    <>
                      <FaStar />
                      Highest confidence
                    </>
                  ) : (
                    <>
                      <FaChartBar />
                      Model prediction
                    </>
                  )}

                </div>

              </div>
            );
          })}

        </div>

      </section>
    );
  };

  /* ============================================================
     UI
  ============================================================ */

  return (
    <div className="email-analyzer-page">

      {/* ======================================================
          EMAIL ANALYSIS
      ====================================================== */}

      <div className="cyber-card email-analysis-card">

        <div className="card-header">

          <FaEnvelope />

          <div>
            <h2>Email Analysis</h2>

            <p>
              Analyze an email using all trained
              phishing detection models
            </p>
          </div>

        </div>

        <textarea
          rows="8"
          placeholder="Paste email content here..."
          value={emailText}
          onChange={(e) =>
            setEmailText(e.target.value)
          }
        />

        <button
          className="scan-btn"
          onClick={analyzeEmail}
          disabled={loading}
        >
          {loading ? (
            <>
              <span className="loading-spinner" />
              Analyzing Email...
            </>
          ) : (
            <>
              <FaShieldAlt />
              Analyze Email
            </>
          )}
        </button>

        {/* ERROR */}

        {error && (
          <div className="error-box">
            <FaExclamationTriangle />
            {error}
          </div>
        )}

        {/* ==================================================
            EMAIL RESULT
        ================================================== */}

        {result && (
          <div className="result-card">

            {/* DUPLICATE */}

            {result.duplicate && (
              <div className="warning-box">
                ⚠️ {result.message}
              </div>
            )}

            {/* RESULT HEADER */}

            <div className="result-main">

              <div
                className={`large-prediction ${getPredictionClass(
                  result.prediction
                )}`}
              >
                {getPredictionIcon(
                  result.prediction
                )}

                <div>
                  <span>FINAL PREDICTION</span>

                  <strong>
                    {result.prediction}
                  </strong>
                </div>
              </div>

              <div
                className={`threat-badge ${getThreatClass()}`}
              >
                Threat Level:{" "}
                {result.threat_level}
              </div>

            </div>

            {/* RESULT DETAILS */}

            <div className="result-details">

              <div className="result-stat">

                <span>Risk Score</span>

                <strong>
                  {result.risk_score}%
                </strong>

              </div>

              {bestModel && (
                <div className="result-stat">

                  <span>Best Model</span>

                  <strong>
                    {bestModel.name}
                  </strong>

                </div>
              )}

              {bestModel && (
                <div className="result-stat">

                  <span>Model Confidence</span>

                  <strong>
                    {Number(
                      bestModel.confidence || 0
                    ).toFixed(2)}
                    %
                  </strong>

                </div>
              )}

            </div>

            {/* RISK BAR */}

            <div className="risk-bar">

              <div
                className={`risk-fill ${
                  result.threat_level ===
                  "HIGH"
                    ? "risk-high"
                    : result.threat_level ===
                      "MEDIUM"
                    ? "risk-medium"
                    : "risk-low"
                }`}
                style={{
                  width: `${Math.min(
                    Math.max(
                      result.risk_score || 0,
                      0
                    ),
                    100
                  )}%`,
                }}
              />

            </div>

            {/* DETECTION REASONS */}

            <div className="result-section">

              <h4>
                <FaExclamationTriangle />
                Detection Reasons
              </h4>

              <ul>

                {result.reasons &&
                result.reasons.length > 0 ? (
                  result.reasons.map(
                    (reason, index) => (
                      <li key={index}>
                        {reason}
                      </li>
                    )
                  )
                ) : (
                  <li>
                    No suspicious indicators
                    detected.
                  </li>
                )}

              </ul>

            </div>

            {/* PREVENTION */}

            {result.prevention &&
              result.prevention.length > 0 && (
                <div className="result-section">

                  <h4>
                    <FaShieldAlt />
                    Prevention
                  </h4>

                  <ul>

                    {result.prevention.map(
                      (item, index) => (
                        <li key={index}>
                          {item}
                        </li>
                      )
                    )}

                  </ul>

                </div>
              )}

            {/* DOWNLOAD */}

            <button
              className="download-btn"
              onClick={downloadReport}
              disabled={downloading}
            >
              {downloading
                ? "Generating Report..."
                : "📄 Download Email Report"}
            </button>

          </div>
        )}

      </div>

      {/* ======================================================
          DYNAMIC MODEL ANALYSIS
      ====================================================== */}

      {renderModelCards()}

    </div>
  );
}

export default EmailAnalyzer;