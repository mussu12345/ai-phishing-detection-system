function ResultCard({ result }) {
  if (!result) return null;

  const threatClass =
    result.threat_level === "HIGH"
      ? "high"
      : result.threat_level === "MEDIUM"
      ? "medium"
      : "low";

  return (
    <div className="result">

      {/* ========================================= */}
      {/* PREDICTION */}
      {/* ========================================= */}

      <h3>{result.prediction}</h3>

      {/* ========================================= */}
      {/* THREAT LEVEL */}
      {/* ========================================= */}

      {result.threat_level && (
        <p>
          <strong>Threat Level:</strong>{" "}
          {result.threat_level}
        </p>
      )}

      {/* ========================================= */}
      {/* FINAL RISK SCORE */}
      {/* ========================================= */}

      <p>
        <strong>Final Risk Score:</strong>{" "}
        {result.risk_score}%
      </p>

      {/* ========================================= */}
      {/* RISK BAR */}
      {/* ========================================= */}

      <div className="risk-bar">
        <div
          className={`risk-fill risk-${threatClass}`}
          style={{
            width: `${Math.min(
              Math.max(result.risk_score || 0, 0),
              100
            )}%`,
          }}
        />
      </div>

      {/* ========================================= */}
      {/* HYBRID COMPONENTS */}
      {/* ========================================= */}

      {result.components && (
        <div className="hybrid-analysis">

          <h4>Hybrid Risk Analysis</h4>

          <p>
            URL Feature Score:{" "}
            <strong>
              {result.components.url_score}%
            </strong>
          </p>

          <p>
            Domain Analysis Score:{" "}
            <strong>
              {result.components.domain_score}%
            </strong>
          </p>

          <p>
            CTI / IOC Score:{" "}
            <strong>
              {result.components.cti_score}%
            </strong>
          </p>

          {result.components.ml_score !== undefined && (
            <p>
              Machine Learning Score:{" "}
              <strong>
                {result.components.ml_score}%
              </strong>
            </p>
          )}

        </div>
      )}

      {/* ========================================= */}
      {/* CTI / IOC */}
      {/* ========================================= */}

      {result.cti && (
        <div className="cti-analysis">

          <h4>Cyber Threat Intelligence</h4>

          <p>
            <strong>IOC Match:</strong>{" "}
            {result.cti.matched
              ? "Known Threat Found"
              : "No IOC Match"}
          </p>

          {result.cti.matched && (
            <>
              <p>
                <strong>Indicator:</strong>{" "}
                {result.cti.indicator}
              </p>

              <p>
                <strong>Type:</strong>{" "}
                {result.cti.indicator_type}
              </p>

              <p>
                <strong>Threat:</strong>{" "}
                {result.cti.threat_type}
              </p>

              <p>
                <strong>Severity:</strong>{" "}
                {result.cti.severity}
              </p>

              <p>
                <strong>Confidence:</strong>{" "}
                {result.cti.confidence}%
              </p>

              <p>
                <strong>Source:</strong>{" "}
                {result.cti.source}
              </p>
            </>
          )}

        </div>
      )}

      {/* ========================================= */}
      {/* DETECTION REASONS */}
      {/* ========================================= */}

      <h4>Detection Reasons</h4>

      <ul>
        {result.reasons &&
        result.reasons.length > 0 ? (
          result.reasons.map((reason, index) => (
            <li key={index}>
              {reason}
            </li>
          ))
        ) : (
          <li>
            No suspicious indicators detected.
          </li>
        )}
      </ul>

      {/* ========================================= */}
      {/* PREVENTION */}
      {/* ========================================= */}

      {result.prevention &&
        result.prevention.length > 0 && (
          <>
            <h4>Prevention</h4>

            <ul>
              {result.prevention.map(
                (item, index) => (
                  <li key={index}>
                    {item}
                  </li>
                )
              )}
            </ul>
          </>
        )}

    </div>
  );
}

export default ResultCard;