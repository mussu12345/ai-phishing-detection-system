function ResultCard({ result }) {
  if (!result) return null;

  return (
    <div className="result">
      <h3>{result.prediction}</h3>

      <p>
        Risk Score:
        {result.risk_score}%
      </p>

      <ul>
        {result.reasons.map((reason, index) => (
          <li key={index}>{reason}</li>
        ))}
      </ul>
    </div>
  );
}

export default ResultCard;