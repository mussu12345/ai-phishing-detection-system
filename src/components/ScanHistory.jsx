import { useEffect, useState } from "react";
import { io } from "socket.io-client";
import axios from "axios";
import { FaHistory } from "react-icons/fa";

const socket = io("https://ai-phishing-detection-system3.onrender.com");

function ScanHistory() {
  const [history, setHistory] = useState([]);

  const fetchHistory = async () => {
    try {
      const response = await axios.get(
        "https://ai-phishing-detection-system3.onrender.com/history"
      );

      setHistory(response.data);
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    fetchHistory();

    socket.on("connect", () => {
      console.log("Socket Connected");
    });

    socket.on("new_scan", () => {
      fetchHistory();
    });

    return () => {
      socket.off("new_scan");
    };
  }, []);

  const clearHistory = async () => {
    try {
      await axios.delete(
        "https://ai-phishing-detection-system3.onrender.com/clear-history"
      );

      fetchHistory();
    } catch (error) {
      console.error(error);
    }
  };

  return (
    <div className="history-card">
      <div className="history-header">
        <FaHistory />
        <h2>Recent Threat Activity</h2>
      </div>

      <table className="history-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Scan Type</th>
            <th>Prediction</th>
            <th>Threat Level</th>
            <th>Risk Score</th>
            <th>Timestamp</th>
          </tr>
        </thead>

        <tbody>
          {history.map((item) => (
            <tr key={item[0]}>
              <td>{item[0]}</td>

              <td>
                <span className="type-badge">
                  {item[1]}
                </span>
              </td>

              <td>{item[3]}</td>

              <td>
                <span
                  className={`threat-badge ${
                    item[4] === "HIGH"
                      ? "high"
                      : item[4] === "MEDIUM"
                      ? "medium"
                      : "low"
                  }`}
                >
                  {item[4]}
                </span>
              </td>

              <td>
                <div className="mini-risk">
                  <div
                    className={`mini-fill ${
                      item[4] === "HIGH"
                        ? "risk-high"
                        : item[4] === "MEDIUM"
                        ? "risk-medium"
                        : "risk-low"
                    }`}
                    style={{
                      width: `${item[5]}%`,
                    }}
                  ></div>
                </div>

                <span>{item[5]}%</span>
              </td>

              <td>
                {item[6] || "N/A"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="history-actions">
        <button
          className="export-btn"
          onClick={() =>
            window.open(
              "https://ai-phishing-detection-system3.onrender.com/export-history",
              "_blank"
            )
          }
        >
          📥 Export CSV Report
        </button>

        <button
          className="clear-btn"
          onClick={clearHistory}
        >
          🗑 Clear Scan History
        </button>
      </div>
    </div>
  );
}

export default ScanHistory;