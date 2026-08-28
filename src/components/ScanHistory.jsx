import { useEffect, useState, useCallback } from "react";
import { io } from "socket.io-client";
import axios from "axios";
import { FaHistory } from "react-icons/fa";

const API_URL =
  "http://127.0.0.1:5000";

const socket = io(API_URL, {
  transports: ["websocket", "polling"],
});

function ScanHistory() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  // ============================================================
  // FETCH HISTORY
  // ============================================================
  const fetchHistory = useCallback(async () => {
    try {
      setLoading(true);

      const response = await axios.get(`${API_URL}/history`, {
        headers: {
          "Cache-Control": "no-cache",
          Pragma: "no-cache",
        },
        params: {
          t: Date.now(),
        },
      });

      if (Array.isArray(response.data)) {
        setHistory(response.data);
      } else {
        console.error("Invalid history response:", response.data);
        setHistory([]);
      }
    } catch (error) {
      console.error("History API Error:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  // ============================================================
  // INITIAL LOAD + AUTO REFRESH + SOCKET
  // ============================================================
  useEffect(() => {
    // Fetch immediately
    fetchHistory();

    // ----------------------------------------------------------
    // Refresh history every 2 seconds
    // This makes sure new scans appear even if Socket.IO
    // event is not received.
    // ----------------------------------------------------------
    const interval = setInterval(() => {
      fetchHistory();
    }, 2000);

    // ----------------------------------------------------------
    // Socket.IO connection
    // ----------------------------------------------------------
    const handleConnect = () => {
      console.log("Socket Connected:", socket.id);
    };

    const handleNewScan = () => {
      console.log("New scan received");
      fetchHistory();
    };

    socket.on("connect", handleConnect);
    socket.on("new_scan", handleNewScan);

    // ----------------------------------------------------------
    // Cleanup
    // ----------------------------------------------------------
    return () => {
      clearInterval(interval);

      socket.off("connect", handleConnect);
      socket.off("new_scan", handleNewScan);
    };
  }, [fetchHistory]);

  // ============================================================
  // CLEAR HISTORY
  // ============================================================
  const clearHistory = async () => {
    const confirmClear = window.confirm(
      "Are you sure you want to clear all scan history?"
    );

    if (!confirmClear) {
      return;
    }

    try {
      await axios.delete(`${API_URL}/clear-history`);

      // Immediately update UI
      setHistory([]);

      // Fetch again to confirm backend state
      await fetchHistory();

      console.log("Scan history cleared");
    } catch (error) {
      console.error("Clear History Error:", error);
      alert("Unable to clear scan history.");
    }
  };

  // ============================================================
  // EXPORT HISTORY
  // ============================================================
  const exportHistory = () => {
    window.open(
      `${API_URL}/export-history`,
      "_blank",
      "noopener,noreferrer"
    );
  };

  // ============================================================
  // GET RISK CLASS
  // ============================================================
  const getThreatClass = (threatLevel) => {
    if (threatLevel === "HIGH") {
      return "high";
    }

    if (threatLevel === "MEDIUM") {
      return "medium";
    }

    return "low";
  };

  // ============================================================
  // RENDER
  // ============================================================
  return (
    <div className="history-card">

      {/* ========================================================
          HEADER
          ======================================================== */}
      <div className="history-header">
        <FaHistory />
        <h2>Recent Threat Activity</h2>

        {loading && (
          <span
            style={{
              marginLeft: "auto",
              fontSize: "11px",
              color: "#64748b",
            }}
          >
            Updating...
          </span>
        )}
      </div>

      {/* ========================================================
          TABLE
          ======================================================== */}
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

          {history.length === 0 ? (

            <tr>
              <td
                colSpan="6"
                style={{
                  textAlign: "center",
                  padding: "25px",
                  color: "#718198",
                }}
              >
                No scan history available
              </td>
            </tr>

          ) : (

            history.map((item, index) => {

              /*
                Expected backend structure:

                item[0] = ID
                item[1] = Scan Type
                item[3] = Prediction
                item[4] = Threat Level
                item[5] = Risk Score
                item[6] = Timestamp
              */

              const id = item[0] ?? index + 1;
              const scanType = item[1] ?? "N/A";
              const prediction = item[3] ?? "N/A";
              const threatLevel = item[4] ?? "LOW";
              const riskScore = Number(item[5]) || 0;
              const timestamp = item[6] ?? "N/A";

              return (
                <tr key={`${id}-${timestamp}-${index}`}>

                  {/* ID */}
                  <td>
                    {id}
                  </td>

                  {/* SCAN TYPE */}
                  <td>
                    <span className="type-badge">
                      {scanType}
                    </span>
                  </td>

                  {/* PREDICTION */}
                  <td>
                    {prediction}
                  </td>

                  {/* THREAT LEVEL */}
                  <td>
                    <span
                      className={`threat-badge ${getThreatClass(
                        threatLevel
                      )}`}
                    >
                      {threatLevel}
                    </span>
                  </td>

                  {/* RISK SCORE */}
                  <td>

                    <div className="mini-risk">

                      <div
                        className={`mini-fill ${
                          threatLevel === "HIGH"
                            ? "risk-high"
                            : threatLevel === "MEDIUM"
                            ? "risk-medium"
                            : "risk-low"
                        }`}
                        style={{
                          width: `${Math.min(
                            Math.max(riskScore, 0),
                            100
                          )}%`,
                        }}
                      ></div>

                    </div>

                    <span>
                      {riskScore}%
                    </span>

                  </td>

                  {/* TIMESTAMP */}
                  <td>
                    {timestamp}
                  </td>

                </tr>
              );
            })

          )}

        </tbody>

      </table>

      {/* ========================================================
          ACTION BUTTONS
          ======================================================== */}
      <div className="history-actions">

        {/* EXPORT */}
        <button
          className="export-btn"
          onClick={exportHistory}
        >
          📥 Export CSV Report
        </button>

        {/* CLEAR */}
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