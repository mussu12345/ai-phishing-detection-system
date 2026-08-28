import { useEffect, useState } from "react";
import axios from "axios";

import EmailAnalyzer from "../components/EmailAnalyzer";
import UrlAnalyzer from "../components/UrlAnalyzer";
import ScanHistory from "../components/ScanHistory";
import ThreatChart from "../components/ThreatChart";
import ThreatTrendChart from "../components/ThreatTrendChart";

import { FaShieldAlt } from "react-icons/fa";

function Dashboard() {
  const [stats, setStats] = useState({
    threats_analyzed: 0,
    phishing_detected: 0,
    accuracy: 0,
  });

  /* ============================================================
     FETCH DASHBOARD STATISTICS
     ============================================================ */

  const fetchStats = async () => {
    try {
      const response = await axios.get(
        "https://ai-phishing-detection-system3.onrender.com/stats"
      );

      setStats(response.data);
    } catch (error) {
      console.error("Stats API Error:", error);
    }
  };

  /* ============================================================
     AUTO REFRESH STATISTICS
     ============================================================ */

  useEffect(() => {
    fetchStats();

    const interval = setInterval(() => {
      fetchStats();
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  /* ============================================================
     DASHBOARD
     ============================================================ */

  return (
    <div className="dashboard">

      {/* ========================================================
          MAIN HEADER
          ======================================================== */}

      <div className="header">

        <div className="header-content">

          <div className="header-icon">
            <FaShieldAlt />
          </div>

          <h1>
            AI Phishing Detection System
          </h1>

          <p>
            Real-Time Threat Intelligence &amp; Risk Analysis
          </p>

        </div>

      </div>

      {/* ========================================================
          STATISTICS
          ======================================================== */}

      <div className="stats">

        <div className="stat-card">

          <h3>
            Threats Analyzed
          </h3>

          <span>
            {stats.threats_analyzed}
          </span>

        </div>


        <div className="stat-card">

          <h3>
            Phishing Detected
          </h3>

          <span>
            {stats.phishing_detected}
          </span>

        </div>


        <div className="stat-card">

          <h3>
            Detection Accuracy
          </h3>

          <span>
            {stats.accuracy}%
          </span>

        </div>

      </div>

      {/* ========================================================
          THREAT ANALYTICS
          ======================================================== */}

      <ThreatChart
        stats={stats}
      />

      {/* ========================================================
          THREAT TREND
          ======================================================== */}

      <ThreatTrendChart />

      {/* ========================================================
          EMAIL + URL ANALYZERS
          ======================================================== */}

      <div className="analyzer-grid">

        <EmailAnalyzer />

        <UrlAnalyzer />

      </div>

      {/* ========================================================
          SCAN HISTORY
          ======================================================== */}

      <ScanHistory />

      {/* ========================================================
          FOOTER
          ======================================================== */}

      <footer className="dashboard-footer">

        <div className="footer-content">

          <h3>
            AI Phishing Detection &amp; Prevention System
          </h3>

          <p className="footer-tagline">
            Securing Digital Communication Through
            Artificial Intelligence &amp; Machine Learning
          </p>


          <div className="footer-info">

          </div>


          <div className="footer-divider"></div>


          <p className="footer-copy">
            © 2026 AI Phishing Detection System | Built with
            React, Flask, Machine Learning, Cybersecurity
            Analytics &amp; Real-Time Threat Monitoring
          </p>

        </div>

      </footer>

    </div>
  );
}

export default Dashboard;