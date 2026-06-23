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

  useEffect(() => {
    fetchStats();

    const interval = setInterval(() => {
      fetchStats();
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard">
      <div className="header">
        <FaShieldAlt className="shield-icon" />
        <div>
          <h1>AI Phishing Detection System</h1>
          <p>Real-Time Threat Intelligence & Risk Analysis</p>
        </div>
      </div>

      <div className="stats">
        <div className="stat-card">
          <h3>Threats Analyzed</h3>
          <span>{stats.threats_analyzed}</span>
        </div>

        <div className="stat-card">
          <h3>Phishing Detected</h3>
          <span>{stats.phishing_detected}</span>
        </div>

        <div className="stat-card">
          <h3>Detection Accuracy</h3>
          <span>{stats.accuracy}%</span>
        </div>
      </div>

      {/* Pie Chart */}
      <ThreatChart stats={stats} />

      {/* Bar Chart */}
      <ThreatTrendChart />

      <div className="analyzer-grid">
        <EmailAnalyzer />
        <UrlAnalyzer />
      </div>

      <ScanHistory />

      {/* Footer */}
      {/* Professional Footer */}
<div className="dashboard-footer">
  <div className="footer-content">

    <h3>AI Phishing Detection & Prevention System</h3>

    <p className="footer-tagline">
      Securing Digital Communication Through Artificial Intelligence & Machine Learning
    </p>

    <div className="footer-info">

      <div className="footer-item">
        <span className="footer-label">Developer</span>
        <span className="footer-value">Muskan Mubarak</span>
      </div>

      <div className="footer-item">
        <span className="footer-label">Email</span>
        <span className="footer-value">
          muskanmubarak19@gmail.com
        </span>
      </div>

      <div className="footer-item">
        <span className="footer-label">Contact</span>
        <span className="footer-value">
          +91 123456789
        </span>
      </div>

    </div>

    <div className="footer-divider"></div>

    <p className="footer-copy">
      © 2026 AI Phishing Detection System | Built with React, Flask,
      Machine Learning, Cybersecurity Analytics & Real-Time Threat Monitoring
    </p>

  </div>
</div>
    </div>
  );
}

export default Dashboard;