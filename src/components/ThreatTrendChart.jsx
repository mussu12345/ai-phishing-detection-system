import { useEffect, useState } from "react";
import axios from "axios";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Cell,
  Legend,
} from "recharts";

function ThreatTrendChart() {
  const API_URL = "http://localhost:5000";

  const [data, setData] = useState([
    { name: "Phishing", count: 0 },
    { name: "Safe", count: 0 },
    { name: "Suspicious", count: 0 },
  ]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchChartData = async () => {
    try {
      const response = await axios.get(`${API_URL}/chart-data`);

      console.log("CHART API RESPONSE:", response.data);

      const result = response.data;

      /*
       * Backend returns:
       *
       * [
       *   ["Phishing", 2],
       *   ["Safe", 5],
       *   ["Suspicious", 1]
       * ]
       *
       * Convert that into Recharts format.
       */

      let phishing = 0;
      let safe = 0;
      let suspicious = 0;

      if (Array.isArray(result)) {
        result.forEach((row) => {
          if (!Array.isArray(row)) return;

          const prediction = String(row[0] || "").toLowerCase();
          const count = Number(row[1]) || 0;

          if (prediction === "phishing") {
            phishing = count;
          } else if (prediction === "safe") {
            safe = count;
          } else if (prediction === "suspicious") {
            suspicious = count;
          }
        });
      }

      /*
       * Also support object response if backend is changed later.
       */
      if (!Array.isArray(result) && result) {
        phishing = Number(result.phishing) || 0;
        safe = Number(result.safe) || 0;
        suspicious = Number(result.suspicious) || 0;
      }

      const chartData = [
        {
          name: "Phishing",
          count: phishing,
        },
        {
          name: "Safe",
          count: safe,
        },
        {
          name: "Suspicious",
          count: suspicious,
        },
      ];

      console.log("FINAL CHART DATA:", chartData);

      setData(chartData);
      setError("");
    } catch (err) {
      console.error("CHART DATA ERROR:", err);

      setError(
        err.response?.data?.error ||
          "Unable to load chart data"
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchChartData();

    /*
     * Refresh chart every 3 seconds so that
     * newly scanned URLs appear automatically.
     */
    const interval = setInterval(() => {
      fetchChartData();
    }, 3000);

    return () => {
      clearInterval(interval);
    };
  }, []);

  const colors = {
    Phishing: "#ff4d4f",
    Safe: "#52c41a",
    Suspicious: "#faad14",
  };

  const totalScans = data.reduce(
    (total, item) => total + item.count,
    0
  );

  return (
    <div className="chart-card">
      <h2>Threat Distribution</h2>

      {loading ? (
        <div
          style={{
            height: "350px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          Loading chart...
        </div>
      ) : error ? (
        <div
          style={{
            height: "350px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexDirection: "column",
            gap: "10px",
          }}
        >
          <p>{error}</p>

          <button
            onClick={fetchChartData}
            className="scan-btn"
          >
            Retry
          </button>
        </div>
      ) : totalScans === 0 ? (
        <div
          style={{
            height: "350px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          No scan data available
        </div>
      ) : (
        <ResponsiveContainer
          width="100%"
          height={350}
        >
          <BarChart
            data={data}
            margin={{
              top: 30,
              right: 30,
              left: 20,
              bottom: 20,
            }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#23304d"
            />

            <XAxis
              dataKey="name"
              stroke="#ffffff"
              tick={{
                fill: "#ffffff",
              }}
            />

            <YAxis
              stroke="#ffffff"
              allowDecimals={false}
              tick={{
                fill: "#ffffff",
              }}
              domain={[
                0,
                (dataMax) =>
                  Math.max(dataMax + 1, 1),
              ]}
            />

            <Tooltip
              contentStyle={{
                backgroundColor: "#111827",
                border: "1px solid #334155",
                borderRadius: "8px",
                color: "#ffffff",
              }}
              formatter={(value) => [
                value,
                "Scans",
              ]}
            />

            <Legend />

            <Bar
              dataKey="count"
              name="Number of Scans"
              radius={[10, 10, 0, 0]}
              animationDuration={500}
              label={{
                position: "top",
                fill: "#ffffff",
              }}
            >
              {data.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={colors[entry.name]}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

export default ThreatTrendChart;