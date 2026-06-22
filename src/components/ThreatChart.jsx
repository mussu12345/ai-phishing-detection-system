import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer
} from "recharts";

function ThreatChart({ stats }) {
  const data = [
    {
      name: "Phishing Detected",
      value: stats.phishing_detected
    },
    {
      name: "Safe Scans",
      value:
        stats.threats_analyzed -
        stats.phishing_detected
    }
  ];

  const COLORS = ["#ff4d4f", "#52c41a"];

  return (
    <div className="chart-card">
      <h2>Threat Analytics</h2>

      <ResponsiveContainer
        width="100%"
        height={300}
      >
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            outerRadius={100}
            dataKey="value"
            label
          >
            {data.map((entry, index) => (
              <Cell
                key={index}
                fill={COLORS[index]}
              />
            ))}
          </Pie>

          <Tooltip />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export default ThreatChart;