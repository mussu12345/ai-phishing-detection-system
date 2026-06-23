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
  Cell
} from "recharts";

function ThreatTrendChart() {
  const [data, setData] = useState([]);

  useEffect(() => {
    fetchChart();
  }, []);

  const fetchChart = async () => {
    try {
      const response = await axios.get(
        "https://ai-phishing-detection-system3.onrender.com/chart-data"
      );

      const formatted = response.data.map(
        (item) => ({
          name: item[0],
          count: item[1]
        })
      );

      setData(formatted);
    } catch (error) {
      console.error(error);
    }
  };

  const colors = {
    Phishing: "#ff4d4f",
    Safe: "#52c41a",
    Suspicious: "#faad14"
  };

  return (
    <div className="chart-card">
      <h2>Threat Distribution</h2>

      <ResponsiveContainer
        width="100%"
        height={350}
      >
        <BarChart
          data={data}
          margin={{
            top: 20,
            right: 30,
            left: 20,
            bottom: 5
          }}
        >
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="#23304d"
          />

          <XAxis
            dataKey="name"
            stroke="#ffffff"
          />

          <YAxis
            stroke="#ffffff"
          />

          <Tooltip />

          <Bar
            dataKey="count"
            radius={[10, 10, 0, 0]}
            animationDuration={1200}
            label={{
              position: "top",
              fill: "#fff"
            }}
          >
            {data.map((entry, index) => (
              <Cell
                key={index}
                fill={
                  colors[entry.name] ||
                  "#00d4ff"
                }
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default ThreatTrendChart;