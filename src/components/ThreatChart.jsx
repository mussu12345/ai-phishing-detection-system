
import { useEffect, useState } from "react";
import axios from "axios";

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";


const API_URL =
  "https://ai-phishing-detection-system3.onrender.com";


function ThreatChart() {

  const [stats, setStats] = useState({
    threats_analyzed: 0,
    phishing_detected: 0,
    safe_scans: 0,
    suspicious_scans: 0,
  });


  const fetchStats = async () => {

    try {

      const response = await axios.get(
        `${API_URL}/stats?t=${Date.now()}`
      );

      console.log(
        "========== PIE STATS =========="
      );

      console.log(response.data);

      console.log(
        "==============================="
      );


      setStats(response.data);

    } catch (error) {

      console.error(
        "PIE STATS ERROR:",
        error
      );

    }

  };


  useEffect(() => {

    fetchStats();

    const interval = setInterval(
      fetchStats,
      3000
    );

    return () => {
      clearInterval(interval);
    };

  }, []);


  const phishing =
    Number(stats.phishing_detected) || 0;

  const safe =
    Number(stats.safe_scans) || 0;

  const suspicious =
    Number(stats.suspicious_scans) || 0;

  const total =
    Number(stats.threats_analyzed) || 0;


  const data = [
    {
      name: "Phishing Detected",
      value: phishing,
    },
    {
      name: "Safe Scans",
      value: safe,
    },
    {
      name: "Suspicious",
      value: suspicious,
    },
  ].filter(
    (item) => item.value > 0
  );


  const COLORS = [
    "#ff4d4f",
    "#52c41a",
    "#faad14",
  ];


  return (

    <div className="chart-card">

      <h2>
        Threat Analytics
      </h2>


      {total === 0 ? (

        <div
          style={{
            height: "350px",
            display: "flex",
            flexDirection: "column",
            justifyContent: "center",
            alignItems: "center",
            color: "white",
          }}
        >

          <div
            style={{
              fontSize: "50px",
              marginBottom: "10px",
            }}
          >
            📊
          </div>

          <div
            style={{
              fontSize: "20px",
              fontWeight: "600",
            }}
          >
            No scans yet
          </div>

        </div>

      ) : (

        <ResponsiveContainer
          width="100%"
          height={350}
        >

          <PieChart>

            <Pie
              data={data}
              cx="50%"
              cy="45%"
              innerRadius={65}
              outerRadius={110}
              paddingAngle={4}
              dataKey="value"
              nameKey="name"
              label={({
                name,
                value,
              }) => `${name}: ${value}`}
            >

              {data.map(
                (entry, index) => (

                  <Cell
                    key={
                      `cell-${index}`
                    }
                    fill={
                      COLORS[index]
                    }
                  />

                )
              )}

            </Pie>


            <Tooltip />


            <Legend
              verticalAlign="bottom"
              height={40}
            />

          </PieChart>

        </ResponsiveContainer>

      )}

    </div>

  );
}


export default ThreatChart;

