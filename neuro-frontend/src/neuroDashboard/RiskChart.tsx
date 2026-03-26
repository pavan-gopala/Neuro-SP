import { useState, useEffect, useRef } from 'react'
import * as d3 from 'd3'

// --- D3 Chart Component ---
const RiskChart = ({ score }: { score: number }) => {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove(); // Clear previous

    const width = 300;
    const height = 20;
    const fillWidth = (score / 100) * width;

    // Background bar
    svg.append("rect")
      .attr("width", width)
      .attr("height", height)
      .attr("fill", "#333")
      .attr("rx", 4);

    // Risk bar (Animated)
    svg.append("rect")
      .attr("width", 0)
      .attr("height", height)
      .attr("fill", score > 70 ? "#ff3333" : "#00ff00")
      .attr("rx", 4)
      .transition()
      .duration(1000)
      .attr("width", fillWidth);
  }, [score]);

  return <svg ref={svgRef} width="300" height="20"></svg>;
};

// --- Main App ---
function RiskChartComponent() {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<any>(null);

  const triggerScan = async () => {
    setLoading(true);
    try {
      const response = await fetch('https://turbo-robot-4rp45r5xprv257j6-8080.app.github.dev/api/v1/sentinel/scan?target=README.md');
      const result = await response.json();
      setData(result);
    } catch (err) {
      console.error("Scan failed", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="dashboard">
      <header className="ibm-banner">NEURO-SP</header>
      
      <div className="main-layout">
        <div className="controls">
          <button onClick={triggerScan} disabled={loading} className="ibm-btn">
            {loading ? "SCANNING..." : "RUN NEURAL CHECK"}
          </button>
        </div>

        {data && (
          <div className="results-box fade-in">
            <h3>Threat Analysis: {data.target}</h3>
            <div className="chart-container">
              <span>Risk Probability:</span>
              <RiskChart score={data.status === 'success' ? 85 : 0} />
              <span className="score-text">85%</span>
            </div>
            <pre className="terminal-out">{data.result}</pre>
          </div>
        )}
      </div>
    </div>
  );
}

export default RiskChartComponent;