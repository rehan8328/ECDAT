import { useEffect, useRef } from "react";
import { ArcElement, Chart, DoughnutController } from "chart.js";
import { scoreColor, severityColors, severityOrder, type Severity } from "./severityColors";

Chart.register(ArcElement, DoughnutController);

export function QuantumReadinessGauge({ score }: { score: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const normalized = Math.max(0, Math.min(100, score));

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const chart = new Chart(canvas, {
      type: "doughnut",
      data: { datasets: [{ data: [normalized, 100 - normalized], backgroundColor: [scoreColor(normalized), "#dce3eb"], borderWidth: 0, spacing: 1 }] },
      options: { animation: false, cutout: "78%", rotation: -90, circumference: 360, responsive: true, maintainAspectRatio: true, plugins: { legend: { display: false }, tooltip: { enabled: false } } },
    });
    return () => chart.destroy();
  }, [normalized]);

  return <div className="readiness-gauge" aria-label={`Quantum readiness ${normalized} out of 100`}><canvas ref={canvasRef} /><div><b>{normalized}</b><small>/100</small></div></div>;
}

export function SeverityStack({ counts }: { counts: Record<Severity, number> }) {
  const total = severityOrder.reduce((sum, level) => sum + counts[level], 0);
  const active = severityOrder.filter((level) => counts[level] > 0);
  return <div className="severity-stack" aria-label="Finding severity distribution"><div className="severity-track">{active.map((level, index) => <span key={level} className={index === 0 ? "first" : index === active.length - 1 ? "last" : ""} style={{ width: `${(counts[level] / Math.max(total, 1)) * 100}%`, backgroundColor: severityColors[level] }} />)}</div><div className="severity-legend">{active.map((level) => <span key={level}><i style={{ backgroundColor: severityColors[level] }} />{level}<b>{counts[level]}</b></span>)}</div></div>;
}

export function MoscaTimeline({ lifetimeYears, migrationYears, horizonYears }: { lifetimeYears: number; migrationYears: number; horizonYears: number }) {
  const totalRequired = lifetimeYears + migrationYears;
  const scale = Math.max(totalRequired, horizonYears, 1);
  const safeWidth = `${(Math.min(totalRequired, horizonYears) / scale) * 100}%`;
  const overrunWidth = `${(Math.max(totalRequired - horizonYears, 0) / scale) * 100}%`;
  const markerPosition = `${(horizonYears / scale) * 100}%`;
  const overrun = totalRequired > horizonYears;
  return <div className="mosca-timeline" aria-label={`Mosca timeline: ${totalRequired} years required against ${horizonYears} year threat horizon`}><div className="timeline-labels"><span>Today</span><span>Lifetime + migration ({totalRequired}y)</span></div><div className="timeline-track"><i className="timeline-safe" style={{ width: safeWidth }} />{overrun && <i className="timeline-overrun" style={{ width: overrunWidth }} />}<b className={overrun ? "at-risk" : "safe"} style={{ left: markerPosition }}>Threat horizon ({horizonYears}y)</b></div><p>{overrun ? `${totalRequired - horizonYears} year planning overrun` : `${horizonYears - totalRequired} year planning margin`}</p></div>;
}

export function RiskScoreBar({ score }: { score: number }) {
  const normalized = Math.max(0, Math.min(100, score));
  const riskColor = normalized >= 75 ? severityColors.critical : normalized >= 50 ? severityColors.high : normalized >= 25 ? severityColors.medium : severityColors.low;
  return <span className="risk-score-bar" aria-label={`Risk score ${normalized} out of 100`} title={`Risk score ${normalized} out of 100`}><i style={{ width: `${normalized}%`, backgroundColor: riskColor }} /></span>;
}
