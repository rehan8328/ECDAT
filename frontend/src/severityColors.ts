export type Severity = "critical" | "high" | "medium" | "low";

export const severityOrder: Severity[] = ["critical", "high", "medium", "low"];

export const severityColors: Record<Severity, string> = {
  critical: "#d03b3b",
  high: "#eb6834",
  medium: "#eda100",
  low: "#639922",
};

export function scoreColor(score: number): string {
  if (score <= 40) return severityColors.critical;
  if (score <= 70) return severityColors.high;
  return severityColors.low;
}
