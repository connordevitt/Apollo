import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

type Finding = {
  package: string;
  version: string;
  hook: string;
  pattern: string;
  snippet: string;
  line: number;
  severity: string;
  confidence: string;
  score: number;
};

function severityClass(severity: string) {
  switch (severity) {
    case "critical":
      return "text-bg-danger";
    case "high":
      return "text-bg-warning";
    case "medium":
      return "text-bg-info";
    default:
      return "text-bg-secondary";
  }
}

export default function Findings() {
  const [findings, setFindings] = useState<Finding[] | null>(null);

  useEffect(() => {
    fetch("http://localhost:3000/findings")
      .then((res) => res.json())
      .then((data) => setFindings(data))
      .catch((err) => console.error("fetch failed", err));
  }, []);

  if (findings === null) {
    return (
      <main className="findings">
        <div className="findings-inner">
          <p className="text-muted mb-0">Loading…</p>
        </div>
      </main>
    );
  }

  return (
    <main className="findings">
      <div className="findings-inner">
        <Link to="/" className="findings-back">
          ← Apollo
        </Link>
        <h1>Findings</h1>
        <p className="findings-meta">{findings.length} results</p>

        <div className="table-responsive">
          <table className="table table-sm table-borderless table-hover align-middle findings-table">
            <thead>
              <tr className="small text-uppercase text-muted">
                <th>Severity</th>
                <th>Package</th>
                <th>Version</th>
                <th>Pattern</th>
                <th>Snippet</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr
                  key={`${finding.package}-${finding.version}-${finding.hook}-${finding.line}-${finding.pattern}`}
                >
                  <td>
                    <span
                      className={`badge rounded-pill ${severityClass(finding.severity)}`}
                    >
                      {finding.severity}
                    </span>
                  </td>
                  <td className="fw-semibold">{finding.package}</td>
                  <td className="text-muted small">{finding.version}</td>
                  <td className="small">{finding.pattern}</td>
                  <td
                    className="small font-monospace text-truncate findings-snippet"
                    title={finding.snippet}
                  >
                    {finding.snippet}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  );
}
