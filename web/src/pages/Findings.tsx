import { useEffect, useState, useMemo } from "react";
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

  const [sortConfig, setSortConfig] = useState<{ key: keyof Finding; direction: 'asc' | 'desc' } | null>(null);

  useEffect(() => {
    fetch("http://localhost:3000/findings")
      .then((res) => res.json())
      .then((data) => setFindings(data))
      .catch((err) => console.error("fetch failed", err));
  }, []);

  const sortedFindings = useMemo(() => {
    const results = [...(findings ?? [])];

    if (sortConfig) {
      results.sort((a, b) => {
        const valueA = a[sortConfig.key];
        const valueB = b[sortConfig.key];

        if (valueA < valueB) { 
          return sortConfig.direction === 'asc' ? -1 : 1;
        }
        if (valueA > valueB) {
          return sortConfig.direction === 'asc' ? 1 : -1;
        }
        return 0;
      });
    }
    return results;
  }, [findings, sortConfig]);

  const requestSort = (key: keyof Finding) => {
    setSortConfig((current) => ({
      key,
      direction:
        current?.key === key && current?.direction === "asc" ? "desc" : "asc",
    }));
  };

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
                <th onClick={() => requestSort("severity")}>Severity</th>
                <th onClick={() => requestSort("package")}>Package</th>
                <th onClick={() => requestSort("version")}>Version</th>
                <th onClick={() => requestSort("pattern")}>Pattern</th>
                <th onClick={() => requestSort("snippet")}>Snippet</th>
              </tr>
            </thead>
            <tbody>
              {sortedFindings.map((finding) => (
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
