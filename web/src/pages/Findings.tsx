import { useEffect, useState, useMemo } from "react";
import { Link } from "react-router-dom";

type Severity = "critical" | "high" | "medium" | "low";

type Finding = {
  package: string;
  version: string;
  hook: string;
  pattern: string;
  snippet: string;
  line: number;
  severity: Severity;
  confidence: string;
  score: number;
  flaggedAt?: string;
};

type SortConfig = {
  key: keyof Finding;
  direction: "asc" | "desc";
};

const severityOrder: Record<Severity, number> = {
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
};

const severityFilters: Array<Severity | "all"> = [
  "all",
  "critical",
  "high",
  "medium",
  "low",
];

export default function Findings() {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [sortConfig, setSortConfig] = useState<SortConfig | null>(null);

  useEffect(() => {
    fetch("http://localhost:3000/findings")
      .then((res) => {
        if (!res.ok) {
          throw new Error(`API returned ${res.status}`);
        }
        return res.json();
      })
      .then((data) => setFindings(data))
      .catch((err: Error) => {
        console.error("fetch failed", err);
        setError("Findings could not be loaded. Check that the Apollo API is running.");
      });
  }, []);

  const counts = useMemo(() => {
    const next: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    for (const finding of findings ?? []) {
      next[finding.severity]++;
    }

    return next;
  }, [findings]);

  const sortedFindings = useMemo(() => {
    const results = (findings ?? []).filter(
      (finding) => severityFilter === "all" || finding.severity === severityFilter,
    );

    if (sortConfig) {
      results.sort((a, b) => {
        const valueA =
          sortConfig.key === "severity"
            ? severityOrder[a.severity]
            : (a[sortConfig.key] ?? "");
        const valueB =
          sortConfig.key === "severity"
            ? severityOrder[b.severity]
            : (b[sortConfig.key] ?? "");

        if (valueA < valueB) {
          return sortConfig.direction === "asc" ? -1 : 1;
        }
        if (valueA > valueB) {
          return sortConfig.direction === "asc" ? 1 : -1;
        }
        return 0;
      });
    }
    return results;
  }, [findings, severityFilter, sortConfig]);

  const requestSort = (key: keyof Finding) => {
    setSortConfig((current) => ({
      key,
      direction:
        current?.key === key && current?.direction === "asc" ? "desc" : "asc",
    }));
  };

  const sortLabel = (key: keyof Finding) =>
    sortConfig?.key === key
      ? sortConfig.direction === "asc"
        ? " ↑"
        : " ↓"
      : "";

  if (error) {
    return (
      <main className="findings">
        <div className="findings-inner">
          <Link to="/" className="findings-back">
            ← Apollo
          </Link>
          <div className="findings-state" role="alert">
            <span className="findings-state-mark">!</span>
            <div>
              <h1>Connection interrupted</h1>
              <p>{error}</p>
            </div>
          </div>
        </div>
      </main>
    );
  }

  if (findings === null) {
    return (
      <main className="findings">
        <div className="findings-inner">
          <p className="findings-loading">
            <span aria-hidden="true" />
            Reading the registry ledger…
          </p>
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
        <header className="findings-header">
          <div>
            <p className="findings-eyebrow">Registry intelligence</p>
            <h1>Findings</h1>
          </div>
          <div className="findings-total">
            <strong>{findings.length}</strong>
            <span>flagged {findings.length === 1 ? "finding" : "findings"}</span>
          </div>
        </header>

        <nav className="findings-filters" aria-label="Filter findings by severity">
          {severityFilters.map((severity) => {
            const count =
              severity === "all" ? findings.length : counts[severity];
            return (
              <button
                className={severityFilter === severity ? "is-active" : ""}
                key={severity}
                type="button"
                onClick={() => setSeverityFilter(severity)}
                aria-pressed={severityFilter === severity}
              >
                <span>{severity}</span>
                <strong>{count}</strong>
              </button>
            );
          })}
        </nav>

        <div className="findings-ledger table-responsive">
          <table className="findings-table">
            <thead>
              <tr>
                <th>
                  <button type="button" onClick={() => requestSort("severity")}>
                    Severity{sortLabel("severity")}
                  </button>
                </th>
                <th>
                  <button type="button" onClick={() => requestSort("package")}>
                    Package / location{sortLabel("package")}
                  </button>
                </th>
                <th>
                  <button type="button" onClick={() => requestSort("pattern")}>
                    Detection{sortLabel("pattern")}
                  </button>
                </th>
                <th>Evidence</th>
                <th>
                  <button type="button" onClick={() => requestSort("flaggedAt")}>
                    Flagged{sortLabel("flaggedAt")}
                  </button>
                </th>
              </tr>
            </thead>
            <tbody>
              {sortedFindings.length === 0 ? (
                <tr>
                  <td className="findings-empty" colSpan={5}>
                    No {severityFilter} findings in the ledger.
                  </td>
                </tr>
              ) : sortedFindings.map((finding) => (
                <tr
                  className={`finding-row finding-row--${finding.severity}`}
                  key={`${finding.package}-${finding.version}-${finding.hook}-${finding.line}-${finding.pattern}`}
                >
                  <td>
                    <span className={`severity-badge severity-badge--${finding.severity}`}>
                      {finding.severity}
                    </span>
                  </td>
                  <td>
                    <strong className="finding-package">{finding.package}</strong>
                    <span className="finding-location">
                      {finding.version} · {finding.hook}
                      {finding.line != null ? `:${finding.line}` : ""}
                    </span>
                  </td>
                  <td>
                    <span className="finding-pattern">{finding.pattern}</span>
                    <span className="finding-confidence">
                      {finding.confidence} confidence
                    </span>
                  </td>
                  <td>
                    <code className="findings-snippet" title={finding.snippet}>
                      {finding.snippet}
                    </code>
                  </td>
                  <td>
                    {finding.flaggedAt ? (
                      <time className="finding-date fw-bold fs-6">{finding.flaggedAt}</time>
                    ) : (
                      <span className="finding-date finding-date--missing">—</span>
                    )}
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
