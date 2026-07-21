import { useEffect, useState } from "react";


export default function Findings() {
  const [findings, setFindings] = useState<any[]>([]);

  useEffect(() => {
    fetch('http://localhost:3000/findings')
      .then(res => res.json())
      .then(data => setFindings(data));
  }, []);
  console.log("findings", findings);

  if (!findings) {
    return <div>Loading...</div>;
  }

  return (
    <main className="findings  d-flex flex-column justify-content-center">
      <div className="findings-inner container">
        <h1 className="display-3">Findings</h1>
        <table className="table table-striped">
          <thead>
            <tr>
              <th>Package</th>
              <th>Version</th>
              <th>Pattern</th>
              <th>Hook</th>
              <th>Snippet</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding: any) => (
              <tr key={finding.id}>
                <td>{finding.package}</td>
                <td>{finding.version}</td>  
                <td>{finding.pattern}</td>
                <td>{finding.hook}</td>
                <td>{finding.snippet}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </main>
  );
}
