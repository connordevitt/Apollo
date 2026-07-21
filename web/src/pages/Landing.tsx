import { Link } from "react-router-dom";

export default function Landing() {
  return (
    <main className="landing ">
      <div className="landing-inner">
        <h1>Apollo</h1>
        <p>
          An npm registry scanner for supply chain attacks and malware.
        </p>
        <div className="d-flex gap-2 justify-content-center">
        <Link to="/findings" className="cta">
          View findings <span aria-hidden="true">→</span>
        </Link>
        </div>
      </div>
    </main>
  );
}
