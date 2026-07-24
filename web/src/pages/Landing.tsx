import { Link } from "react-router-dom";
import apollo from "../assets/apollo2.png";

export default function Landing() {
  return (
    <>
    <main className="landing">
      <div className="landing-inner">
        <div className="landing-copy">
          <h1>Apollo</h1>
          <p className="font-monospace">
            An npm registry scanner for supply chain attacks and malware.
          </p>
          <Link to="/findings" className="cta">
            View findings <span aria-hidden="true">→</span>
          </Link>
        </div>
      </div>
      <div className="landing-visual">
        <img src={apollo} alt="" />
      </div>
    </main>
     <footer className="footer">
     <div className="footer-inner">
       <p className="mb-0">
         <span aria-hidden="true">©</span> 2026 Apollo · All rights reserved · <></>
          <a href="https://github.com/connordevitt/apollo" target="_blank" rel="noopener noreferrer">GitHub</a> · 
         AGPL-3.0-only
       </p>
        </div>
      </footer>
    </>
  );
}

