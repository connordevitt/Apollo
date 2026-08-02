import { Link } from "react-router-dom";
import apollo from "../assets/Apollo2.png";

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
          <div className="footer-top">
            <div className="footer-brand">
              <span className="footer-mark" aria-hidden="true">
                <img src={apollo} alt="" />
              </span>
              <div>
                <p className="footer-brand-name">Apollo</p>
                <p className="footer-brand-tagline">
                  An npm registry scanner for supply chain attacks and malware.
                </p>
              </div>
            </div>

            <nav className="footer-nav" aria-label="Footer">
              <div className="footer-nav-group">
                <h2>Scanner</h2>
                <ul>
                  <li>
                    <Link to="/findings">Findings</Link>
                  </li>
                </ul>
              </div>
              <div className="footer-nav-group">
                <h2>Project</h2>
                <ul>
                  <li>
                    <a
                      href="https://github.com/connordevitt/apollo"
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      GitHub
                      <span className="footer-external" aria-hidden="true">
                        ↗
                      </span>
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.gnu.org/licenses/agpl-3.0.html"
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      AGPL-3.0-only
                      <span className="footer-external" aria-hidden="true">
                        ↗
                      </span>
                    </a>
                  </li>
                </ul>
              </div>
            </nav>
          </div>

          <p className="footer-wordmark" aria-hidden="true">
            Apollo
          </p>

          <div className="footer-bottom">
            <p>
              <span aria-hidden="true">©</span> 2026 Apollo · All rights reserved
            </p>
            <p className="footer-meta">Open source · AGPL-3.0-only</p>
          </div>
        </div>
      </footer>
    </>
  );
}

