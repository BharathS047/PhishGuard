import React from "react";
import { Link } from "react-router-dom";
import Summary from "../summary/Summary";
import "./Head.css";

function Head() {
  return (
    <div className="home-page">
      {/* ── Hero Section ── */}
      <div className="hero-section">
        <div className="hero-content text-center">
          <div className="max-w">
            <div className="glow-orb"></div>
            <h1 className="main-title text-gradient-cyan">PhishGuard</h1>
            <p className="hero-description mb-4">
              Next-Generation Threat Intelligence
            </p>
            <p className="hero-subtitle mb-5">
              Protect your digital workspace with an advanced, multi-layered detection engine.
              PhishGuard combines machine learning, real-time reputation analysis, and heuristic
              scanning to identify malicious URLs and socially engineered emails before they cause harm.
            </p>

            <div className="hero-stats flex justify-center gap-4 mt-4 mb-5">
              <div className="stat-badge glass-panel">
                ML-Powered
              </div>
              <div className="stat-badge glass-panel">
                Real-Time Analysis
              </div>
              <div className="stat-badge glass-panel">
                Global Threat Intel
              </div>
            </div>

            <div className="hero-actions flex justify-center gap-8 mt-8">
              <Link to="/checkurl" className="cyber-btn cyber-btn-primary">
                Analyze URL
              </Link>
              <Link to="/email-analysis" className="cyber-btn" style={{ marginLeft: '1rem' }}>
                Scan Email
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* ── How It Works Section ── */}
      <div className="info-section relative">
        <h2 className="section-heading text-center mb-5">Detection Engine</h2>

        <div className="process-grid">
          <div className="process-step glass-panel">
            <div className="step-number text-gradient-cyan">01</div>
            <h3 className="step-title">URL Extraction</h3>
            <p>We extract and analyze 15 distinct structural features from any URL, identifying obfuscation techniques, hidden iframes, and typosquatting attempts.</p>
            <div className="step-glow"></div>
          </div>

          <div className="process-step glass-panel">
            <div className="step-number text-gradient-cyan">02</div>
            <h3 className="step-title">Reputation Sync</h3>
            <p>URLs are cross-referenced against global threat intelligence networks including Google Safe Browsing and VirusTotal in real-time.</p>
            <div className="step-glow"></div>
          </div>

          <div className="process-step glass-panel">
            <div className="step-number text-gradient-cyan">03</div>
            <h3 className="step-title">ML Inference</h3>
            <p>For zero-day threats not yet in databases, our XGBoost classifier predicts malicious intent based on patterns learned from thousands of known attacks.</p>
            <div className="step-glow"></div>
          </div>

          <div className="process-step glass-panel">
            <div className="step-number text-gradient-cyan">04</div>
            <h3 className="step-title">Semantic Analysis</h3>
            <p>We look beyond the link. PhishGuard analyzes email headers for SPF/DKIM spoofing and scans the body for social engineering urgency.</p>
            <div className="step-glow"></div>
          </div>
        </div>
      </div>

      {/* ── Capabilities Highlights ── */}
      <div className="info-section">
        <Summary />
      </div>
    </div>
  );
}

export default Head;
