import axios from "axios";
import React, { useState } from "react";
import "./CheckUrl.css";

function CheckUrl() {
  const [inputUrl, setInputUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showResults, setShowResults] = useState(false);
  const [resInfo, setResInfo] = useState(null);

  /* eslint-disable */
  const HTTP_URL_VALIDATOR_REGEX =
    /(http(s)?:\/\/.)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)/g;

  const checkLink = (string) => string.match(HTTP_URL_VALIDATOR_REGEX);

  const checkUrlHandler = () => {
    setError("");
    setShowResults(false);

    if (!inputUrl) {
      setError("Please enter a URL");
      return;
    }

    const formattedUrl =
      inputUrl.startsWith("http://") || inputUrl.startsWith("https://")
        ? inputUrl
        : `https://${inputUrl}`;

    if (checkLink(formattedUrl)) {
      setLoading(true);
      const apiUrl = process.env.REACT_APP_API_URL || "http://localhost:8000";
      axios
        .get(`${apiUrl}/api/?url=${encodeURIComponent(formattedUrl)}`)
        .then((res) => {
          setResInfo(res.data);
          setLoading(false);
          setShowResults(true);
        })
        .catch(() => {
          setLoading(false);
          setError(
            "Error connecting to the server. Please make sure the backend is running."
          );
        });
    } else {
      setError("Please enter a valid URL");
      setLoading(false);
    }
  };

  const loadExampleUrl = () => setInputUrl("https://www.google.com");

  // ── Feature-name mapping ──
  const featureNames = [
    { key: "having_ip_address", label: "IP Address in URL", desc: "URL uses an IP address instead of a domain name", bad: 1 },
    { key: "long_url", label: "Abnormally Long URL", desc: "URL length exceeds normal expectations", bad: 1 },
    { key: "shortening_service", label: "URL Shortener", desc: "URL goes through a shortening service (bit.ly, tinyurl, etc.)", bad: 1 },
    { key: "having_at_symbol", label: "@ Symbol in URL", desc: "URL contains @ which can redirect browsers", bad: 1 },
    { key: "redirection", label: "Double-Slash Redirect", desc: "URL contains '//' redirect outside of protocol", bad: 1 },
    { key: "prefix_suffix", label: "Dash in Domain", desc: "Domain name contains hyphens (common in phishing)", bad: 1 },
    { key: "sub_domains", label: "Excessive Subdomains", desc: "Domain has too many subdomains", bad: 1 },
    { key: "https_token", label: "HTTPS Token in Domain", desc: "'HTTPS' appears in domain name to deceive users", bad: 1 },
    { key: "age_of_domain", label: "New Domain", desc: "Domain was recently registered", bad: 1 },
    { key: "dns_record", label: "No DNS Record", desc: "Domain has no DNS record or is not resolvable", bad: 1 },
    { key: "web_traffic", label: "Low Web Traffic", desc: "Website has very low or no traffic ranking", bad: 1 },
    { key: "domain_reg_length", label: "Short Registration", desc: "Domain registered for a short period", bad: 1 },
    { key: "statistical_report", label: "In Statistical Reports", desc: "URL appears in known phishing statistical reports", bad: 1 },
    { key: "iframe", label: "Hidden iFrame", desc: "Page uses invisible iFrames (data theft technique)", bad: 1 },
    { key: "mouse_over", label: "Mouse-over Tampering", desc: "Status bar is manipulated on hover", bad: 1 },
  ];

  const sourceLabels = {
    ml_model: "Machine Learning Model (XGBoost)",
    trusted_list: "Trusted Domain List",
    virustotal: "VirusTotal Threat Intelligence",
    google_safebrowsing: "Google Safe Browsing",
    cached_phishing_list: "Known Phishing Domain",
    error_fallback: "Error Recovery (Default)",
    emergency_trusted_override: "Verified Safe Domain",
    openphish: "OpenPhish Database",
    urlhaus: "URLhaus Database",
    typosquatting: "Typosquatting Detection",
    homograph_attack: "Homograph Attack Detection",
    email_analysis: "Email Analysis",
  };

  const getSourceLabel = (src) => {
    if (!src) return "Machine Learning Model";
    if (src.startsWith("cache_"))
      return `Cached: ${sourceLabels[src.replace("cache_", "")] || src}`;
    return sourceLabels[src] || src;
  };

  const buildFindings = () => {
    if (!resInfo || !resInfo.featureExtractionResult) return [];
    const features = resInfo.featureExtractionResult;
    const findings = [];

    features.forEach((val, i) => {
      if (i < featureNames.length) {
        const f = featureNames[i];
        if (val === f.bad) {
          findings.push({
            label: f.label,
            desc: f.desc,
            severity: "high",
          });
        }
      }
    });
    return findings;
  };

  const getDomain = (url) => {
    try {
      const u = new URL(url.startsWith("http") ? url : `http://${url}`);
      return u.hostname;
    } catch {
      return url;
    }
  };

  const getRiskLevel = () => {
    if (!resInfo) return { label: "Unknown", variant: "secondary" };
    if (resInfo.predictionMade === 1 && resInfo.phishRate >= 75)
      return { label: "High Risk", variant: "danger", glowCls: "glow-danger" };
    if (resInfo.predictionMade === 1)
      return { label: "Suspicious", variant: "warning", glowCls: "glow-warning" };
    if (resInfo.successRate >= 90)
      return { label: "Safe", variant: "success", glowCls: "glow-success" };
    return { label: "Likely Safe", variant: "info", glowCls: "glow-info" };
  };

  return (
    <div className="url-analysis-page">
      <div className="url-analysis-header">
        <h1 className="url-analysis-title text-gradient-cyan">URL Analysis</h1>
      </div>
      <p className="url-analysis-description">
        Analyze URLs to detect phishing links, URL shorteners, and other
        suspicious patterns using real-time threat intelligence.
      </p>

      {/* ── Input ── */}
      <div className="url-input-container glass-panel">
        <div className="url-input-label">
          <span className="text-cyan">Target URL</span>
          <button className="cyber-btn" style={{ padding: '0.2rem 0.75rem', fontSize: '0.75rem' }} onClick={loadExampleUrl}>
            Load Example
          </button>
        </div>
        <div className="url-input-wrapper mt-3">
          <input
            type="text"
            className="cyber-input"
            value={inputUrl}
            onChange={(e) => setInputUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && checkUrlHandler()}
            placeholder="e.g., https://suspicious-link.com/login"
          />
          <button className="cyber-btn cyber-btn-primary search-btn" onClick={checkUrlHandler}>
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
              <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" stroke="currentColor" fill="none" />
            </svg>
          </button>
        </div>
        <p className="url-hint mt-3" style={{ color: 'var(--text-main)' }}>Enter any URL you suspect might be phishing to analyze it securely.</p>
        {error && <p className="text-rose mt-2">{error}</p>}
      </div>

      {/* ── Loading ── */}
      {loading && (
        <div className="loading-container glass-panel">
          <div className="spinner"></div>
          <p className="text-cyan mt-3 tracking-widest text-uppercase">Scanning Global Threat Feeds...</p>
        </div>
      )}

      {/* ── Results ── */}
      {showResults && resInfo && (() => {
        const risk = getRiskLevel();
        const findings = buildFindings();
        const domain = getDomain(resInfo.url);

        return (
          <div className={`results-container glass-panel ${risk.glowCls}`}>
            {/* Risk Level Header */}
            <div className="results-header">
              <h2 className="results-title">Analysis Result</h2>
              <span className={`cyber-badge ${risk.variant}`}>
                {risk.label}
              </span>
            </div>

            {/* Risk Score */}
            <div className="result-section glass-panel">
              <div className="result-label">Risk Probability</div>
              <div className="result-content">
                <div className="confidence-meters">
                  <div className="confidence-meter">
                    <span className="text-emerald">Safe</span>
                    <div className="meter-bar">
                      <div className="meter-fill safe-fill" style={{ width: `${resInfo.successRate}%` }}></div>
                    </div>
                    <span className="text-emerald">{resInfo.successRate}%</span>
                  </div>
                  <div className="confidence-meter">
                    <span className="text-rose">Phishing</span>
                    <div className="meter-bar">
                      <div className="meter-fill danger-fill" style={{ width: `${resInfo.phishRate}%` }}></div>
                    </div>
                    <span className="text-rose">{resInfo.phishRate}%</span>
                  </div>
                </div>
              </div>
            </div>

            {/* URL & Domain Info */}
            <div className="result-section glass-panel">
              <div className="result-label">Target Identifiers</div>
              <div className="result-content flex-column align-items-start gap-3">
                <div className="w-100 d-flex justify-content-between align-items-center">
                  <span className="text-uppercase" style={{ fontSize: '0.75rem', letterSpacing: '0.1em', color: 'var(--text-main)' }}>URL</span>
                  <span className="result-text">{resInfo.url}</span>
                </div>
                <div className="w-100 d-flex justify-content-between align-items-center">
                  <span className="text-uppercase" style={{ fontSize: '0.75rem', letterSpacing: '0.1em', color: 'var(--text-main)' }}>Domain</span>
                  <span className="result-text font-weight-bold">{domain}</span>
                </div>
                <div className="w-100 d-flex justify-content-between align-items-center">
                  <span className="text-uppercase" style={{ fontSize: '0.75rem', letterSpacing: '0.1em', color: 'var(--text-main)' }}>Detection Engine</span>
                  <span className="result-text text-cyan">{getSourceLabel(resInfo.detectionSource)}</span>
                </div>
              </div>
            </div>

            {/* Why This URL Was Flagged */}
            {findings.length > 0 && (
              <div className="result-section glass-panel" style={{ borderColor: 'rgba(255, 42, 95, 0.3)' }}>
                <div className="result-label" style={{ color: 'var(--accent-rose)' }}>
                  Critical Indicators ({findings.length} issue{findings.length > 1 ? 's' : ''})
                </div>
                <div className="result-content">
                  <table className="findings-table">
                    <thead>
                      <tr>
                        <th>Indicator</th>
                        <th>Details</th>
                        <th>Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {findings.map((f, i) => (
                        <tr key={i}>
                          <td className="text-rose"><strong>{f.label}</strong></td>
                          <td>{f.desc}</td>
                          <td>
                            <span className="cyber-badge danger">High</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* All Feature Checks */}
            <div className="result-section glass-panel">
              <div className="result-label">Deep Scan Diagnostics ({featureNames.length} Parameters)</div>
              <div className="result-content">
                <table className="findings-table">
                  <thead>
                    <tr>
                      <th>Heuristic Check</th>
                      <th>Status Signal</th>
                    </tr>
                  </thead>
                  <tbody>
                    {featureNames.map((f, i) => {
                      const val = resInfo.featureExtractionResult?.[i] ?? 0;
                      const isBad = val === f.bad;
                      return (
                        <tr key={i}>
                          <td>{f.label}</td>
                          <td>
                            <span className={`cyber-badge ${isBad ? 'danger' : 'success'}`}>
                              {isBad ? 'Detected' : 'Clean'}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Safe result message */}
            {findings.length === 0 && resInfo.predictionMade === 0 && (
              <div className="result-section glass-panel" style={{ textAlign: 'center', borderColor: 'rgba(0, 255, 163, 0.3)' }}>
                <p style={{ color: 'var(--accent-emerald)', fontSize: '1.1rem', margin: '1rem 0', fontFamily: 'var(--font-display)' }}>
                  No suspicious indicators found. The target appears safe.
                </p>
              </div>
            )}
          </div>
        );
      })()}
    </div>
  );
}

export default CheckUrl;
