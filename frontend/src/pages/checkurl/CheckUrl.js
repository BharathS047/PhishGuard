import axios from "axios";
import React, { useState } from "react";
import "./CheckUrl.css";
import { useAuth } from "../../context/AuthContext";

function CheckUrl() {
  const [inputUrl, setInputUrl] = useState("");
  const { tokens } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [urlWarning, setUrlWarning] = useState("");
  const [showResults, setShowResults] = useState(false);
  const [resInfo, setResInfo] = useState(null);
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false);

  // ── Real-time URL validator ──
  const validateUrl = (value) => {
    if (!value || !value.trim()) return ""; // empty = no warning
    const trimmed = value.trim();
    if (trimmed.includes(" ")) return "URL cannot contain spaces.";
    try {
      const normalized =
        trimmed.startsWith("http://") || trimmed.startsWith("https://")
          ? trimmed
          : `https://${trimmed}`;
      const parsed = new URL(normalized);
      const hostname = parsed.hostname;
      if (!hostname.includes("."))
        return "Enter a complete URL with a domain (e.g., example.com).";
      const tld = hostname.split(".").pop();
      if (tld.length < 2)
        return "URL must have a valid extension (.com, .org, .net …).";
      // Reject pure numeric hostnames that aren't IPs
      if (/^[a-z0-9]+$/i.test(hostname))
        return "This looks like an incomplete URL. Did you mean " + hostname + ".com?";
      return ""; // looks valid
    } catch {
      return "This doesn't look like a valid URL. Example: https://example.com";
    }
  };

  const handleInputChange = (e) => {
    const val = e.target.value;
    setInputUrl(val);
    setUrlWarning(validateUrl(val));
  };

  /* eslint-disable */
  const checkLink = (string) =>
    /^(https?:\/\/)[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+$/.test(string);

  const checkUrlHandler = () => {
    setError("");
    setShowResults(false);
    setFeedbackSubmitted(false);

    if (!inputUrl || !inputUrl.trim()) {
      setError("Please enter a URL.");
      return;
    }

    const warning = validateUrl(inputUrl.trim());
    if (warning) {
      setUrlWarning(warning);
      setError("Please fix the URL before scanning.");
      return;
    }

    const formattedUrl =
      inputUrl.trim().startsWith("http://") || inputUrl.trim().startsWith("https://")
        ? inputUrl.trim()
        : `https://${inputUrl.trim()}`;

    if (checkLink(formattedUrl)) {
      setLoading(true);
      const apiUrl = process.env.REACT_APP_API_URL || "http://localhost:8000";
      axios
        .get(`${apiUrl}/api/?url=${encodeURIComponent(formattedUrl)}`, {
          headers: {
            Authorization: `Bearer ${tokens?.access}`
          },
          timeout: 180000
        })
        .then((res) => {
          setResInfo(res.data);
          setLoading(false);
          setShowResults(true);
        })
        .catch((err) => {
          setLoading(false);
          if (err.response) {
            const status = err.response.status;
            if (status === 401) {
              setError("Your session has expired. Please log in again.");
            } else {
              setError(`The scan could not be completed (server error ${status}). Please try again.`);
            }
          } else if (err.code === "ECONNABORTED") {
            setError("The scan timed out — this site is taking unusually long to analyze. Please try again.");
          } else {
            setError("Could not reach the server. Please check your internet connection and try again.");
          }
        });
    } else {
      setError("Please enter a valid URL before scanning.");
      setLoading(false);
    }
  };

  const loadExampleUrl = () => setInputUrl("https://www.google.com");

  // ── Feature-name mapping (29 features) ──
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
    // New features (16-25)
    { key: "url_entropy", label: "High URL Entropy", desc: "URL contains random-looking character patterns", bad: 1 },
    { key: "digit_ratio", label: "High Digit Ratio", desc: "URL contains unusually many digits", bad: 1 },
    { key: "special_char_count", label: "Excessive Special Chars", desc: "URL path has too many special characters (obfuscation)", bad: 1 },
    { key: "domain_length", label: "Unusual Domain Length", desc: "Domain name is unusually short or long", bad: 1 },
    { key: "path_depth", label: "Deep Path Nesting", desc: "URL has deeply nested directory structure", bad: 1 },
    { key: "tld_suspicious", label: "Suspicious TLD", desc: "Uses a top-level domain commonly abused by phishers", bad: 1 },
    { key: "punycode_detected", label: "Punycode / IDN Attack", desc: "Domain uses encoded Unicode characters (homograph attack)", bad: 1 },
    { key: "contains_brand_name", label: "Brand Impersonation", desc: "Known brand name in subdomain/path but not in actual domain", bad: 1 },
    { key: "cert_check", label: "SSL Certificate Issue", desc: "Missing or invalid SSL certificate", bad: 1 },
    { key: "url_has_login_keywords", label: "Login Keywords in URL", desc: "URL path contains login/verify/account keywords", bad: 1 },
    // Missing attack features (26-29)
    { key: "data_uri_phishing", label: "Data URI Phishing", desc: "URL uses data: scheme to embed a full phishing page", bad: 1 },
    { key: "open_redirect_detection", label: "Open Redirect", desc: "URL contains redirect parameters pointing to an external domain", bad: 1 },
    { key: "suspicious_query_string", label: "Suspicious Query String", desc: "URL query contains base64 blobs, credential keywords, or excessive parameters", bad: 1 },
    { key: "domain_ip_mismatch", label: "Suspicious IP Resolution", desc: "Domain resolves to a private, reserved, or suspicious IP address", bad: 1 },
  ];

  const sourceLabels = {
    ml_model: "Machine Learning Model",
    trusted_list: "Trusted Domain List",
    virustotal: "VirusTotal Threat Intelligence",
    google_safebrowsing: "Google Safe Browsing",
    cached_phishing_list: "Known Phishing Domain",
    error_no_data: "Inconclusive (no data available)",
    openphish: "OpenPhish Database",
    urlhaus: "URLhaus Database",
    typosquatting: "Typosquatting Detection",
    homograph_attack: "Homograph Attack Detection",
    email_analysis: "Email Analysis",
    ensemble: "Multi-Engine Ensemble",
    "ml_model+features": "ML Model + Feature Analysis",
    feature_override: "Feature-Based Override",
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
    if (resInfo.predictionMade === -1)
      return { label: "Inconclusive", variant: "warning", glowCls: "glow-warning" };
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
            onChange={handleInputChange}
            onKeyDown={(e) => e.key === "Enter" && checkUrlHandler()}
            placeholder="e.g., https://suspicious-link.com/login"
            style={urlWarning ? { borderColor: 'var(--accent-gold)', boxShadow: '0 0 0 3px rgba(255,184,0,0.12)' } : {}}
          />
          <button className="cyber-btn cyber-btn-primary search-btn" onClick={checkUrlHandler}>
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
              <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" stroke="currentColor" fill="none" />
            </svg>
          </button>
        </div>
        {/* URL validation warning */}
        {urlWarning && (
          <p style={{
            color: 'var(--accent-gold)',
            fontSize: '0.82rem',
            marginTop: '0.5rem',
            marginBottom: 0,
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}>
            <span>⚠️</span> {urlWarning}
          </p>
        )}
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

            {/* User Feedback */}
            <div className="result-section glass-panel" style={{ textAlign: 'center' }}>
              {feedbackSubmitted ? (
                <p style={{ color: 'var(--accent-cyan)', margin: '0.5rem 0', fontFamily: 'var(--font-display)' }}>
                  Thank you for your feedback! It will help improve our detection.
                </p>
              ) : (
                <>
                  <div className="result-label" style={{ marginBottom: '0.75rem' }}>Was this analysis correct?</div>
                  <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
                    <button
                      className="cyber-btn"
                      style={{ padding: '0.4rem 1.5rem', borderColor: 'var(--accent-emerald)', color: 'var(--accent-emerald)' }}
                      onClick={() => {
                        const apiUrl = process.env.REACT_APP_API_URL || "http://localhost:8000";
                        axios.post(`${apiUrl}/feedback/`, {
                          scan_id: resInfo.scanId,
                          feedback: 'correct',
                        }, { headers: { Authorization: `Bearer ${tokens?.access}` } })
                          .then(() => setFeedbackSubmitted(true))
                          .catch(() => setFeedbackSubmitted(true));
                      }}
                    >
                      Yes, Correct
                    </button>
                    <button
                      className="cyber-btn"
                      style={{ padding: '0.4rem 1.5rem', borderColor: 'var(--accent-rose)', color: 'var(--accent-rose)' }}
                      onClick={() => {
                        const apiUrl = process.env.REACT_APP_API_URL || "http://localhost:8000";
                        axios.post(`${apiUrl}/feedback/`, {
                          scan_id: resInfo.scanId,
                          feedback: 'incorrect',
                        }, { headers: { Authorization: `Bearer ${tokens?.access}` } })
                          .then(() => setFeedbackSubmitted(true))
                          .catch(() => setFeedbackSubmitted(true));
                      }}
                    >
                      No, Incorrect
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        );
      })()}
    </div>
  );
}

export default CheckUrl;
