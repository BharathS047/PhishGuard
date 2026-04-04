import React, { useState } from 'react';
import axios from 'axios';
import './EmailAnalysis.css';
import { useAuth } from '../../context/AuthContext';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const EmailAnalysis = () => {
  const { tokens } = useAuth();
  const [formData, setFormData] = useState({
    sender: '',
    subject: '',
    body: ''
  });

  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await axios.post(`${API_URL}/analyze_email/`, formData, {
        headers: {
          Authorization: `Bearer ${tokens?.access}`
        }
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred while analyzing the email');
    } finally {
      setLoading(false);
    }
  };

  const getBadgeVariant = (risk) => {
    if (risk === 'High Risk') return 'danger';
    if (risk === 'Medium Risk') return 'warning';
    if (risk === 'Low Risk') return 'info';
    return 'success';
  };

  const getSeverityVariant = (severity) => {
    if (severity === 'high') return 'danger';
    if (severity === 'medium') return 'warning';
    return 'info';
  };

  const renderAnalysisResult = () => {
    if (!result) return null;

    const allIndicators = [
      ...result.header_analysis.suspicious_indicators.map(i => ({ ...i, source: 'Header' })),
      ...result.content_analysis.suspicious_indicators.map(i => ({ ...i, source: 'Content' }))
    ];

    const tactics = result.content_analysis.social_engineering_tactics || [];
    const urls = result.content_analysis.extracted_urls || [];

    // Determine glow color based on combined risk score
    let glowCls = "glow-success";
    if (result.combined_risk_score >= 70) glowCls = "glow-danger";
    else if (result.combined_risk_score >= 45) glowCls = "glow-warning";
    else if (result.combined_risk_score >= 20) glowCls = "glow-info";

    return (
      <div className={`results-container glass-panel mt-5 ${glowCls}`}>
        <div className="results-header" style={{ marginBottom: '1rem' }}>
          <h2 className="results-title">Analysis Result</h2>
          <span className={`cyber-badge ${getBadgeVariant(result.risk_level)}`}>
            {result.risk_level}
          </span>
        </div>

        <div className="confidence-meter mt-4" style={{ justifyContent: 'center', fontSize: '1.25rem' }}>
          <span style={{ width: 'auto', marginRight: '1rem', color: 'var(--text-main)' }}>Combined Score</span>
          <div className="meter-bar" style={{ maxWidth: '400px', flex: 'none', width: '100%', height: '16px' }}>
            <div className={`meter-fill ${result.combined_risk_score >= 50 ? 'danger-fill' : 'safe-fill'}`} style={{ width: `${result.combined_risk_score}%` }}></div>
          </div>
          <span className="text-main" style={{ width: 'auto', marginLeft: '1rem' }}>{Math.round(result.combined_risk_score)}%</span>
        </div>

        <div className="d-flex justify-content-center gap-5 mt-4 mb-4">
          <div className="text-center">
            <div className="text-uppercase tracking-widest mb-2" style={{ fontSize: '0.75rem', color: 'var(--text-main)' }}>Header Score</div>
            <span className={`cyber-badge ${getBadgeVariant(result.header_analysis.risk_level)}`}>
              {result.header_analysis.risk_score}%
            </span>
          </div>
          <div className="text-center">
            <div className="text-uppercase tracking-widest mb-2" style={{ fontSize: '0.75rem', color: 'var(--text-main)' }}>Content Score</div>
            <span className={`cyber-badge ${getBadgeVariant(result.content_analysis.risk_level)}`}>
              {result.content_analysis.risk_score}%
            </span>
          </div>
        </div>

        {result.header_analysis.has_raw_headers === false && (
          <div className="text-center mb-4" style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontStyle: 'italic' }}>
            Note: Raw email headers were not provided. SPF/DKIM/DMARC authentication could not be verified. For a more complete analysis, paste the full email source including headers.
          </div>
        )}

        {tactics.length > 0 && (
          <div className="result-section glass-panel">
            <div className="result-label text-rose">Psychological Tactics Detected</div>
            <div className="result-content d-flex flex-wrap gap-2">
              {tactics.map((tactic, index) => (
                <span key={index} className="cyber-badge danger" style={{ fontSize: '0.75rem' }}>
                  {tactic.charAt(0).toUpperCase() + tactic.slice(1)}
                </span>
              ))}
            </div>
          </div>
        )}

        {allIndicators.length > 0 && (
          <div className="result-section glass-panel" style={{ borderColor: 'rgba(255, 184, 0, 0.3)' }}>
            <div className="result-label text-gold">Suspicious Indicators</div>
            <div className="result-content">
              <table className="findings-table">
                <thead>
                  <tr>
                    <th>Finding</th>
                    <th>Details</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {allIndicators.map((indicator, index) => (
                    <tr key={index}>
                      <td className="text-main"><strong>{indicator.name}</strong></td>
                      <td>{indicator.description}</td>
                      <td>
                        <span className={`cyber-badge ${getSeverityVariant(indicator.severity)}`} style={{ fontSize: '0.65rem', padding: '0.25rem 0.5rem' }}>
                          {indicator.severity}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {urls.length > 0 && (
          <div className="result-section glass-panel">
            <div className="result-label text-cyan">Extracted URLs</div>
            <div className="result-content">
              <table className="findings-table">
                <thead>
                  <tr>
                    <th>URL Payload</th>
                    <th>Status</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {urls.map((url, index) => (
                    <tr key={index}>
                      <td style={{ wordBreak: 'break-all' }}>{url.url}</td>
                      <td>
                        <span className={`cyber-badge ${url.suspicious ? 'danger' : 'success'}`} style={{ fontSize: '0.65rem', padding: '0.25rem 0.5rem' }}>
                          {url.suspicious ? 'Suspicious' : 'Clean'}
                        </span>
                      </td>
                      <td className="text-muted">{url.reason || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {allIndicators.length === 0 && (
          <div className="result-section glass-panel" style={{ textAlign: 'center', borderColor: 'rgba(0, 255, 163, 0.3)' }}>
            <p style={{ color: 'var(--accent-emerald)', fontSize: '1.1rem', margin: '1rem 0', fontFamily: 'var(--font-display)' }}>
              No suspicious indicators found in this email.
            </p>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="email-analysis-page">
      <div className="container" style={{ maxWidth: '1000px' }}>
        <div className="url-analysis-header">
          <h1 className="url-analysis-title text-gradient text-purple">Email Analysis</h1>
        </div>
        <p className="url-analysis-description mb-5">
          Deep scan email content and headers for semantic phishing indicators, SPF/DKIM failures, and psychological manipulation tactics.
        </p>

        <div className="analysis-form glass-panel">
          <form onSubmit={handleSubmit}>
            <div className="form-field">
              <label htmlFor="sender" className="text-cyan">Sender Address</label>
              <input
                type="text"
                id="sender"
                name="sender"
                className="cyber-input"
                placeholder="e.g., security@microsoft-secure.com"
                value={formData.sender}
                onChange={handleChange}
                required
              />
            </div>

            <div className="form-field">
              <label htmlFor="subject" className="text-cyan">Message Subject</label>
              <input
                type="text"
                id="subject"
                name="subject"
                className="cyber-input"
                placeholder="e.g., URGENT: Account Compromise Detected"
                value={formData.subject}
                onChange={handleChange}
                required
              />
            </div>

            <div className="form-field">
              <label htmlFor="body" className="text-cyan">Raw Body Content</label>
              <textarea
                id="body"
                name="body"
                className="cyber-input"
                placeholder="Paste the raw email content or headers here to scan for hidden threats..."
                value={formData.body}
                onChange={handleChange}
                rows={8}
                required
                style={{ resize: 'vertical', minHeight: '150px' }}
              />
            </div>

            <button type="submit" className="cyber-btn cyber-btn-primary w-100 mt-3" disabled={loading} style={{ padding: '1rem' }}>
              {loading ? (
                <><div className="spinner" style={{ width: '20px', height: '20px', borderTopColor: '#000', marginRight: '0.5rem' }}></div> Scanning Email Structs...</>
              ) : (
                <><i className="bi bi-shield-check me-2"></i> Scan Email Payload</>
              )}
            </button>
          </form>
        </div>

        {error && (
          <div className="glass-panel p-4 mt-4" style={{ borderColor: 'var(--accent-rose)', backgroundColor: 'rgba(255,42,95,0.1)' }}>
            <p className="text-rose m-0 text-center font-weight-bold">{error}</p>
          </div>
        )}

        {renderAnalysisResult()}
      </div>
    </div>
  );
};

export default EmailAnalysis;