import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './Dashboard.css';
import { useAuth } from '../../context/AuthContext';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const { tokens } = useAuth();

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API_URL}/dashboard_stats/`, {
        headers: {
          Authorization: `Bearer ${tokens?.access}`
        }
      });
      setStats(response.data);
      setError(null);
    } catch (err) {
      setError('Could not establish connection to the telemetry server.');
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    // Refresh every 30 seconds
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
  }, []);

  // Helpers
  const getResultBadge = (result) => {
    switch (result) {
      case 'phishing': return 'danger';
      case 'suspicious': return 'warning';
      case 'legitimate': return 'success';
      default: return 'info';
    }
  };

  const getRiskColorClass = (score) => {
    if (score >= 75) return 'text-rose';
    if (score >= 40) return 'text-gold';
    return 'text-emerald';
  };

  const getRiskFillClass = (score) => {
    if (score >= 75) return 'danger-fill';
    if (score >= 40) return 'warning-fill';
    return 'safe-fill';
  };

  if (isLoading) {
    return (
      <div className="dashboard-container d-flex flex-column align-items-center justify-content-center" style={{ minHeight: '80vh' }}>
        <div className="spinner mb-4" style={{ width: '60px', height: '60px', borderTopColor: 'var(--accent-cyan)' }}></div>
        <p className="text-cyan text-uppercase tracking-widest font-weight-bold" style={{ letterSpacing: '0.2em' }}>Initializing Telemetry...</p>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="dashboard-container">
        <h2 className="dashboard-title mb-5">
          SECURITY TELEMETRY
        </h2>
        <div className="glass-panel text-center p-5" style={{ borderColor: 'var(--accent-rose)' }}>
          <h4 className="text-rose text-uppercase tracking-widest mb-3">System Offline</h4>
          <p className="text-muted">{error || 'Telemetry node unresponsive'}</p>
          <p className="text-muted mt-4" style={{ fontSize: '0.875rem' }}>
            Ensure the analytics engine is running and collecting data points.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <h2 className="dashboard-title mb-5">
        SECURITY TELEMETRY
      </h2>

      {/* ── Summary cards ── */}
      <div className="dashboard-grid stats-grid mb-5">
        <div className="glass-panel threat-card">
          <h4 className="card-title text-cyan">Global Scans</h4>
          <div className="threat-count">
            <div className="count-value text-main">{stats.total_scans}</div>
            <div className="count-label mt-2">
              <span style={{ color: 'var(--text-main)' }}>{stats.url_scans} URLs</span> · <span style={{ color: 'var(--text-main)' }}>{stats.email_scans} Emails</span>
            </div>
          </div>
        </div>

        <div className="glass-panel threat-card">
          <h4 className="card-title text-rose">Threats Neutralized</h4>
          <div className="threat-count">
            <div className={`count-value ${stats.phishing_count > 0 ? 'text-rose' : 'text-emerald'}`}>
              {stats.phishing_count}
            </div>
            <div className="count-label mt-2" style={{ color: 'var(--text-main)' }}>Confirmed Phishing</div>
          </div>
        </div>

        <div className="glass-panel threat-card">
          <h4 className="card-title text-emerald">Verified Safe</h4>
          <div className="threat-count">
            <div className="count-value text-emerald">{stats.legitimate_count}</div>
            <div className="count-label mt-2" style={{ color: 'var(--text-main)' }}>Legitimate Requests</div>
          </div>
        </div>

        <div className="glass-panel threat-card">
          <h4 className="card-title text-gold">Network Risk Factor</h4>
          <div className="threat-meter">
            <div className={`threat-level ${getRiskColorClass(stats.avg_risk_score)}`}>
              {stats.avg_risk_score}%
            </div>
            <div className="meter-bar mt-3" style={{ height: '8px', margin: '0' }}>
              <div className={`meter-fill ${getRiskFillClass(stats.avg_risk_score)}`} style={{ width: `${stats.avg_risk_score}%` }}></div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Result distribution ── */}
      <div className="dashboard-grid mb-5">
        <div className="glass-panel chart-card w-100">
          <h4 className="card-title text-cyan">Threat Distribution Analysis</h4>
          <div className="card-content mt-4">
            {stats.total_scans > 0 ? (
              <div className="attack-distribution">
                {[
                  { label: 'Critical (Phishing)', count: stats.phishing_count, fillClass: 'danger-fill' },
                  { label: 'Elevated (Suspicious)', count: stats.suspicious_count, fillClass: 'warning-fill' },
                  { label: 'Nominal (Legitimate)', count: stats.legitimate_count, fillClass: 'safe-fill' },
                ].map(({ label, count, fillClass }) => {
                  const pct = stats.total_scans > 0 ? Math.round((count / stats.total_scans) * 100) : 0;
                  return (
                    <div key={label} className="distribution-item mb-4">
                      <div className="d-flex justify-content-between align-items-end mb-2">
                        <span className="attack-type">{label}</span>
                        <span className="attack-value">{count} <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>({pct}%)</span></span>
                      </div>
                      <div className="meter-bar" style={{ height: '10px', margin: '0' }}>
                        <div className={`meter-fill ${fillClass}`} style={{ width: `${pct}%` }}></div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-center text-muted py-5">
                Awaiting telemetry data streams...
              </p>
            )}
          </div>
        </div>
      </div>

      {/* ── Recent scan history ── */}
      <div className="glass-panel attacks-card p-0" style={{ overflow: 'hidden' }}>
        <div className="p-4 border-bottom" style={{ borderColor: 'var(--separator)' }}>
          <div className="d-flex justify-content-between align-items-center">
            <h4 className="card-title m-0 text-cyan border-0">Network Logs</h4>
            <span className="cyber-badge info">{stats.recent_scans.length} events logged</span>
          </div>
        </div>
        <div className="card-content">
          {stats.recent_scans.length > 0 ? (
            <div className="table-responsive" style={{ border: 'none' }}>
              <table className="findings-table m-0">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Vector</th>
                    <th>Target Address</th>
                    <th>Classification</th>
                    <th>Risk Factor</th>
                    <th>Subsystem</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recent_scans.map(scan => {
                    const date = new Date(scan.created_at);
                    const formatted = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
                    return (
                      <tr key={scan.id} style={{ backgroundColor: scan.result === 'phishing' ? 'rgba(255,42,95,0.05)' : 'transparent' }}>
                        <td style={{ fontSize: '0.875rem', fontFamily: 'monospace', color: 'var(--text-main)' }}>{formatted}</td>
                        <td>
                          <span className={`cyber-badge ${scan.scan_type === 'url' ? 'info' : 'warning'}`} style={{ fontSize: '0.65rem' }}>
                            {scan.scan_type.toUpperCase()}
                          </span>
                        </td>
                        <td className="text-truncate text-main" style={{ maxWidth: '250px', fontFamily: 'monospace' }}>{scan.target}</td>
                        <td>
                          <span className={`cyber-badge ${getResultBadge(scan.result)}`} style={{ fontSize: '0.65rem' }}>
                            {scan.result.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <div className="d-flex align-items-center">
                            <span className="me-3" style={{ fontFamily: 'monospace', width: '30px' }}>{Math.round(scan.risk_score)}%</span>
                            <div className="meter-bar m-0" style={{ height: '6px', width: '60px' }}>
                              <div className={`meter-fill ${getRiskFillClass(scan.risk_score)}`} style={{ width: `${scan.risk_score}%` }}></div>
                            </div>
                          </div>
                        </td>
                        <td style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-main)' }}>{scan.detection_source}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center p-5 text-muted">
              <p>Buffer empty. Traffic not intercepted.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;