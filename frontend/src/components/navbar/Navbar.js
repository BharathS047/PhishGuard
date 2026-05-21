import React from "react";
import { Link, useLocation } from "react-router-dom";
import "./Navbar.css";
import ThemeToggle from "./ThemeToggle";
import { useAuth } from "../../context/AuthContext";

function Navbar() {
  const location = useLocation();
  const { user, logout } = useAuth();

  return (
    <nav className="cyber-navbar glass-panel">
      <div className="navbar-logo">
        <Link to="/" className="brand-name">
          PhishGuard<span className="text-cyan">.</span>
        </Link>
      </div>
      <ul className="nav-links">
        {user && !user.is_staff && (
          <>
            <li className="nav-item">
              <Link
                to="/dashboard"
                className={`nav-link ${location.pathname === '/dashboard' ? 'active' : ''}`}
              >
                Dashboard
              </Link>
            </li>
            <li className="nav-item">
              <Link
                to="/checkurl"
                className={`nav-link ${location.pathname === '/checkurl' ? 'active' : ''}`}
              >
                Analyze URL
              </Link>
            </li>
            <li className="nav-item">
              <Link
                to="/email-analysis"
                className={`nav-link ${location.pathname === '/email-analysis' ? 'active' : ''}`}
              >
                Analyze Email
              </Link>
            </li>
          </>
        )}

      </ul>
      <div className="d-flex align-items-center gap-4">
        <ThemeToggle />
        {user ? (
          <div className="d-flex align-items-center gap-3">
            <span className="text-muted" style={{ fontSize: '0.85rem' }}>Op: <span className="text-cyan fw-bold">{user.username}</span></span>
            <button onClick={logout} className="cyber-btn" style={{ padding: '0.4rem 1rem', fontSize: '0.75rem' }}>LOGOUT</button>
          </div>
        ) : (
          <Link to="/login" className="cyber-btn cyber-btn-primary" style={{ padding: '0.4rem 1rem', fontSize: '0.75rem' }}>LOGIN</Link>
        )}
      </div>
    </nav>
  );
}

export default Navbar;
