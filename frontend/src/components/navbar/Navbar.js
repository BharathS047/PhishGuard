import React from "react";
import { Link, useLocation } from "react-router-dom";
import "./Navbar.css";
import ThemeToggle from "./ThemeToggle";

function Navbar() {
  const location = useLocation();

  return (
    <nav className="cyber-navbar glass-panel">
      <div className="navbar-logo">
        <Link to="/" className="brand-name">
          PhishGuard<span className="text-cyan">.</span>
        </Link>
      </div>
      <ul className="nav-links">
        <li className="nav-item">
          <Link
            to="/"
            className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}
          >
            Home
          </Link>
        </li>
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
      </ul>
      <ThemeToggle />
    </nav>
  );
}

export default Navbar;
