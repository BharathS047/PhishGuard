import React from "react";
import "./Footer.css";

function Footer() {
  return (
    <footer className="cyber-footer glass-panel">
      <div className="footer-brand">
        <p>PhishGuard <span className="text-cyan">|</span> Threat Intelligence</p>
      </div>
      <div className="footer-copyright">
        <p>© {new Date().getFullYear()} SECURE SYSTEMS. ALL RIGHTS RESERVED.</p>
      </div>
    </footer>
  );
}

export default Footer;
