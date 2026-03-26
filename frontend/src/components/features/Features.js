import React from "react";
import "./Features.css";

function Features() {
  return (
    <div className="features-page">
      <div className="container">
        <h1 className="page-title text-gradient-cyan">Features & Technology</h1>

        <div className="feature-section glass-panel">
          <h2 className="section-title">About Phishing Detection</h2>
          <div className="feature-content">
            <p>
              Phishing is a form of cybercrime that attempts to obtain sensitive information by disguising as a trustworthy entity.
              Attackers create counterfeit websites that mimic legitimate ones, but with different URLs.
              Our system uses machine learning and multiple detection methods to identify these threats.
            </p>
          </div>
        </div>

        <div className="feature-section glass-panel">
          <h2 className="section-title">Data Sources</h2>
          <div className="data-sources">
            <div className="data-card glass-panel">
              <h3 className="text-cyan">Phishing URLs</h3>
              <p>
                Our system uses data from OpenPhish and URLhaus, open-source services that provide real-time phishing URL feeds.
                This ensures our detection model stays current with new threats.
              </p>
              <a href="https://openphish.com/" target="_blank" rel="noopener noreferrer" className="cyber-btn">
                View Source Data
              </a>
            </div>

            <div className="data-card glass-panel">
              <h3 className="text-emerald">Legitimate URLs</h3>
              <p>
                We use the University of New Brunswick's dataset of over 35,300 legitimate URLs to train our model
                to recognize safe websites and reduce false positives.
              </p>
              <a href="https://www.unb.ca/cic/datasets/url-2016.html" target="_blank" rel="noopener noreferrer" className="cyber-btn">
                View Source Data
              </a>
            </div>
          </div>
        </div>

        <div className="feature-section glass-panel">
          <h2 className="section-title">Feature Extraction Process</h2>
          <div className="extraction-steps">
            <div className="step-card glass-panel">
              <div className="step-number text-gradient">1</div>
              <p>Advanced processing with Python</p>
            </div>
            <div className="step-card glass-panel">
              <div className="step-number text-gradient">2</div>
              <p>8 Address Bar-based features analyzed</p>
            </div>
            <div className="step-card glass-panel">
              <div className="step-number text-gradient">3</div>
              <p>5 Domain-based features extracted</p>
            </div>
            <div className="step-card glass-panel">
              <div className="step-number text-gradient">4</div>
              <p>2 HTML and JavaScript features evaluated</p>
            </div>
            <div className="step-card glass-panel">
              <div className="step-number text-gradient">5</div>
              <p>URLs classified as legitimate (0) or phishing (1)</p>
            </div>
          </div>
        </div>

        <div className="feature-section glass-panel">
          <h2 className="section-title">Detection Methods</h2>
          <div className="detection-methods">
            <div className="method-card glass-panel">
              <h3>Machine Learning</h3>
              <p>Uses XGBoost and RandomForest algorithms to analyze URL patterns and structure</p>
            </div>
            <div className="method-card glass-panel">
              <h3>Reputation Services</h3>
              <p>Integration with Google Safe Browsing and VirusTotal APIs for real-time verification</p>
            </div>
            <div className="method-card glass-panel">
              <h3>Trusted Domain Verification</h3>
              <p>Checking against a list of known safe domains to reduce false positives</p>
            </div>
            <div className="method-card glass-panel">
              <h3>Email Security Analysis</h3>
              <p>SPF, DKIM, and DMARC validation for authenticating email sources</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Features;
