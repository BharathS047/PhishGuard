import React from "react";
import AlgorithmIcon from "../../assets/png/algorithm.png";
import DatasetIcon from "../../assets/png/dataset.png";
import FeatureIcon from "../../assets/png/feature.png";
import VerifiedIcon from "../../assets/png/verified.png";
import "./Summary.css";

function Summary() {
  return (
    <div className="features-summary">
      <h2 className="section-title text-gradient-cyan">Key Capabilities</h2>
      <div className="features-grid">
        <div className="feature-card glass-panel">
          <div className="feature-icon">
            <img src={DatasetIcon} alt="dataset" />
          </div>
          <h3 className="feature-title">Extensive Training</h3>
          <p className="feature-description">
            Trained and tested with 2000+ URLs for high accuracy detection
          </p>
        </div>

        <div className="feature-card glass-panel">
          <div className="feature-icon">
            <img src={FeatureIcon} alt="feature" />
          </div>
          <h3 className="feature-title">Advanced Analysis</h3>
          <p className="feature-description">
            15 feature extractions used for precise phishing detection
          </p>
        </div>

        <div className="feature-card glass-panel">
          <div className="feature-icon">
            <img src={VerifiedIcon} alt="verify" />
          </div>
          <h3 className="feature-title">Comprehensive Verification</h3>
          <p className="feature-description">
            Verifies domains, URLs, and scripts for security threats
          </p>
        </div>

        <div className="feature-card glass-panel">
          <div className="feature-icon">
            <img src={AlgorithmIcon} alt="algorithm" />
          </div>
          <h3 className="feature-title">Powerful Algorithms</h3>
          <p className="feature-description">
            Uses XGBoost and RandomForest models for reliable results
          </p>
        </div>
      </div>
    </div>
  );
}

export default Summary;
