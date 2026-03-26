# 🛡️ PhishGuard: AI-Powered Phishing Detection System

**PhishGuard** is an intelligent phishing detection system powered by Machine Learning and real-time threat intelligence APIs. It safeguards users by analyzing suspicious URLs and predicting phishing threats instantly.

---

## 🔍 Features

- ✅ Real-time phishing detection
- ✅ 15+ URL-based feature extraction
- ✅ ML-powered predictions with XGBoost
- ✅ Google Safe Browsing API integration
- ✅ VirusTotal threat intelligence
- ✅ Confidence scoring for predictions
- ✅ Responsive and beautiful web interface (React + Tailwind + DaisyUI)

---

## 🗂️ Project Structure
```
PhishGuard-Phishing-Detection-System/
├── backend/ # Django + DRF API server
├── frontend/ # React + Tailwind + DaisyUI client
├── ml/ # ML model and feature extraction logic
├── scripts/ # Batch scripts for automation
│ ├── setup_api_keys.bat
│ └── run_app.bat
└── README.md
```



## 🔧 Getting Started

### 🛠 Prerequisites

- Python 3.8+
- Node.js & npm
- API Keys for:
  - [Google Safe Browsing](https://developers.google.com/safe-browsing/v4/get-started)
  - [VirusTotal](https://www.virustotal.com/gui/join-us)

---

## 🔐 API Key Setup

Create a `.env` file inside the `backend/` folder:

```env
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

⚙️ Backend Setup (Django + DRF)

cd backend
python -m venv venv
venv\Scripts\activate      # On Windows
# OR
source venv/bin/activate   # On Linux/Mac

pip install -r requirements.txt
python manage.py runserver


🌐 Frontend Setup (React + Tailwind CSS)
cd frontend
npm install
npm start

⚡ Quick Start (Windows Only)
scripts/run_app.bat


🧠 How It Works
User enters a URL

Frontend sends URL to Django backend

Backend extracts features from URL

URL is scanned using:

Google Safe Browsing

VirusTotal

ML model (XGBoost) predicts phishing probability

Result + confidence score is returned to frontend

📊 Tech Stack
Layer	Tech
Frontend	React, Tailwind CSS, DaisyUI
Backend	Django, Django REST Framework
ML Model	XGBoost
APIs	Google Safe Browsing, VirusTotal
Automation	Windows Batch Scripts

🌟 Feature Highlights
Feature	Description
⚡ Instant Predictions	Real-time phishing probability analysis
🧠 ML Intelligence	XGBoost classifier trained on URL features
🔍 Safe Browsing Check	Checks against Google's threat database
🛰️ VirusTotal Integration	External scan for threat indicators
🎨 Beautiful UI	Tailwind-powered responsive interface
📊 Confidence Score	Transparent scoring of prediction certainty


🔮 Future Scope
🔐 User authentication + history tracking

🧠 Deep Learning-based models

☁️ Cloud deployment (Heroku, GCP, or AWS)

🧩 Chrome Extension for URL scanning

🤝 Contributing
Pull requests are welcome! 🎉
Whether you're improving UI, adding new ML features, or optimizing backend code — PhishGuard grows with your contributions.

📄 License
MIT License. See LICENSE for details.



