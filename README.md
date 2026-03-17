🚨 Autonomous Cyber Defense Platform
An intelligent, real-time cybersecurity system that monitors network traffic, detects anomalies using machine learning, and automatically responds to threats without human intervention.

🔍 Overview
The Autonomous Cyber Defense Platform is designed to protect networks from modern cyber threats such as:

Port scanning

Brute-force attempts

Suspicious traffic patterns

Unknown behavioral anomalies

Unlike traditional security systems that only generate alerts, this platform actively detects and neutralizes threats in real time.

⚙️ Key Features
🔥 Real-Time Packet Monitoring
Continuously captures and analyzes network traffic.

🧠 Machine Learning Anomaly Detection
Uses Isolation Forest to detect abnormal behavior.

⚡ Threat Scoring Engine
Assigns dynamic threat scores based on activity patterns.

🚫 Automated Response System
Automatically blocks malicious IPs when thresholds are exceeded.

🪤 Honeypot System
Traps attackers and records their behavior for analysis.

📊 Security Dashboard API
Provides real-time insights into:

network activity

detected threats

blocked IPs

event logs

🧾 Forensics & Logging
Stores detailed attack data for analysis and auditing.

🏗️ System Architecture
Network Traffic
      ↓
Packet Monitoring Engine
      ↓
Feature Extraction
      ↓
ML Anomaly Detection (Isolation Forest)
      ↓
Threat Scoring Engine
      ↓
Decision Engine
      ↓
Auto Response (Block IP)
      ↓
Logging + Dashboard API
🛠️ Tech Stack
Component	Technology Used
Frontend	HTML, CSS, JavaScript
Backend	Python (Flask)
Database	SQLite
Machine Learning	Scikit-learn (Isolation Forest)
Networking	Scapy / Socket Programming
🚀 How It Works
The system captures live network packets

Extracts important features from traffic

ML model detects anomalies

Threat engine assigns a score

If threshold exceeded:

IP is blocked

Event is logged

Data is displayed on dashboard

📦 Installation & Setup
# Clone the repository
git clone https://github.com/your-repo/autonomous-cyber-defense.git

# Navigate to project
cd autonomous-cyber-defense

# Install dependencies
pip install -r requirements.txt

# Run the system
python app.py
📊 API Endpoints
/api/events → Get security events

/api/network/stats → Get network statistics

/api/blocked → Get blocked IPs

🎯 Use Cases
Small & medium business network protection

Educational institutions

Personal network monitoring

Cybersecurity research & learning

🔐 Future Improvements
Threat intelligence integration

Distributed monitoring agents

Advanced attack classification

Real-time attack visualization

Cloud deployment

👥 Team
Sarthak Mhatre – CTO / Lead Security Engineer

Diksha Churi – Co-Founder / Full Stack Developer

Diya – Business & Strategy

Ankita – Product Support

⚡ Vision
To build an autonomous security layer that continuously monitors, detects, and defends networks against cyber threats in real time.

🧠 Note
This project is developed as part of a hackathon and demonstrates a working prototype of an autonomous cybersecurity defense system.

