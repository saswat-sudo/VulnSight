# 🔐 VulnSight – AI-Enhanced Vulnerability Scanner

VulnSight is a Python-based GUI vulnerability scanner developed on Kali Linux.  
It integrates Nmap-powered service detection with an AI-driven vulnerability explanation engine to provide intelligent risk analysis and mitigation guidance.

This project demonstrates practical cybersecurity automation, network enumeration, and structured vulnerability reporting.

---

## 🚀 Project Overview

VulnSight performs automated network scanning and enhances raw scan data with intelligent threat interpretation.

The application:

- Scans target systems using Nmap
- Detects open ports and running services
- Classifies risk levels (High / Medium / Low)
- Generates AI-based vulnerability explanations
- Suggests mitigation strategies
- Uses multithreading for smooth GUI performance
- Automatically generates structured scan reports

This project simulates a lightweight vulnerability assessment framework for educational and ethical security testing.

---

## 🏗️ Architecture Workflow

1. User enters target IP address
2. Nmap performs service and version detection
3. Risk classification engine evaluates detected ports
4. AI explanation module maps services to security risks
5. Structured report is generated
6. Report is displayed in GUI and saved locally

---

## 🛠️ Technologies Used

- Python 3
- Tkinter (GUI Framework)
- Nmap
- python-nmap
- Multithreading
- Kali Linux

---

## 📦 Installation & Setup

### 1️⃣ Clone Repository

```bash
git clone https://github.com/saswat-sudo/VulnSight.git
cd VulnSight
```

### 2️⃣ Install Dependencies

```bash
sudo apt update
sudo apt install nmap python3-tk -y
pip install python-nmap
```

### 3️⃣ Run the Application

```bash
python3 vuln_sight.py
```

---

## 🧪 Safe Testing Environment

⚠️ Only scan systems you own or have explicit permission to test.

Recommended lab setup:

- Kali Linux VM (Attacker)
- Metasploitable 2 VM (Target)
- Host-Only Network Adapter

Example safe test target:

```
192.168.56.101
```

---

## 🔎 Features

✔ Port Scanning  
✔ Service & Version Detection  
✔ Risk Classification Engine  
✔ AI-Based Threat Explanation  
✔ Mitigation Recommendations  
✔ Multithreaded Execution  
✔ Timestamped Report Generation  
✔ Structured Output Logging  

---

## 🧠 AI Explanation Engine

The AI engine maps detected services to predefined security knowledge and provides contextual explanations.

### Example Output:

```
Port: 22
Service: ssh
Risk Level: HIGH

[AI ANALYSIS]
Threat: Brute Force Risk
Impact: Attackers may gain remote shell access.
Mitigation: Disable password authentication and use SSH keys.
```

---

## 📊 Sample Report Output

```
Target: 192.168.56.101
Date: 2026-02-15

Port: 21
Service: ftp
Risk Level: HIGH

Port: 80
Service: http
Risk Level: MEDIUM
```

Reports are automatically saved in the `/reports` directory with timestamped filenames.

---

## 🎯 Learning Objectives

- Understand vulnerability scanning fundamentals
- Integrate Nmap with Python
- Implement GUI-based security tools
- Apply multithreading in cybersecurity applications
- Design structured risk classification logic
- Automate vulnerability reporting

---

## ⚠️ Disclaimer

This tool is developed strictly for educational and ethical cybersecurity research purposes.

Do not scan systems, networks, or infrastructure without proper authorization.

Unauthorized scanning may violate laws and regulations.

---

## 🚀 Future Enhancements

- CVE API integration
- CVSS score calculation
- PDF report export
- Web-based dashboard (Flask/Django)
- Real-time progress bar
- Automated exploit correlation
- Database logging system

---

## 👨‍💻 Author

Saswat Pandey  
Cybersecurity Enthusiast | Ethical Hacking | Security Automation  

---

## ⭐ Support

If you found this project helpful, consider giving it a star ⭐ on GitHub.
