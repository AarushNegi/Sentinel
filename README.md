# Sentinel

### Interactive Cyber Attack Kill Chain Simulation Platform

<p align="center">
  <b>Learn Cyber Attacks. Understand Every Stage. Without Performing Real Attacks.</b>
</p>

---

## Overview

**Sentinel** is an enterprise-grade cybersecurity learning platform that simulates the complete lifecycle of cyber attacks in a safe, controlled, and educational environment.

Unlike traditional learning platforms that rely on static case studies or theoretical explanations, Sentinel provides an interactive visual experience where users can observe attacks unfold across a simulated enterprise network in real time.

The platform generates realistic security logs, maps attacker actions to the Cyber Kill Chain and MITRE ATT&CK frameworks, and visualizes attack progression through an immersive dashboard experience.

No real attacks, malware, or exploitation techniques are executed.

---

## Features

### Interactive Kill Chain Visualization

Visualize every stage of the cyber kill chain:

* Reconnaissance
* Weaponization
* Delivery
* Exploitation
* Installation
* Command & Control
* Actions on Objectives

Each stage is represented as an interactive animated node connected through attack paths.

---

### Enterprise Network Simulation

Simulate attacks across realistic infrastructure:

* Internet
* Firewall
* Web Server
* Database Server
* Employee Workstations
* File Server
* Cloud Storage

Attack routes illuminate dynamically while defensive responses update in real time.

---

### Real-Time Log Generation

Generate realistic security logs such as:

```text
INFO      Port Scan Started
SUCCESS   SSH Port Open
WARNING   Credential Reuse Detected
ALERT     Privilege Escalation Detected
CRITICAL  Sensitive Data Accessed
```

Logs are correlated to reconstruct the complete attack timeline.

---

### Attack Timeline

Track the progression of an attack:

```text
09:01 Recon Started
09:03 Port Scan
09:04 Open Port Found
09:06 Phishing Email Delivered
09:08 Credentials Captured
09:10 Privilege Escalation
09:14 Lateral Movement
09:18 Data Exfiltration
```

Each event contains:

* Timestamp
* Severity Level
* Kill Chain Stage
* MITRE ATT&CK Mapping

---

### AI Attack Summary

After every simulation, Sentinel automatically generates a detailed summary describing:

* Initial access vector
* Attacker movement
* Privilege escalation
* Defensive opportunities
* Recommended mitigations

---

### Automated Incident Reports

Generate enterprise-style reports containing:

* Executive Summary
* Timeline of Events
* Affected Assets
* MITRE ATT&CK Mapping
* Risk Score
* Security Recommendations

---

### Learning Hub

Interactive cybersecurity learning modules:

* Beginner
* Intermediate
* Advanced

Includes:

* Videos
* Flashcards
* Quizzes
* Progress Tracking
* Achievements

---

## Dashboard Modules

### Dashboard

* Active Simulations
* Threat Level
* Generated Logs
* Completed Scenarios
* Kill Chain Progress

### Simulation Engine

* Attack Scenario Selection
* Network Size Configuration
* Attack Speed Control
* Red Team / Blue Team Modes

### Attack Library

Available scenarios include:

| Attack Type       | Difficulty   | Category          |
| ----------------- | ------------ | ----------------- |
| Phishing          | Beginner     | Email Security    |
| SQL Injection     | Intermediate | Web Security      |
| Brute Force       | Beginner     | Authentication    |
| Ransomware        | Advanced     | Endpoint Security |
| Man-in-the-Middle | Advanced     | Network Security  |

---

## Technology Stack

### Backend

* Python 3.9+
* Flask
* Pandas
* NumPy
* Faker

### Frontend

* React
* Tailwind CSS
* Framer Motion
* Plotly
* D3.js

### Visualization

* Plotly
* Matplotlib
* Recharts

### Version Control

* Git
* GitHub

---
## Educational Objectives

Sentinel aims to:

* Bridge the gap between cybersecurity theory and practice.
* Help learners understand attacker behavior.
* Teach incident analysis using realistic logs.
* Provide safe cybersecurity experimentation.
* Improve defensive thinking and threat analysis skills.

---

## Target Users

* Cybersecurity Students
* Universities and Colleges
* SOC Analysts
* Security Researchers
* Blue Team Professionals
* Security Awareness Programs

---

## Safety Statement

Sentinel does **not** perform real attacks.

The platform:

* Does not exploit live systems.
* Does not execute malware.
* Does not interact with external networks.
* Does not provide offensive tooling.

All activities occur within a fully controlled educational simulation environment.

---

## Future Enhancements

* AI Threat Prediction
* Adaptive Blue Team Responses
* Incident Replay System
* Time Travel Analysis
* Attack Comparison Engine
* Multi-User Collaboration
* Leaderboards and Certifications

---

## License

This project is intended strictly for educational and research purposes.

Commercial usage requires explicit permission from the authors.
