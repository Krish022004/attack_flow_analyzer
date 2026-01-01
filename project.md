# CYBER SECURITY PROJECT COMPENDIUM

**PES UNIVERSITY**  
**Department of Computer Science and Engineering**  
**Cyber Security Mini Project List**

---

## 1. EVALUATION RUBRIC (15 Marks)

| Component | Description | Marks |
| :--- | :--- | :--- |
| **Implementation** | Correctness, algorithms, real-time execution, integration. | 8 |
| **Report Quality** | Diagrams, screenshots, evaluation, clarity. | 2 |
| **Viva Performance** | Understanding of topics & explanation ability. | 5 |

---

## 2. COMMON LEARNING OUTCOMES

* Build real-world cyber security tools using Python.
* Capture and analyze real network traffic and logs.
* Develop GUI dashboards for security monitoring.
* Design simple self-learning rule engines.
* Understand cryptography, forensics, blockchain, DNS & packet analysis.

---

## Project 14: Incident Response Attack-Flow Analyzer

### Concept
A log analysis tool that reconstructs an end-to-end attack lifecycle from multiple log sources.

### Inputs
* Authentication logs, web server logs, firewall logs, and other text-based logs provided for the exercise.
* Mapping rules or templates for each attack phase (Reconnaissance, Initial Access, Lateral Movement, Exfiltration).
* Network packet capture files (.pcap, .pcapng) for real-time traffic analysis.

### Outputs
* Chronological timeline of key attacker activities.
* Labelled phases of the attack with associated log events.
* Indicators of Compromise (IOCs) list such as IPs, domains, and file hashes.

### Main Modules
1. **Multi-Source Log Ingestion Module** - Parses various log formats and packet capture files.
2. **Correlation Engine** - Groups events by user, IP, or session.
3. **Phase Classifier** - Maps events to stages of kill-chain.
4. **Timeline Visualizer** - Provides graphical view of attack flow.
5. **IOC Exporter** - Exports IOCs for reporting and further defence activities.
6. **Packet Capture Module** - Captures and analyzes live network traffic.

### Learning Component
Tracks which attack phase occurs most frequently or lasts longest, helping students prioritise defence activities.

### Use Case / Purpose
Demonstrates practical incident response analysis without requiring commercial SIEM tools.
