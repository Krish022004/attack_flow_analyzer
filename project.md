# [cite_start]CYBER SECURITY PROJECT COMPENDIUM [cite: 1]

[cite_start]**PES UNIVERSITY** [cite: 2]
[cite_start]**Department of Computer Science and Engineering** [cite: 3]
[cite_start]**Cyber Security Mini Project List** [cite: 4]

---

## [cite_start]1. EVALUATION RUBRIC (15 Marks) [cite: 5]

| Component | Description | Marks |
| :--- | :--- | :--- |
| **Implementation** | [cite_start]Correctness, algorithms, real-time execution, integration. [cite: 6] | [cite_start]8 [cite: 6] |
| **Report Quality** | [cite_start]Diagrams, screenshots, evaluation, clarity. [cite: 6] | [cite_start]2 [cite: 6] |
| **Viva Performance** | [cite_start]Understanding of topics & explanation ability. [cite: 6] | [cite_start]5 [cite: 6] |

---

## [cite_start]2. COMMON LEARNING OUTCOMES [cite: 7]

* [cite_start]Build real-world cyber security tools using Python. [cite: 8]
* [cite_start]Capture and analyze real network traffic and logs. [cite: 9]
* [cite_start]Develop GUI dashboards for security monitoring. [cite: 10]
* [cite_start]Design simple self-learning rule engines. [cite: 11]
* [cite_start]Understand cryptography, forensics, blockchain, DNS & packet analysis. [cite: 12]

---

## [cite_start]Project 14: Incident Response Attack-Flow Analyzer [cite: 14]

### Concept
[cite_start]A log analysis tool that reconstructs an end-to-end attack lifecycle from multiple log sources. [cite: 15, 16]

### Inputs
* [cite_start]Authentication logs, web server logs, firewall logs, and other text-based logs provided for the exercise. [cite: 17]
* [cite_start]Mapping rules or templates for each attack phase (Reconnaissance, Initial Access, Lateral Movement, Exfiltration). [cite: 18]

### Outputs
* [cite_start]Chronological timeline of key attacker activities. [cite: 20]
* [cite_start]Labelled phases of the attack with associated log events. [cite: 21]
* [cite_start]Indicators of Compromise (IOCs) list such as IPs, domains, and file hashes. [cite: 22]

### Main Modules
1.  [cite_start]**Multi-Source Log Ingestion Module.** [cite: 24]
2.  [cite_start]**Correlation Engine** that groups events by user, IP, or session. [cite: 25]
3.  [cite_start]**Phase Classifier** that maps events to stages of kill-chain. [cite: 26]
4.  [cite_start]**Timeline Visualizer** providing graphical view of attack flow. [cite: 27]
5.  [cite_start]**IOC Exporter** for reporting and further defence activities. [cite: 28]

### Learning Component
[cite_start]Tracks which attack phase occurs most frequently or lasts longest, helping students prioritise defence activities. [cite: 29, 30]

### Use Case / Purpose
[cite_start]Demonstrates practical incident response analysis without requiring commercial SIEM tools. [cite: 31, 32]