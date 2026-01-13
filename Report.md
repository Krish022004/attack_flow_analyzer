# CYBER SECURITY MINI PROJECT REPORT

**PES UNIVERSITY**  
**Department of Computer Science and Engineering**  
**M.Tech 1st SEM 2025**

---

## 1. Project Title:
**Incident Response Attack-Flow Analyzer**

## 2. Abstract:
This project addresses the challenge of manual incident response analysis by developing an automated log analysis tool that reconstructs end-to-end attack lifecycles from multiple log sources. The system automatically correlates events from authentication logs, web server logs, firewall logs, and network packet captures to classify attack phases and extract Indicators of Compromise (IOCs). The solution provides security analysts with a comprehensive web-based dashboard featuring interactive timelines, phase classification, and IOC export capabilities, enabling efficient incident response without requiring commercial SIEM tools.

## 3. Objectives and Solution:

**Objective 1 – Solution:** Multi-source log ingestion and parsing from diverse formats (Apache/Nginx access logs, authentication logs, firewall logs, and .pcap/.pcapng files). Implemented automatic log type detection, timestamp normalization, and regex-based pattern matching for efficient parsing. *[Screenshot: Log upload interface showing multiple file types supported]*

**Objective 2 – Solution:** Automated attack phase classification using rule-based system mapping events to MITRE ATT&CK phases (Reconnaissance, Initial Access, Lateral Movement, Exfiltration). Implemented weighted confidence scoring and pattern matching for accurate classification. *[Screenshot: Attack phases dashboard showing phase distribution and classified events]*

**Objective 3 – Solution:** Interactive timeline visualization and IOC extraction with export functionality. Built Plotly-based timeline showing chronological attack progression and automatic extraction of IPs, domains, URLs, hashes, and user agents with JSON/CSV export. Additionally implemented Quick Log Analysis feature with client-side attack detection for instant analysis of log files and live captured packets, including download capability for captured packets as log files. *[Screenshot: Interactive timeline visualization, IOC export interface, and Log Analysis dashboard]*

## 4. Problem Statement:
Traditional incident response requires security analysts to manually analyze multiple log sources from different systems, making the process time-consuming, error-prone, and inefficient. Analysts struggle to correlate events across different log formats, identify attack progression through various phases, and extract actionable Indicators of Compromise (IOCs). The lack of automated tools for small to medium organizations forces reliance on expensive commercial SIEM solutions, creating a gap in accessible incident response capabilities.

## 5. Proposed Solution:
The project solves this problem through a comprehensive web-based attack flow analyzer that: (1) Ingests and parses multiple log formats automatically, (2) Correlates events by user, IP address, and session using hash-based algorithms, (3) Classifies events into attack phases using rule-based pattern matching with confidence scoring, (4) Generates interactive timelines showing attack progression, (5) Extracts and categorizes IOCs automatically, (6) Provides real-time packet capture and analysis capabilities, (7) Offers quick client-side log analysis with instant attack detection, and (8) Enables download of captured packets as log files for offline analysis. The solution integrates all components into a single Flask-based web dashboard, making it accessible and user-friendly for security analysts.

## 6. Tools & Technologies Used:
- **Programming Language:** Python 3.8+
- **Web Framework:** Flask 3.0+
- **Packet Analysis:** scapy 2.5+, pyshark 0.6
- **Visualization:** Plotly 5.18+
- **UI Framework:** Bootstrap 5
- **Libraries:** python-dateutil (timestamp parsing), validators (URL/domain validation), flask-socketio (real-time updates)
- **Development Tools:** Git, VS Code

## 7. Algorithms / Techniques Used:
- **Regex-based Pattern Matching:** For log parsing and IOC extraction using compiled regular expressions for O(n) complexity
- **Hash-based Correlation:** O(1) lookup using dictionary/hash maps to group events by user, IP, and session identifiers
- **Time-window Correlation:** Groups events within configurable time windows (default 5 minutes) for session-based correlation
- **Rule-based Classification:** Weighted scoring algorithm that matches event patterns against phase-specific rules, calculating confidence scores (0.0-1.0) for each attack phase
- **Event Sorting:** O(n log n) merge sort for chronological timeline construction
- **IOC Deduplication:** Set-based deduplication with metadata tracking (first seen, last seen, event count)
- **Protocol-aware Packet Parsing:** Layer-based packet dissection for TCP, UDP, ICMP, DNS, and HTTP protocols

## 8. Implementation Details:
**Modules:** (1) **Log Ingestion Module:** Parses Apache/Nginx, auth, and firewall logs with automatic format detection. (2) **Correlation Engine:** Groups events using hash maps and time windows. (3) **Phase Classifier:** Applies rule-based classification with confidence scoring from JSON rule files. (4) **Timeline Builder:** Sorts events chronologically and groups by phase. (5) **IOC Extractor:** Uses regex patterns to extract IPs, domains, URLs, hashes, and user agents. (6) **Packet Capture Module:** Real-time capture using scapy with background threading. (7) **Quick Log Analysis Module:** Client-side log parsing and attack detection with Chart.js visualization. (8) **Packet Export Module:** Converts captured packets to log file format for download. (9) **Web Dashboard:** Flask routes for upload, analysis, visualization, and export.

**Workflow:** User uploads logs → Log ingestion parses files → Events correlated by IP/user/session → Phase classifier assigns attack phases → Timeline builder creates chronological view → IOC extractor identifies threats → Results displayed in dashboard with export options. **Alternative Quick Workflow:** User uploads log file or analyzes captured packets → Client-side parser detects attacks instantly → Visual chart and table display results → Option to download captured packets as log file.

## 9. Results:
The system successfully processes multiple log formats, correlates events across sources, classifies attack phases with high accuracy, and extracts comprehensive IOCs. Outputs include: (1) Interactive timeline showing chronological attack progression, (2) Phase distribution statistics and classified events, (3) Comprehensive IOC list with metadata, (4) Correlation groups showing related events, (5) Real-time packet analysis results, (6) Quick log analysis with instant attack detection (Brute Force, SQL Injection, XSS, DDoS, Port Scan, Suspicious Port), (7) Downloadable log files from captured packets. *[Screenshots: Dashboard with statistics, Timeline visualization, Phases breakdown, IOC table, Packet capture interface, Log Analysis with attack chart]*

## 10. Limitations:
- Currently supports common log formats (Apache/Nginx, syslog, generic firewall) - extensible but requires format-specific parsers
- Rule-based classification may miss novel attack patterns not covered in rules - could be enhanced with machine learning
- Limited to text-based logs and standard packet formats (.pcap, .pcapng)
- IOC extraction depends on log/packet content - may miss encoded or obfuscated IOCs
- Live packet capture requires root/administrator privileges on Linux/macOS
- Single-threaded log processing for large files may be slow

## 11. Future Enhancements:
- Machine learning-based phase classification for improved accuracy
- Support for Windows Event Logs and other proprietary formats
- Real-time log streaming from remote sources
- Integration with SIEM systems (Splunk, ELK stack)
- STIX/TAXII export format for threat intelligence sharing
- User authentication and multi-user support with role-based access
- Advanced packet analysis with deep packet inspection (DPI)
- Network flow analysis and visualization
- Automated IOC enrichment from threat intelligence feeds

## 12. Conclusion:
The Incident Response Attack-Flow Analyzer successfully demonstrates practical incident response analysis capabilities, providing security analysts with automated correlation, phase classification, and IOC extraction. The system effectively reconstructs attack lifecycles from multiple log sources, making it valuable for security operations teams. The web-based interface ensures accessibility, while real-time packet capture extends analysis to live network traffic. The project achieved its objectives of automating log analysis, classifying attack phases, and extracting IOCs, providing a foundation for further enhancements with machine learning and additional log format support. This project enhanced understanding of incident response workflows, log analysis techniques, network packet analysis, and web application development for security tools.

## 13. References:
- MITRE ATT&CK Framework - https://attack.mitre.org/
- Flask Documentation - https://flask.palletsprojects.com/
- scapy Documentation - https://scapy.readthedocs.io/
- Plotly Python Documentation - https://plotly.com/python/
- Common Log Format Specification - Apache/Nginx documentation
- PES University Cyber Security Project Compendium
- Python Regular Expressions - https://docs.python.org/3/library/re.html

## 14. Folder Structure:
```
attack_flow_analyzer/
├── code/
│   ├── app.py
│   ├── config.py
│   ├── requirements.txt
│   ├── modules/
│   │   ├── log_ingestion.py
│   │   ├── correlation.py
│   │   ├── phase_classifier.py
│   │   ├── timeline.py
│   │   ├── ioc_extractor.py
│   │   ├── ioc_exporter.py
│   │   ├── packet_capture.py
│   │   └── packet_analyzer.py
│   ├── templates/
│   ├── static/
│   ├── utils/
│   └── rules/
├── dataset_or_logs/
│   └── sample_logs/
│       ├── access.log
│       ├── auth.log
│       └── firewall.log
└── report/
    └── Report.pdf
```

**Team Members:** PES1PG25CS025, PES1PG25CS025, PES1PG25CS025
