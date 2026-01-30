# Attack Flow Analyzer

A comprehensive Incident Response Attack-Flow Analyzer that reconstructs end-to-end attack lifecycles from multiple log sources. This tool analyzes authentication logs, web server logs, firewall logs, and network packet captures to identify attack phases and extract Indicators of Compromise (IOCs).

## Features

- **Multi-Source Log Ingestion**: Parse Apache/Nginx access logs, authentication logs, firewall logs, and packet capture files (.pcap, .pcapng)
- **Live Packet Capture**: Capture and analyze real-time network traffic using scapy
- **Quick Log Analysis**: Client-side log analysis with instant attack detection (Brute Force, SQL Injection, XSS, DDoS, Port Scan, Suspicious Port)
- **Packet-to-Log Integration**: Analyze live captured packets directly in the Log Analysis interface
- **Download Captured Packets**: Export captured packets as downloadable log files for offline analysis
- **Intelligent Correlation**: Group events by user, IP address, and session
- **Attack Phase Classification**: Automatically classify events into attack phases (Reconnaissance, Initial Access, Lateral Movement, Exfiltration)
- **Timeline Visualization**: Interactive timeline showing the chronological sequence of attack events
- **IOC Extraction**: Automatically extract IPs, domains, hashes, URLs, and suspicious user agents
- **Export Capabilities**: Export IOCs in JSON and CSV formats
- **Web Dashboard**: Modern web interface built with Flask and Bootstrap 5

## Project Structure

```
attack_flow_analyzer/
├── app.py                 # Flask main application
├── config.py             # Configuration settings
├── requirements.txt      # Python dependencies
├── project.md            # Project requirements and specifications
├── modules/
│   ├── log_ingestion.py  # Multi-source log parser
│   ├── correlation.py   # Event correlation engine
│   ├── phase_classifier.py # Attack phase mapping
│   ├── timeline.py       # Timeline builder
│   ├── ioc_extractor.py  # IOC extraction
│   ├── ioc_exporter.py   # IOC export functionality
│   ├── packet_capture.py # Packet capture and pcap parsing
│   └── packet_analyzer.py # Packet analysis and attack detection
├── templates/            # HTML templates
│   ├── index.html        # Dashboard
│   ├── upload.html       # Log upload interface
│   ├── timeline.html     # Timeline visualization
│   ├── phases.html       # Attack phases view
│   ├── iocs.html         # IOCs view
│   ├── packet_capture.html # Packet capture interface
│   └── log_analysis.html  # Quick log analysis interface
├── static/               # CSS and JavaScript files
│   ├── css/
│   │   ├── style.css     # Main stylesheet
│   │   └── components.css # Component styles
│   └── js/
│       ├── main.js       # Common utilities
│       ├── dashboard.js  # Dashboard logic
│       ├── upload.js     # Upload functionality
│       ├── timeline.js   # Timeline visualization
│       ├── iocs.js       # IOCs table management
│       ├── packet_capture.js # Packet capture UI
│       └── log_analysis.js  # Quick log analysis and attack detection
├── utils/
│   └── log_generator.py  # Sample log generator
├── data/
│   └── sample_logs/      # Sample log files
└── rules/
    ├── phase_rules.json  # Attack phase classification rules
    └── packet_rules.json # Packet analysis rules
```

## Installation

1. **Clone or navigate to the project directory:**
   ```bash
   cd attack_flow_analyzer
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **For packet capture features (optional but recommended):**
   ```bash
   # Install scapy (required for packet capture)
   pip install scapy
   
   # On Linux/macOS, you may need root privileges for live capture
   # Run the application with: sudo python3 app.py
   ```

## Usage

### Starting the Application

1. **Run the Flask application:**
   ```bash
   python3 app.py
   ```
   
   For live packet capture (requires root privileges on Linux/macOS):
   ```bash
   sudo python3 app.py
   ```

2. **Access the web interface:**
   Open your browser and navigate to `http://localhost:5001`

### Using the Application

1. **Upload Log Files:**
   - Click on "Upload Logs" in the navigation bar
   - Select one or more log files (Apache/Nginx access logs, authentication logs, firewall logs, or .pcap/.pcapng files)
   - Click "Upload Files"
   - Click "Analyze Logs" to start the analysis

2. **Live Packet Capture:**
   - Navigate to "Packet Capture" in the navigation bar
   - Upload a .pcap or .pcapng file, OR
   - Start live capture by:
     - Selecting a network interface (optional, defaults to all interfaces)
     - Setting packet count limit (default: 1000)
     - Setting duration limit in seconds (optional)
     - Click "Start Capture"
   - Stop capture when done
   - Click "Analyze Packets" to process captured packets

3. **Quick Log Analysis:**
   - Navigate to "Log Analysis" in the navigation bar
   - Upload a log file (.log or .txt) for instant client-side analysis, OR
   - Click "Analyze Captured Packets" to analyze live captured packets
   - View attack distribution chart, detected attacks list, and detailed attack table
   - Download captured packets as log file for offline analysis

4. **View Results:**
   - **Dashboard**: Overview statistics and phase distribution
   - **Timeline**: Interactive timeline visualization of attack events
   - **Phases**: Detailed breakdown of each attack phase
   - **IOCs**: List of extracted Indicators of Compromise with filtering options
   - **Log Analysis**: Quick attack detection with visualizations

5. **Export IOCs:**
   - Navigate to the IOCs page
   - Click "Export JSON" or "Export CSV" to download IOCs

6. **Download Captured Packets:**
   - After capturing packets, navigate to "Packet Capture" or "Log Analysis" page
   - Click "Download as Log File" to export captured packets as a .log file
   - The downloaded file can be analyzed later or shared with other tools

### Generating Sample Logs

The application includes a sample log generator for testing:

```bash
python3 utils/log_generator.py
```

This will generate sample log files in `data/sample_logs/` directory.

## Supported Log Formats

### Apache/Nginx Access Logs
- Common Log Format
- Combined Log Format

### Authentication Logs
- Syslog format
- SSH authentication logs
- General authentication events

### Firewall Logs
- Generic firewall format
- IP-based blocking/allowing events

### Network Packet Capture Files
- **.pcap** files (Wireshark/tcpdump format)
- **.pcapng** files (Next Generation capture format)
- Supports TCP, UDP, ICMP, DNS, and HTTP protocols
- Extracts IP addresses, ports, protocols, and payload data

## Attack Phases

The system classifies events into the following attack phases:

1. **Reconnaissance**: Initial scanning and information gathering
   - Port scans, directory enumeration, DNS queries
   - Access to sensitive files (.git, .env, admin panels)
   - Network scanning activities

2. **Initial Access**: Attempts to gain initial access
   - SQL injection attempts
   - XSS attacks
   - Path traversal attempts
   - Failed login attempts
   - Suspicious HTTP requests

3. **Lateral Movement**: Movement within the network
   - Internal network connections
   - SSH/RDP connections
   - Privilege escalation attempts
   - Internal IP communication patterns

4. **Exfiltration**: Data exfiltration activities
   - Large data transfers
   - Suspicious outbound connections
   - Backup/export operations
   - DNS exfiltration patterns

## IOC Types

The system extracts the following types of IOCs:

- **IP Addresses**: Source and destination IPs from suspicious events
- **Domains**: DNS queries and hostnames from logs
- **File Hashes**: MD5, SHA1, SHA256 hashes (if present)
- **URLs**: Suspicious URLs and endpoints
- **User Agents**: Malicious or suspicious user agents
- **Ports**: Suspicious port numbers from packet captures

## Configuration

Configuration settings can be modified in `config.py`:

- Log format patterns
- Attack phase indicators
- IOC extraction patterns
- Correlation settings
- Visualization settings

Attack phase classification rules can be customized in `rules/phase_rules.json`.  
Packet analysis rules can be customized in `rules/packet_rules.json`.

## API Endpoints

The application provides the following API endpoints:

### Analysis Endpoints
- `GET /api/statistics` - Overall statistics
- `GET /api/timeline` - Timeline data
- `GET /api/iocs` - IOC data
- `GET /api/correlation` - Correlation data
- `GET /export/iocs/<format>` - Export IOCs (json/csv)

### Packet Capture Endpoints
- `GET /packet-capture` - Packet capture interface page
- `POST /capture/start` - Start live packet capture
- `POST /capture/stop` - Stop live packet capture
- `GET /capture/status` - Get capture status
- `GET /capture/packets` - Get all captured packets (JSON)
- `GET /capture/download` - Download captured packets as log file
- `POST /analyze/packets` - Analyze captured packets

### Log Analysis Endpoints
- `GET /log-analysis` - Quick log analysis interface page

## Technologies Used

- **Python 3.8+**: Core language
- **Flask 3.0+**: Web framework
- **Plotly 5.18+**: Timeline visualization
- **Bootstrap 5**: UI framework
- **scapy 2.5+**: Packet manipulation and network analysis
- **python-dateutil**: Robust timestamp parsing
- **validators**: URL and domain validation
- **Chart.js**: Client-side attack visualization
- **flask-socketio**: Real-time WebSocket communication for live packet streaming

## Algorithm Highlights

### Log Parsing
- Efficient regex-based parsing with pattern matching
- Automatic log type detection
- Timestamp normalization across different formats
- Support for multiple log formats simultaneously

### Packet Capture & Analysis
- Real-time packet capture using scapy
- Protocol-aware packet parsing (TCP, UDP, ICMP, DNS, HTTP)
- Attack pattern detection in network traffic
- Conversion of packets to standardized event format
- Export captured packets as log files for compatibility with log analysis tools

### Quick Log Analysis
- Client-side log file parsing and analysis
- Instant attack detection without server processing
- Pattern matching for common attacks (Brute Force, SQL Injection, XSS, DDoS)
- Packet-based attack detection (Port Scan, Suspicious Port)
- Real-time packet status checking
- Integration with live packet capture data
- Visual attack distribution using Chart.js

### Correlation Engine
- Hash-based grouping for O(1) lookups
- Time-window based correlation
- Multi-dimensional correlation (IP, user, session)

### Phase Classification
- Rule-based classification with confidence scoring
- Pattern matching for attack signatures
- Weighted scoring system for accurate classification
- Supports both log-based and packet-based events

### IOC Extraction
- Pattern-based extraction using regex
- Deduplication and categorization
- Metadata tracking (first seen, last seen, event count)
- Cross-source IOC correlation

## Performance

The system is designed for efficiency:

- **O(n log n)** complexity for event sorting
- **O(n)** complexity for correlation grouping
- **O(n)** complexity for IOC extraction
- Efficient memory usage with streaming log parsing
- Background thread processing for live packet capture

## Limitations

- Currently supports common log formats (extensible)
- Rule-based classification (can be enhanced with ML)
- Limited to text-based logs and standard packet formats
- IOC extraction depends on log/packet content
- Live packet capture requires root/administrator privileges

## Future Enhancements

- Machine learning-based phase classification
- Support for more log formats (Windows Event Logs, etc.)
- Real-time log streaming
- Integration with SIEM systems
- STIX/TAXII export format
- User authentication and multi-user support
- Advanced packet analysis (deep packet inspection)
- Network flow analysis and visualization

## Contributing

This is an academic project. For improvements or bug fixes, please follow standard development practices.

## License

This project is developed for academic purposes as part of the Cyber Security course.

## Author

Developed as part of the PES University Cyber Security Mini Project.

## Acknowledgments

- MITRE ATT&CK framework for attack phase definitions
- Common log formats and standards
- Open-source security tools and frameworks
- scapy project for packet manipulation capabilities
