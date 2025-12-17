# Attack Flow Analyzer

A comprehensive Incident Response Attack-Flow Analyzer that reconstructs end-to-end attack lifecycles from multiple log sources. This tool analyzes authentication logs, web server logs, and firewall logs to identify attack phases and extract Indicators of Compromise (IOCs).

## Features

- **Multi-Source Log Ingestion**: Parse Apache/Nginx access logs, authentication logs, and firewall logs
- **Intelligent Correlation**: Group events by user, IP address, and session
- **Attack Phase Classification**: Automatically classify events into attack phases (Reconnaissance, Initial Access, Lateral Movement, Exfiltration)
- **Timeline Visualization**: Interactive timeline showing the chronological sequence of attack events
- **IOC Extraction**: Automatically extract IPs, domains, hashes, URLs, and suspicious user agents
- **Export Capabilities**: Export IOCs in JSON and CSV formats
- **Web Dashboard**: Modern web interface built with Flask and Bootstrap

## Project Structure

```
attack_flow_analyzer/
├── app.py                 # Flask main application
├── config.py             # Configuration settings
├── requirements.txt      # Python dependencies
├── modules/
│   ├── log_ingestion.py  # Multi-source log parser
│   ├── correlation.py   # Event correlation engine
│   ├── phase_classifier.py # Attack phase mapping
│   ├── timeline.py       # Timeline builder
│   ├── ioc_extractor.py  # IOC extraction
│   └── ioc_exporter.py   # IOC export functionality
├── templates/            # HTML templates
├── static/               # CSS and JavaScript files
├── utils/
│   └── log_generator.py  # Sample log generator
├── data/
│   └── sample_logs/      # Sample log files
└── rules/
    └── phase_rules.json  # Attack phase classification rules
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

## Usage

### Starting the Application

1. **Run the Flask application:**
   ```bash
   python app.py
   ```

2. **Access the web interface:**
   Open your browser and navigate to `http://localhost:5000`

### Using the Application

1. **Upload Log Files:**
   - Click on "Upload Logs" in the navigation bar
   - Select one or more log files (Apache/Nginx access logs, authentication logs, firewall logs)
   - Click "Upload Files"
   - Click "Analyze Logs" to start the analysis

2. **View Results:**
   - **Dashboard**: Overview statistics and phase distribution
   - **Timeline**: Interactive timeline visualization of attack events
   - **Phases**: Detailed breakdown of each attack phase
   - **IOCs**: List of extracted Indicators of Compromise with filtering options

3. **Export IOCs:**
   - Navigate to the IOCs page
   - Click "Export JSON" or "Export CSV" to download IOCs

### Generating Sample Logs

The application includes a sample log generator for testing:

```bash
python utils/log_generator.py
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

## Attack Phases

The system classifies events into the following attack phases:

1. **Reconnaissance**: Initial scanning and information gathering
   - Port scans, directory enumeration, DNS queries
   - Access to sensitive files (.git, .env, admin panels)

2. **Initial Access**: Attempts to gain initial access
   - SQL injection attempts
   - XSS attacks
   - Path traversal attempts
   - Failed login attempts

3. **Lateral Movement**: Movement within the network
   - Internal network connections
   - SSH/RDP connections
   - Privilege escalation attempts

4. **Exfiltration**: Data exfiltration activities
   - Large data transfers
   - Suspicious outbound connections
   - Backup/export operations

## IOC Types

The system extracts the following types of IOCs:

- **IP Addresses**: Source and destination IPs from suspicious events
- **Domains**: DNS queries and hostnames from logs
- **File Hashes**: MD5, SHA1, SHA256 hashes (if present)
- **URLs**: Suspicious URLs and endpoints
- **User Agents**: Malicious or suspicious user agents

## Configuration

Configuration settings can be modified in `config.py`:

- Log format patterns
- Attack phase indicators
- IOC extraction patterns
- Correlation settings
- Visualization settings

Attack phase classification rules can be customized in `rules/phase_rules.json`.

## API Endpoints

The application provides the following API endpoints:

- `GET /api/statistics` - Overall statistics
- `GET /api/timeline` - Timeline data
- `GET /api/iocs` - IOC data
- `GET /api/correlation` - Correlation data
- `GET /export/iocs/<format>` - Export IOCs (json/csv)

## Technologies Used

- **Python 3.8+**: Core language
- **Flask**: Web framework
- **Pandas**: Data manipulation
- **Plotly**: Timeline visualization
- **Bootstrap 5**: UI framework

## Algorithm Highlights

### Log Parsing
- Efficient regex-based parsing with pattern matching
- Automatic log type detection
- Timestamp normalization across different formats

### Correlation Engine
- Hash-based grouping for O(1) lookups
- Time-window based correlation
- Multi-dimensional correlation (IP, user, session)

### Phase Classification
- Rule-based classification with confidence scoring
- Pattern matching for attack signatures
- Weighted scoring system for accurate classification

### IOC Extraction
- Pattern-based extraction using regex
- Deduplication and categorization
- Metadata tracking (first seen, last seen, event count)

## Performance

The system is designed for efficiency:

- **O(n log n)** complexity for event sorting
- **O(n)** complexity for correlation grouping
- **O(n)** complexity for IOC extraction
- Efficient memory usage with streaming log parsing

## Limitations

- Currently supports common log formats (extensible)
- Rule-based classification (can be enhanced with ML)
- Limited to text-based logs
- IOC extraction depends on log content

## Future Enhancements

- Machine learning-based phase classification
- Support for more log formats (Windows Event Logs, etc.)
- Real-time log streaming
- Integration with SIEM systems
- STIX/TAXII export format
- User authentication and multi-user support

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
