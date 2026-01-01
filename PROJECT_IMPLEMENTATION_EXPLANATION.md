# Project Implementation Explanation
## Attack Flow Analyzer - Incident Response Tool

### Project Overview
This document explains how the **Attack Flow Analyzer** project was implemented based on the requirements specified in `project.md`. The project reconstructs end-to-end attack lifecycles from multiple log sources using Python and modern web technologies.

---

## 1. Project Concept Implementation

**Requirement**: A log analysis tool that reconstructs an end-to-end attack lifecycle from multiple log sources.

**Implementation**:
- Built a comprehensive Flask-based web application (`app.py`)
- Implemented a modular architecture with 5 core modules
- Created a web-based GUI dashboard for visualization
- Designed to process logs from multiple sources simultaneously

---

## 2. Inputs Implementation

### 2.1 Multiple Log Sources
**Requirement**: Authentication logs, web server logs, firewall logs, and other text-based logs.

**Implementation** (`modules/log_ingestion.py`):
- **ApacheLogParser**: Parses Apache/Nginx access logs (Common and Combined formats)
- **AuthLogParser**: Parses authentication logs in syslog format (SSH, login attempts)
- **FirewallLogParser**: Parses firewall logs with IP and port information
- **LogIngestionEngine**: Coordinates all parsers with automatic log type detection

**Key Features**:
- Auto-detection of log type from filename and content patterns
- Timestamp normalization across different formats using `dateutil` library
- Robust error handling and logging
- Support for multiple log formats via regex pattern matching

### 2.2 Mapping Rules/Templates
**Requirement**: Mapping rules or templates for each attack phase.

**Implementation** (`rules/phase_rules.json`):
- JSON configuration file defining rules for 4 attack phases:
  - **Reconnaissance**: URL patterns, status codes, user agents
  - **Initial Access**: SQL injection, XSS, path traversal patterns
  - **Lateral Movement**: Internal IP ranges, protocol indicators
  - **Exfiltration**: File extensions, endpoints, transfer sizes
- Weighted confidence scoring system for each indicator
- Configurable thresholds and patterns

---

## 3. Outputs Implementation

### 3.1 Chronological Timeline
**Requirement**: Chronological timeline of key attacker activities.

**Implementation** (`modules/timeline.py` + `templates/timeline.html`):
- **TimelineBuilder** class builds chronological sequences
- Sorts all events by timestamp
- Groups events by attack phase
- Calculates phase durations and transitions
- Visual timeline using Plotly.js interactive charts
- API endpoint `/api/timeline` for data retrieval

**Visualization**:
- Interactive scatter plot showing events over time
- Color-coded by attack phase
- Hover tooltips with event details
- Filterable by phase, IP, and time range

### 3.2 Labelled Phases
**Requirement**: Labelled phases of the attack with associated log events.

**Implementation** (`modules/phase_classifier.py` + `templates/phases.html`):
- **PhaseClassifier** class maps events to kill-chain stages
- Rule-based classification with confidence scoring (0.0-1.0)
- Each event assigned to: Reconnaissance, Initial Access, Lateral Movement, Exfiltration, or Unknown
- Visual phase flow diagram showing attack progression
- Phase statistics: count, percentage, average confidence, duration

**Classification Algorithm**:
- Multi-indicator scoring system
- Weighted confidence calculation
- Pattern matching for attack signatures
- Context-aware classification (e.g., failed login attempts over time)

### 3.3 IOC List
**Requirement**: Indicators of Compromise (IOCs) list - IPs, domains, file hashes.

**Implementation** (`modules/ioc_extractor.py` + `templates/iocs.html`):
- **IOCExtractor** class extracts multiple IOC types:
  - **IP Addresses**: Source and destination IPs (IPv4)
  - **Domains**: DNS queries and hostnames
  - **File Hashes**: MD5, SHA1, SHA256
  - **URLs**: Suspicious URLs and endpoints
  - **User Agents**: Malicious or suspicious user agents
- Deduplication and categorization
- Metadata tracking: first seen, last seen, event count, associated phases
- Filterable and sortable IOC table with pagination

---

## 4. Main Modules Implementation

### 4.1 Multi-Source Log Ingestion Module
**File**: `modules/log_ingestion.py`

**Key Classes**:
- `LogParser`: Base class with common parsing utilities
- `ApacheLogParser`: Handles web server logs
- `AuthLogParser`: Handles authentication logs
- `FirewallLogParser`: Handles firewall logs
- `LogIngestionEngine`: Main coordinator

**Algorithms Used**:
- **Regex Pattern Matching**: For parsing log lines (O(n) complexity)
- **Timestamp Normalization**: Multiple format support with fallback parsing
- **Error Recovery**: Continues parsing even with malformed lines

**Statistics Provided**:
- Total events parsed
- Events by log type
- Time range coverage
- Error count

### 4.2 Correlation Engine
**File**: `modules/correlation.py`

**Requirement**: Groups events by user, IP, or session.

**Implementation**:
- **CorrelationGroup** class: Represents groups with metadata
- Three correlation methods:
  1. **IP Correlation**: Groups by source/destination IP with time windows
  2. **User Correlation**: Groups by username with 7-day window
  3. **Session Correlation**: Time-based sessions with 30-minute timeout

**Algorithms Used**:
- **Hash-based Grouping**: O(1) lookup for group membership
- **Time-window Correlation**: Efficient sliding window algorithm (O(n))
- **Event Indexing**: Maps events to multiple correlation groups

**Features**:
- Configurable time windows per correlation type
- First seen/last seen timestamps
- Event count per group
- Duration calculation

### 4.3 Phase Classifier
**File**: `modules/phase_classifier.py`

**Requirement**: Maps events to stages of kill-chain.

**Implementation**:
- **PhaseClassifier** class with rule-based classification
- Loads rules from `rules/phase_rules.json`
- Multi-indicator scoring system:
  - URL pattern matching
  - Status code analysis
  - SQL injection detection (regex patterns)
  - XSS detection (regex patterns)
  - Path traversal detection
  - Failed login analysis (time-window based)
  - Internal IP detection
  - Large transfer detection

**Algorithm**:
1. Score each indicator for each phase (0.0-1.0)
2. Apply weighted confidence calculation
3. Select phase with highest confidence
4. Threshold-based classification (0.1 minimum confidence)

**Output**: Each event tagged with:
- Primary attack phase
- Confidence score (0.0-1.0)
- Detailed phase scores breakdown

### 4.4 Timeline Visualizer
**File**: `modules/timeline.py` + `templates/timeline.html`

**Requirement**: Graphical view of attack flow.

**Implementation**:
- **TimelineBuilder** class:
  - Sorts events chronologically (O(n log n))
  - Groups events by phase
  - Calculates phase durations
  - Identifies phase transitions
- Interactive Plotly.js visualization
- Filter controls (phase, IP, time range)
- Event details modal
- Export functionality

**Visualization Features**:
- Scatter plot with phase-based coloring
- Hover tooltips with event details
- Phase legend with click-to-filter
- Responsive design for mobile/tablet

### 4.5 IOC Exporter
**File**: `modules/ioc_exporter.py`

**Requirement**: Export for reporting and further defence activities.

**Implementation**:
- **IOCExporter** class supports multiple formats:
  - **JSON Export**: Structured data with metadata
  - **CSV Export**: Table format for spreadsheets
- Export by type (grouped exports)
- Summary statistics included
- Downloadable files via Flask routes

**Export Features**:
- Metadata: export time, total IOCs, format version
- Complete IOC data with all fields
- Organized by IOC type (optional)

---

## 5. Learning Component Implementation

**Requirement**: Tracks which attack phase occurs most frequently or lasts longest.

**Implementation** (`modules/timeline.py`):
- **get_statistics()** method provides:
  - Most frequent phase (highest event count)
  - Longest phase (greatest duration)
  - Phase duration calculations
  - Transition analysis
- Displayed on Dashboard and Phases pages
- Helps prioritize defence activities based on:
  - Which phase has most events (where attacker spends most time)
  - Which phase lasts longest (persistence indicator)

---

## 6. Technology Stack

### Backend (Python)
- **Flask 3.0+**: Web framework for REST API and routing
- **Python 3.8+**: Core language
- **pathlib**: Modern file path handling
- **dateutil**: Timestamp parsing and normalization
- **ipaddress**: IP address validation (standard library)
- **re**: Regex pattern matching (standard library)

### Frontend
- **Bootstrap 5**: Responsive UI framework
- **Font Awesome 6**: Icon library
- **Plotly.js**: Interactive charting library
- **Vanilla JavaScript**: No jQuery dependency

### Data Formats
- **JSON**: Configuration files, API responses, exports
- **CSV**: IOC exports
- **Log Formats**: Apache Combined, Syslog, Generic Firewall

---

## 7. Architecture & Design Patterns

### Modular Architecture
Each module is self-contained with clear interfaces:
- Single Responsibility Principle
- Dependency Injection (config files)
- Factory Pattern (parser selection)

### Data Flow
```
Log Files → Log Ingestion → Events
Events → Correlation → Correlated Groups
Events → Phase Classifier → Classified Events
Classified Events → Timeline Builder → Timeline
Classified Events → IOC Extractor → IOCs
IOCs → IOC Exporter → JSON/CSV Files
```

### API Design
- RESTful endpoints:
  - `/api/statistics`: Overall statistics
  - `/api/timeline`: Timeline data
  - `/api/iocs`: IOC list
  - `/api/correlation`: Correlation groups
  - `/export/iocs/<format>`: IOC export

---

## 8. Algorithms & Complexity Analysis

### Log Parsing
- **Complexity**: O(n) where n = number of log lines
- **Method**: Regex pattern matching per line
- **Optimization**: Streaming parser (processes line-by-line)

### Correlation
- **Complexity**: O(n log n) for sorting + O(n) for grouping = O(n log n)
- **Method**: Hash-based grouping with time windows
- **Optimization**: Single-pass algorithm with hash tables

### Phase Classification
- **Complexity**: O(n × m) where n = events, m = pattern rules
- **Method**: Rule-based pattern matching with weighted scoring
- **Optimization**: Compiled regex patterns, cached rule loading

### Timeline Building
- **Complexity**: O(n log n) for sorting
- **Method**: Merge sort equivalent (Python's Timsort)
- **Optimization**: In-place sorting when possible

### IOC Extraction
- **Complexity**: O(n × p) where n = events, p = IOC patterns
- **Method**: Regex extraction with deduplication
- **Optimization**: Set-based deduplication (O(1) lookups)

---

## 9. User Interface Features

### Dashboard (`templates/index.html`)
- Statistics cards with animated counters
- Phase distribution chart
- Quick actions for upload and sample generation
- Real-time statistics updates

### Upload Page (`templates/upload.html`)
- Drag-and-drop file upload
- File preview with size indicators
- Progress bars for upload and analysis
- Multiple file support

### Timeline Page (`templates/timeline.html`)
- Interactive timeline visualization
- Filters (phase, IP, time range)
- Event details modal
- Export functionality
- Sortable event table with pagination

### Phases Page (`templates/phases.html`)
- Visual attack flow diagram
- Phase statistics cards
- Progress indicators
- Timeline statistics

### IOCs Page (`templates/iocs.html`)
- Statistics cards (horizontal layout)
- Advanced filtering (type, phase, search)
- Sortable columns
- Pagination
- IOC detail modals
- Export buttons

---

## 10. Configuration & Customization

### Configuration File (`config.py`)
- Log format patterns (regex)
- Attack phase indicators
- IOC extraction patterns
- Correlation settings (time windows)
- Visualization settings (colors, sizes)

### Rules File (`rules/phase_rules.json`)
- Phase-specific indicators
- Confidence weights
- Thresholds
- Pattern definitions

---

## 11. Error Handling & Robustness

- Try-except blocks around file operations
- Graceful degradation for malformed logs
- User-friendly error messages
- Logging for debugging
- Input validation
- File size limits (100MB per file)

---

## 12. Testing & Sample Data

### Sample Log Generator (`utils/log_generator.py`)
- Generates realistic attack scenarios
- Includes all 4 attack phases
- Multiple log types (access, auth, firewall)
- Configurable event counts

---

## 13. Meeting Project Requirements

### ✅ All Required Inputs
- [x] Authentication logs support
- [x] Web server logs support
- [x] Firewall logs support
- [x] Mapping rules/templates (phase_rules.json)

### ✅ All Required Outputs
- [x] Chronological timeline
- [x] Labelled phases with events
- [x] IOC list (IPs, domains, hashes)

### ✅ All 5 Main Modules
- [x] Multi-Source Log Ingestion Module
- [x] Correlation Engine (IP, user, session)
- [x] Phase Classifier (kill-chain mapping)
- [x] Timeline Visualizer (graphical view)
- [x] IOC Exporter (JSON/CSV)

### ✅ Learning Component
- [x] Most frequent phase tracking
- [x] Longest phase tracking
- [x] Phase duration calculations

### ✅ Use Case/Purpose
- [x] Practical incident response analysis
- [x] No commercial SIEM required
- [x] Web-based GUI dashboard

---

## 14. Additional Features Implemented

Beyond the basic requirements:
- Modern, responsive UI/UX design
- Toast notification system
- Drag-and-drop file upload
- Advanced filtering and search
- Pagination for large datasets
- Export functionality
- Real-time statistics updates
- Interactive visualizations
- Mobile-friendly design
- Detailed IOC metadata
- Phase confidence scoring
- Transition analysis

---

## 15. Project Structure

```
attack_flow_analyzer/
├── app.py                          # Flask main application
├── config.py                       # Configuration settings
├── modules/
│   ├── log_ingestion.py           # Module 1: Multi-source log parser
│   ├── correlation.py             # Module 2: Correlation engine
│   ├── phase_classifier.py        # Module 3: Phase classification
│   ├── timeline.py                # Module 4: Timeline builder
│   ├── ioc_extractor.py           # Module 5: IOC extraction
│   └── ioc_exporter.py            # Module 5: IOC export
├── templates/                      # HTML templates (GUI)
├── static/
│   ├── css/                       # Styling
│   └── js/                        # JavaScript functionality
├── rules/
│   └── phase_rules.json           # Attack phase rules
├── utils/
│   └── log_generator.py           # Sample log generator
└── data/
    └── sample_logs/               # Sample log files
```

---

## 16. Key Algorithms Explained

### 1. Log Parsing Algorithm
- Uses regex patterns to match log line structures
- Extracts fields: timestamp, IP, path, status code, etc.
- Normalizes timestamps to datetime objects
- Handles multiple log formats with pattern matching

### 2. Correlation Algorithm
- Creates hash maps for fast lookups (O(1))
- Groups events by key (IP/user/session)
- Applies time windows to determine group membership
- Maintains metadata for each group

### 3. Phase Classification Algorithm
- Scores each event against phase indicators
- Uses weighted average for confidence calculation
- Selects phase with highest confidence
- Applies threshold to avoid false positives

### 4. Timeline Building Algorithm
- Sorts events by timestamp (O(n log n))
- Groups by phase for visualization
- Calculates durations using min/max timestamps
- Identifies transitions between phases

### 5. IOC Extraction Algorithm
- Uses regex patterns to find IOCs in event data
- Deduplicates using dictionaries/sets
- Tracks metadata: first seen, last seen, count
- Categorizes by type (IP, domain, hash, etc.)

---

## 17. How to Present This Project

### Introduction (1-2 minutes)
- "I've implemented Project 14: Incident Response Attack-Flow Analyzer"
- "This tool reconstructs end-to-end attack lifecycles from multiple log sources"
- "Built using Python Flask with a modular architecture"

### Core Modules (3-4 minutes)
1. **Log Ingestion**: "Handles multiple log formats with auto-detection"
2. **Correlation**: "Groups events by IP, user, and session using efficient algorithms"
3. **Phase Classification**: "Maps events to kill-chain phases using rule-based classification"
4. **Timeline**: "Creates chronological visualization of the attack"
5. **IOC Extraction**: "Extracts and exports indicators of compromise"

### Technical Highlights (2-3 minutes)
- Algorithms: O(n log n) sorting, O(n) correlation, hash-based grouping
- Technologies: Flask, Bootstrap, Plotly.js, Python
- Features: Real-time analysis, interactive visualizations, export capabilities

### Demonstration (2-3 minutes)
- Show upload process
- Demonstrate analysis flow
- Show timeline visualization
- Display IOC extraction results
- Show export functionality

---

## Conclusion

This project successfully implements all requirements from `project.md`:
- ✅ All 5 main modules fully functional
- ✅ All required inputs and outputs
- ✅ Learning component for phase analysis
- ✅ Modern web-based GUI
- ✅ Comprehensive error handling
- ✅ Extensible and maintainable code structure

The implementation demonstrates understanding of:
- Python programming and web development
- Log analysis and parsing
- Security incident response
- Data visualization
- Algorithm design and optimization

