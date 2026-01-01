# Live Packet Capture Analysis Flow

## Overview
This document explains how live packet capture works and how captured packets are analyzed in the Attack Flow Analyzer.

## Live Capture Flow

### 1. Starting Capture (`/capture/start`)
- User provides:
  - Network interface (optional, defaults to all interfaces)
  - Packet count limit (default: 1000)
  - Duration limit in seconds (optional)
- `LiveCapture` object is created
- `start_capture()` starts a background thread
- Packets are captured using `scapy.sniff()` and queued in `capture_queue`
- Capture runs until:
  - Packet count limit is reached, OR
  - Duration limit is reached, OR
  - User manually stops capture

### 2. During Capture
- Packets are continuously added to `capture_queue`
- Status can be checked via `/capture/status` endpoint
- Status shows:
  - `is_capturing`: Boolean flag
  - `queued_packets`: Number of packets in queue
  - `packets_captured`: Number of processed packets
  - `statistics`: Protocol distribution

### 3. Stopping Capture (`/capture/stop`)
- `stop_capture()` is called
- `stop_event` is set to signal capture thread to stop
- Capture thread joins (waits up to 5 seconds)
- All queued packets are processed:
  - Each packet is converted to event format using `PcapFileParser._packet_to_event()`
  - Events are stored in `captured_packets`
  - Statistics are updated
- Events are returned and stored in `capture_state['captured_events']`

## Packet Analysis Flow

### 1. Packet to Event Conversion
When packets are processed, they're converted to a standardized event format:

```python
{
    'timestamp': datetime,
    'log_type': 'packet_capture',
    'log_source': 'live_capture',
    'source_ip': str,
    'destination_ip': str,
    'source_port': int,
    'destination_port': int,
    'protocol': str,  # 'tcp', 'udp', 'icmp', 'dns', 'http'
    'packet_size': int,
    'raw_data': {
        'tcp_flags': int,
        'payload_size': int,
        'dns_query': str,  # if DNS
        'dns_answer': str,  # if DNS
        'icmp_type': int,   # if ICMP
        'icmp_code': int    # if ICMP
    },
    'payload': bytes,  # First 1000 bytes
    'path': str,       # HTTP path (if HTTP)
    'method': str,     # HTTP method (if HTTP)
    'status_code': int # HTTP status (if HTTP response)
}
```

### 2. Attack Pattern Detection (`/analyze/packets`)
The `PacketAnalyzer` class detects various attack patterns:

#### Port Scanning
- Detects when a source IP scans multiple ports on a destination
- Threshold: 10+ different ports
- Confidence: Based on number of ports scanned

#### SYN Flood
- Detects SYN flood attacks (many SYN packets without ACK)
- Threshold: 50+ SYN packets with <10% SYN-ACK ratio
- Confidence: Based on number of SYN packets

#### DNS Exfiltration
- Detects DNS-based data exfiltration
- Indicators:
  - Long domain names (>50 chars)
  - Base64-like patterns in domain names
  - Excessive subdomains (>5 levels)
- Confidence: 0.5-0.7

#### Large Data Transfers
- Detects large data transfers (potential exfiltration)
- Threshold: 10MB+ total transfer between IPs
- Confidence: Based on transfer size

#### Suspicious Payloads
- Detects SQL injection and XSS attempts in payloads
- Patterns:
  - SQL: `SELECT.*FROM`, `UNION.*SELECT`, `DROP.*TABLE`, etc.
  - XSS: `<script`, `javascript:`, `onerror=`, etc.
- Confidence: 0.7-0.8

#### Internal Communication (Lateral Movement)
- Detects internal-to-internal communication
- Focuses on suspicious ports: 22 (SSH), 3389 (RDP), 445 (SMB), 5985/5986 (WinRM)
- Confidence: 0.6

### 3. Full Analysis Pipeline
After packet analysis, events go through the standard analysis pipeline:

1. **Packet Analysis** (`PacketAnalyzer.analyze_all()`)
   - Detects attack patterns
   - Adds `attack_indicator` and `attack_confidence` to events

2. **Correlation** (`CorrelationEngine.correlate_all()`)
   - Groups events by user, IP, session
   - Creates correlation groups

3. **Phase Classification** (`PhaseClassifier.classify_all()`)
   - Maps events to attack phases:
     - Reconnaissance
     - Initial Access
     - Lateral Movement
     - Exfiltration
   - Uses attack indicators from packet analysis

4. **Timeline Building** (`TimelineBuilder.build_timeline()`)
   - Creates chronological timeline
   - Groups events by phase

5. **IOC Extraction** (`IOCExtractor.extract_all()`)
   - Extracts IPs, domains, URLs, user agents
   - Tracks metadata (first seen, last seen, count)

## Usage Example

```python
# 1. Start capture
POST /capture/start
{
    "interface": "eth0",      # Optional
    "packet_count": 1000,     # Optional, default 1000
    "duration": 60            # Optional, seconds
}

# 2. Check status (optional, can poll)
GET /capture/status
# Returns: { "is_capturing": true, "queued_packets": 150, ... }

# 3. Stop capture
POST /capture/stop
# Returns: { "success": true, "packets_captured": 1000, ... }

# 4. Analyze packets
POST /analyze/packets
# Returns: {
#   "success": true,
#   "packet_statistics": { ... },
#   "total_events": 1000,
#   ...
# }
```

## Key Points

1. **Thread Safety**: Capture runs in a background thread to avoid blocking
2. **Queue-Based**: Packets are queued during capture and processed when stopped
3. **Event Format**: Packets are converted to the same event format as log files
4. **Unified Analysis**: Packet events go through the same analysis pipeline as log events
5. **Attack Detection**: Packet analyzer detects network-level attack patterns
6. **Phase Mapping**: Attack indicators are mapped to MITRE ATT&CK phases

## Troubleshooting

- **No packets captured**: Check if interface has traffic, verify permissions (root required)
- **Capture not stopping**: Check if stop_event is being set correctly
- **Analysis fails**: Ensure packets were captured and stopped before analyzing
- **Missing protocols**: HTTP layers require `scapy.layers.http` (optional dependency)

