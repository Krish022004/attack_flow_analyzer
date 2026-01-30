"""
Multi-Source Log Ingestion Module
Efficiently parses multiple log formats and normalizes data
"""

import re
import json
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from dateutil import parser as date_parser
import config

try:
    from modules.packet_capture import PcapFileParser
    PCAP_AVAILABLE = True
except ImportError:
    PCAP_AVAILABLE = False


class LogParser:
    """Base class for log parsers with common functionality"""
    
    def __init__(self):
        self.parsed_events = []
        self.errors = []
    
    def parse_timestamp(self, timestamp_str: str, log_type: str) -> Optional[datetime]:
        """Normalize timestamps from various formats"""
        formats = [
            '%d/%b/%Y:%H:%M:%S %z',
            '%d/%b/%Y:%H:%M:%S',
            '%b %d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S%z',
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str.strip(), fmt)
            except ValueError:
                continue
        
        # Try dateutil as fallback
        try:
            return date_parser.parse(timestamp_str)
        except:
            self.errors.append(f"Failed to parse timestamp: {timestamp_str}")
            return None
    
    def extract_size(self, size_str: str) -> int:
        """Extract size in bytes from log entry"""
        if size_str == '-' or not size_str:
            return 0
        try:
            return int(size_str)
        except ValueError:
            return 0


class ApacheLogParser(LogParser):
    """Parser for Apache/Nginx access logs"""
    
    def parse(self, log_file: Path, log_format: str = 'combined') -> List[Dict]:
        """Parse Apache/Nginx access log"""
        pattern = config.LOG_PATTERNS.get(f'apache_{log_format}', config.LOG_PATTERNS['apache_combined'])
        events = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    match = pattern.match(line)
                    if match:
                        data = match.groupdict()
                        timestamp = self.parse_timestamp(data.get('timestamp', ''), 'apache')
                        
                        if timestamp:
                            event = {
                                'timestamp': timestamp,
                                'source_ip': data.get('ip', ''),
                                'user': data.get('user', '-'),
                                'method': data.get('method', ''),
                                'path': data.get('path', ''),
                                'protocol': data.get('protocol', ''),
                                'status_code': int(data.get('status', 0)),
                                'size': self.extract_size(data.get('size', '0')),
                                'referer': data.get('referer', ''),
                                'user_agent': data.get('user_agent', ''),
                                'log_type': 'web_access',
                                'log_source': str(log_file.name),
                                'raw_line': line,
                            }
                            events.append(event)
                    else:
                        self.errors.append(f"Line {line_num}: Could not parse")
        
        except Exception as e:
            self.errors.append(f"Error reading {log_file}: {str(e)}")
        
        return events


class AuthLogParser(LogParser):
    """Parser for authentication logs (syslog format)"""
    
    def parse(self, log_file: Path) -> List[Dict]:
        """Parse authentication log"""
        pattern = config.LOG_PATTERNS['syslog_auth']
        events = []
        current_year = datetime.now().year
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    match = pattern.match(line)
                    if match:
                        data = match.groupdict()
                        timestamp_str = f"{data.get('timestamp', '')} {current_year}"
                        timestamp = self.parse_timestamp(timestamp_str, 'auth')
                        
                        if timestamp:
                            message = data.get('message', '')
                            event = {
                                'timestamp': timestamp,
                                'hostname': data.get('hostname', ''),
                                'service': data.get('service', ''),
                                'pid': data.get('pid', ''),
                                'message': message,
                                'log_type': 'authentication',
                                'log_source': str(log_file.name),
                                'raw_line': line,
                            }
                            
                            # Extract IP and user from message
                            ip_match = config.IOC_PATTERNS['ipv4'].search(message)
                            if ip_match:
                                event['source_ip'] = ip_match.group()
                            
                            # Extract username patterns
                            user_match = re.search(r'user[=:]\s*(\S+)', message, re.I)
                            if user_match:
                                event['user'] = user_match.group(1)
                            
                            # Determine action
                            if 'failed' in message.lower() or 'denied' in message.lower():
                                event['action'] = 'failed_login'
                            elif 'accepted' in message.lower() or 'success' in message.lower():
                                event['action'] = 'successful_login'
                            else:
                                event['action'] = 'unknown'
                            
                            events.append(event)
                    else:
                        self.errors.append(f"Line {line_num}: Could not parse")
        
        except Exception as e:
            self.errors.append(f"Error reading {log_file}: {str(e)}")
        
        return events


class FirewallLogParser(LogParser):
    """Parser for firewall logs"""
    
    def parse(self, log_file: Path) -> List[Dict]:
        """Parse firewall log"""
        pattern = config.LOG_PATTERNS['firewall_generic']
        events = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    match = pattern.match(line)
                    if match:
                        data = match.groupdict()
                        timestamp = self.parse_timestamp(data.get('timestamp', ''), 'firewall')
                        
                        if timestamp:
                            event = {
                                'timestamp': timestamp,
                                'action': data.get('action', ''),
                                'protocol': data.get('protocol', ''),
                                'source_ip': data.get('src_ip', ''),
                                'source_port': int(data.get('src_port', 0)),
                                'destination_ip': data.get('dst_ip', ''),
                                'destination_port': int(data.get('dst_port', 0)),
                                'log_type': 'firewall',
                                'log_source': str(log_file.name),
                                'raw_line': line,
                            }
                            events.append(event)
                    else:
                        # Try to extract at least IPs and action
                        ip_match = config.IOC_PATTERNS['ipv4'].findall(line)
                        if ip_match and ('block' in line.lower() or 'allow' in line.lower() or 'deny' in line.lower()):
                            action = 'block' if 'block' in line.lower() or 'deny' in line.lower() else 'allow'
                            timestamp = self.parse_timestamp(line.split()[0] if line.split() else '', 'firewall')
                            
                            if timestamp and ip_match:
                                event = {
                                    'timestamp': timestamp,
                                    'action': action,
                                    'source_ip': ip_match[0] if len(ip_match) > 0 else '',
                                    'destination_ip': ip_match[1] if len(ip_match) > 1 else '',
                                    'log_type': 'firewall',
                                    'log_source': str(log_file.name),
                                    'raw_line': line,
                                }
                                events.append(event)
        
        except Exception as e:
            self.errors.append(f"Error reading {log_file}: {str(e)}")
        
        return events


class LogIngestionEngine:
    """Main log ingestion engine that coordinates parsing"""
    
    def __init__(self):
        self.parsers = {
            'apache': ApacheLogParser(),
            'nginx': ApacheLogParser(),  # Same format
            'auth': AuthLogParser(),
            'firewall': FirewallLogParser(),
        }
        if PCAP_AVAILABLE:
            self.parsers['pcap'] = PcapFileParser()
        self.all_events = []
        self.errors = []
    
    def detect_log_type(self, log_file: Path) -> str:
        """Auto-detect log type from filename and content"""
        filename = log_file.name.lower()
        
        # Check for pcap files first (binary files)
        if filename.endswith('.pcap') or filename.endswith('.pcapng'):
            return 'pcap'
        
        # Check filename patterns
        if 'access' in filename or 'apache' in filename or 'nginx' in filename:
            return 'apache'
        elif 'auth' in filename or 'login' in filename or 'secure' in filename:
            return 'auth'
        elif 'firewall' in filename or 'iptables' in filename or 'pfsense' in filename:
            return 'firewall'
        
        # Check first few lines for patterns (skip for binary files)
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                sample = ''.join([f.readline() for _ in range(5)])
                
                if config.LOG_PATTERNS['apache_combined'].search(sample):
                    return 'apache'
                elif config.LOG_PATTERNS['syslog_auth'].search(sample):
                    return 'auth'
                elif config.LOG_PATTERNS['firewall_generic'].search(sample):
                    return 'firewall'
        except:
            pass
        
        return 'apache'  # Default
    
    def ingest(self, log_files: List[Path], log_types: Optional[Dict[str, str]] = None) -> List[Dict]:
        """Ingest multiple log files"""
        self.all_events = []
        self.errors = []
        
        if log_types is None:
            log_types = {}
        
        for log_file in log_files:
            if not log_file.exists():
                self.errors.append(f"File not found: {log_file}")
                continue
            
            # Determine log type
            log_type = log_types.get(str(log_file), self.detect_log_type(log_file))
            
            if log_type not in self.parsers:
                self.errors.append(f"Unknown log type: {log_type} for {log_file}")
                continue
            
            # Parse log file
            parser = self.parsers[log_type]
            events = parser.parse(log_file)
            self.all_events.extend(events)
            self.errors.extend(parser.errors)
        
        # Sort all events by timestamp
        self.all_events.sort(key=lambda x: x['timestamp'])
        
        return self.all_events
    
    def get_statistics(self) -> Dict:
        """Get ingestion statistics"""
        return {
            'total_events': len(self.all_events),
            'log_types': self._count_by_type(),
            'time_range': self._get_time_range(),
            'errors': len(self.errors),
        }
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count events by log type"""
        counts = {}
        for event in self.all_events:
            log_type = event.get('log_type', 'unknown')
            counts[log_type] = counts.get(log_type, 0) + 1
        return counts
    
    def _get_time_range(self) -> Dict:
        """Get time range of events"""
        if not self.all_events:
            return {}
        
        timestamps = [e['timestamp'] for e in self.all_events if e.get('timestamp')]
        if timestamps:
            return {
                'start': min(timestamps).isoformat(),
                'end': max(timestamps).isoformat(),
                'duration_hours': (max(timestamps) - min(timestamps)).total_seconds() / 3600,
            }
        return {}
