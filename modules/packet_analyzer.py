"""
Packet Analyzer Module
Analyzes packets for attack patterns and suspicious network activity
"""

import re
import ipaddress
from typing import List, Dict, Set
from collections import defaultdict
from datetime import datetime, timedelta


class PacketAnalyzer:
    """Analyzes packet events for attack patterns"""
    
    def __init__(self):
        self.port_scan_threshold = 10  # Number of ports to consider scan
        self.time_window_minutes = 5
        self.suspicious_ports = [22, 23, 80, 443, 3389, 3306, 5432, 8080, 8443]
    
    def detect_port_scan(self, events: List[Dict]) -> List[Dict]:
        """Detect port scanning activity"""
        scan_events = []
        ip_port_combinations = defaultdict(set)
        
        # Group by source IP and destination IP
        for event in events:
            if event.get('protocol') in ['tcp', 'udp']:
                src_ip = event.get('source_ip', '')
                dst_ip = event.get('destination_ip', '')
                dst_port = event.get('destination_port', 0)
                
                if src_ip and dst_ip and dst_port:
                    key = f"{src_ip}:{dst_ip}"
                    ip_port_combinations[key].add(dst_port)
        
        # Check for port scans (many ports to same destination)
        for key, ports in ip_port_combinations.items():
            if len(ports) >= self.port_scan_threshold:
                src_ip, dst_ip = key.split(':')
                # Mark events from this IP as port scan
                for event in events:
                    if (event.get('source_ip') == src_ip and 
                        event.get('destination_ip') == dst_ip and
                        event.get('protocol') in ['tcp', 'udp']):
                        event['attack_indicator'] = 'port_scan'
                        event['attack_confidence'] = min(len(ports) / 50.0, 1.0)
                        scan_events.append(event)
        
        return scan_events
    
    def detect_syn_flood(self, events: List[Dict]) -> List[Dict]:
        """Detect SYN flood attacks (many SYN packets without ACK)"""
        syn_count = defaultdict(int)
        syn_ack_count = defaultdict(int)
        
        # Count SYN and SYN-ACK packets per destination
        for event in events:
            if event.get('protocol') == 'tcp':
                tcp_flags = event.get('raw_data', {}).get('tcp_flags', 0)
                dst_ip = event.get('destination_ip', '')
                
                # SYN flag (0x02)
                if tcp_flags & 0x02:
                    if not (tcp_flags & 0x10):  # Not ACK
                        syn_count[dst_ip] += 1
                    else:  # SYN-ACK
                        syn_ack_count[dst_ip] += 1
        
        # Detect floods (many SYN without corresponding SYN-ACK)
        flood_events = []
        for dst_ip in syn_count:
            syn_num = syn_count[dst_ip]
            syn_ack_num = syn_ack_count.get(dst_ip, 0)
            
            if syn_num > 50 and syn_num > syn_ack_num * 10:
                for event in events:
                    if (event.get('destination_ip') == dst_ip and
                        event.get('protocol') == 'tcp'):
                        tcp_flags = event.get('raw_data', {}).get('tcp_flags', 0)
                        if tcp_flags & 0x02 and not (tcp_flags & 0x10):
                            event['attack_indicator'] = 'syn_flood'
                            event['attack_confidence'] = min(syn_num / 100.0, 1.0)
                            flood_events.append(event)
        
        return flood_events
    
    def detect_dns_exfiltration(self, events: List[Dict]) -> List[Dict]:
        """Detect DNS-based data exfiltration"""
        exfil_events = []
        
        for event in events:
            if event.get('protocol') == 'dns':
                raw_data = event.get('raw_data', {})
                dns_query = raw_data.get('dns_query', '')
                
                # Check for suspicious long domain names (potential exfiltration)
                if dns_query and len(dns_query) > 50:
                    # Check for base64-like patterns
                    if re.search(r'[A-Za-z0-9+/]{20,}', dns_query):
                        event['attack_indicator'] = 'dns_exfiltration'
                        event['attack_confidence'] = 0.7
                        exfil_events.append(event)
                
                # Check for suspicious subdomains
                if dns_query and dns_query.count('.') > 5:
                    event['attack_indicator'] = 'dns_exfiltration'
                    event['attack_confidence'] = 0.5
                    exfil_events.append(event)
        
        return exfil_events
    
    def detect_large_transfers(self, events: List[Dict]) -> List[Dict]:
        """Detect large data transfers (potential exfiltration)"""
        transfer_events = []
        threshold = 10 * 1024 * 1024  # 10MB
        
        # Group transfers by source-destination pair
        transfers = defaultdict(int)
        
        for event in events:
            src_ip = event.get('source_ip', '')
            dst_ip = event.get('destination_ip', '')
            size = event.get('packet_size', 0)
            
            if src_ip and dst_ip:
                key = f"{src_ip}:{dst_ip}"
                transfers[key] += size
        
        # Mark large transfers
        for key, total_size in transfers.items():
            if total_size >= threshold:
                src_ip, dst_ip = key.split(':')
                for event in events:
                    if (event.get('source_ip') == src_ip and
                        event.get('destination_ip') == dst_ip):
                        event['attack_indicator'] = 'large_transfer'
                        event['attack_confidence'] = min(total_size / (100 * 1024 * 1024), 1.0)
                        transfer_events.append(event)
        
        return transfer_events
    
    def detect_suspicious_payloads(self, events: List[Dict]) -> List[Dict]:
        """Detect suspicious payloads (SQL injection, XSS, etc.)"""
        suspicious_events = []
        
        sql_patterns = [
            r"SELECT.*FROM",
            r"UNION.*SELECT",
            r"DROP.*TABLE",
            r"' OR '1'='1",
            r"'; DROP",
        ]
        
        xss_patterns = [
            r"<script",
            r"javascript:",
            r"onerror=",
        ]
        
        for event in events:
            payload = event.get('payload', b'')
            if not payload:
                continue
            
            try:
                payload_str = payload.decode('utf-8', errors='ignore').lower()
            except:
                continue
            
            # Check SQL injection
            for pattern in sql_patterns:
                if re.search(pattern, payload_str, re.I):
                    event['attack_indicator'] = 'sql_injection'
                    event['attack_confidence'] = 0.8
                    suspicious_events.append(event)
                    break
            
            # Check XSS
            for pattern in xss_patterns:
                if re.search(pattern, payload_str, re.I):
                    event['attack_indicator'] = 'xss_attempt'
                    event['attack_confidence'] = 0.7
                    suspicious_events.append(event)
                    break
        
        return suspicious_events
    
    def detect_internal_communication(self, events: List[Dict]) -> List[Dict]:
        """Detect internal network communication (lateral movement indicator)"""
        internal_events = []
        
        private_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('172.16.0.0/12'),
        ]
        
        def is_private(ip_str: str) -> bool:
            try:
                ip = ipaddress.ip_address(ip_str)
                for network in private_ranges:
                    if ip in network:
                        return True
            except:
                pass
            return False
        
        for event in events:
            src_ip = event.get('source_ip', '')
            dst_ip = event.get('destination_ip', '')
            
            if src_ip and dst_ip and is_private(src_ip) and is_private(dst_ip):
                # Internal to internal communication
                if event.get('protocol') in ['tcp', 'udp']:
                    port = event.get('destination_port', 0)
                    # Check for suspicious ports (SSH, RDP, etc.)
                    if port in [22, 3389, 445, 5985, 5986]:
                        event['attack_indicator'] = 'internal_communication'
                        event['attack_confidence'] = 0.6
                        internal_events.append(event)
        
        return internal_events
    
    def analyze_all(self, events: List[Dict]) -> List[Dict]:
        """Run all detection methods on events"""
        analyzed_events = events.copy()
        
        # Run all detectors
        self.detect_port_scan(analyzed_events)
        self.detect_syn_flood(analyzed_events)
        self.detect_dns_exfiltration(analyzed_events)
        self.detect_large_transfers(analyzed_events)
        self.detect_suspicious_payloads(analyzed_events)
        self.detect_internal_communication(analyzed_events)
        
        return analyzed_events
    
    def get_statistics(self, events: List[Dict]) -> Dict:
        """Get analysis statistics"""
        stats = {
            'total_packets': len(events),
            'attack_indicators': defaultdict(int),
            'protocols': defaultdict(int),
            'top_source_ips': defaultdict(int),
            'top_dest_ips': defaultdict(int),
        }
        
        for event in events:
            # Count protocols
            protocol = event.get('protocol', 'unknown')
            stats['protocols'][protocol] += 1
            
            # Count attack indicators
            indicator = event.get('attack_indicator')
            if indicator:
                stats['attack_indicators'][indicator] += 1
            
            # Count IPs
            src_ip = event.get('source_ip', '')
            dst_ip = event.get('destination_ip', '')
            if src_ip:
                stats['top_source_ips'][src_ip] += 1
            if dst_ip:
                stats['top_dest_ips'][dst_ip] += 1
        
        # Sort and limit top IPs
        stats['top_source_ips'] = dict(sorted(
            stats['top_source_ips'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10])
        
        stats['top_dest_ips'] = dict(sorted(
            stats['top_dest_ips'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10])
        
        return stats

