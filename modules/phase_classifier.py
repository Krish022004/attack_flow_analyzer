"""
Phase Classifier
Maps events to attack phases using rule-based classification with confidence scoring
"""

import re
import json
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import config


class PhaseClassifier:
    """Classifies events into attack phases"""
    
    def __init__(self, rules_file: Optional[Path] = None):
        if rules_file is None:
            rules_file = Path(__file__).parent.parent / 'rules' / 'phase_rules.json'
        
        self.rules = self._load_rules(rules_file)
        self.classified_events: List[Dict] = []
        self.phase_statistics: Dict = defaultdict(lambda: {'count': 0, 'total_confidence': 0.0})
    
    def _load_rules(self, rules_file: Path) -> Dict:
        """Load phase classification rules"""
        try:
            with open(rules_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load rules file: {e}")
            return {}
    
    def _check_url_patterns(self, event: Dict, phase: str) -> float:
        """Check if event matches URL patterns for a phase"""
        if phase not in self.rules:
            return 0.0
        
        path = event.get('path', '')
        url_patterns = self.rules[phase].get('indicators', {}).get('url_patterns', [])
        
        if not url_patterns:
            return 0.0
        
        for pattern in url_patterns:
            if pattern.lower() in path.lower():
                return 1.0
        
        return 0.0
    
    def _check_status_codes(self, event: Dict, phase: str) -> float:
        """Check if status codes match phase indicators"""
        if phase not in self.rules:
            return 0.0
        
        status_code = event.get('status_code', 0)
        expected_codes = self.rules[phase].get('indicators', {}).get('status_codes', [])
        
        if status_code in expected_codes:
            return 1.0
        
        return 0.0
    
    def _check_sql_injection(self, event: Dict) -> float:
        """Detect SQL injection patterns"""
        sql_patterns = [
            r"SELECT.*FROM",
            r"UNION.*SELECT",
            r"DROP.*TABLE",
            r"' OR '1'='1",
            r"'; DROP",
            r"OR 1=1",
            r"AND 1=1",
        ]
        
        path = event.get('path', '')
        user_agent = event.get('user_agent', '')
        message = event.get('message', '')
        
        text = f"{path} {user_agent} {message}".lower()
        
        for pattern in sql_patterns:
            if re.search(pattern, text, re.I):
                return 1.0
        
        return 0.0
    
    def _check_xss(self, event: Dict) -> float:
        """Detect XSS patterns"""
        xss_patterns = [
            r"<script",
            r"javascript:",
            r"onerror=",
            r"onclick=",
            r"onload=",
            r"alert\(",
        ]
        
        path = event.get('path', '')
        user_agent = event.get('user_agent', '')
        message = event.get('message', '')
        
        text = f"{path} {user_agent} {message}".lower()
        
        for pattern in xss_patterns:
            if re.search(pattern, text, re.I):
                return 1.0
        
        return 0.0
    
    def _check_path_traversal(self, event: Dict) -> float:
        """Detect path traversal patterns"""
        traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"C:\\Windows\\System32",
            r"\.\.%2F",
            r"\.\.%5C",
        ]
        
        path = event.get('path', '')
        message = event.get('message', '')
        
        text = f"{path} {message}".lower()
        
        for pattern in traversal_patterns:
            if re.search(pattern, text, re.I):
                return 1.0
        
        return 0.0
    
    def _check_failed_logins(self, events: List[Dict], event: Dict, time_window_minutes: int = 10) -> float:
        """Check for multiple failed login attempts"""
        if event.get('action') != 'failed_login':
            return 0.0
        
        timestamp = event.get('timestamp')
        source_ip = event.get('source_ip', '')
        
        if not timestamp or not source_ip:
            return 0.0
        
        from datetime import timedelta
        window_start = timestamp - timedelta(minutes=time_window_minutes)
        
        failed_count = sum(1 for e in events 
                          if e.get('source_ip') == source_ip 
                          and e.get('action') == 'failed_login'
                          and e.get('timestamp') and window_start <= e.get('timestamp') <= timestamp)
        
        if failed_count >= 3:
            return min(1.0, failed_count / 10.0)  # Normalize to 0-1
        
        return 0.0
    
    def _check_internal_ips(self, event: Dict) -> float:
        """Check if IPs are internal"""
        source_ip = event.get('source_ip', '')
        dest_ip = event.get('destination_ip', '')
        
        internal_patterns = [
            r'^10\.',
            r'^192\.168\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        ]
        
        has_internal = False
        for ip in [source_ip, dest_ip]:
            if ip:
                for pattern in internal_patterns:
                    if re.match(pattern, ip):
                        has_internal = True
                        break
                if has_internal:
                    break
        
        # Also check if event involves internal network communication
        if has_internal:
            # Check if it's a connection attempt (not just web access)
            log_type = event.get('log_type', '')
            if log_type in ['firewall', 'authentication']:
                return 1.0
            # For web access, give partial score
            elif source_ip and dest_ip and has_internal:
                return 0.7
        
        return 0.0
    
    def _check_large_transfers(self, event: Dict, threshold_bytes: int = 10485760) -> float:
        """Check for large data transfers"""
        size = event.get('size', 0)
        
        if size >= threshold_bytes:
            return min(1.0, size / (threshold_bytes * 2))  # Normalize
        
        return 0.0
    
    def _check_suspicious_user_agent(self, event: Dict) -> float:
        """Check for suspicious user agents"""
        user_agent = event.get('user_agent', '').lower()
        
        for suspicious in config.SUSPICIOUS_USER_AGENTS:
            if suspicious.lower() in user_agent:
                return 1.0
        
        return 0.0
    
    def _calculate_confidence(self, event: Dict, phase: str, scores: Dict[str, float]) -> float:
        """Calculate confidence score for phase classification"""
        if phase not in self.rules:
            return 0.0
        
        weights = self.rules[phase].get('confidence_weights', {})
        total_weight = sum(weights.values())
        
        if total_weight == 0:
            return 0.0
        
        confidence = 0.0
        for indicator, weight in weights.items():
            score = scores.get(indicator, 0.0)
            confidence += (weight / total_weight) * score
        
        return min(1.0, confidence)
    
    def classify_event(self, event: Dict, all_events: List[Dict]) -> Dict:
        """Classify a single event into attack phases"""
        scores = {
            'reconnaissance': {},
            'initial_access': {},
            'lateral_movement': {},
            'exfiltration': {},
        }
        
        # Reconnaissance indicators
        scores['reconnaissance']['url_pattern'] = self._check_url_patterns(event, 'reconnaissance')
        scores['reconnaissance']['status_code'] = self._check_status_codes(event, 'reconnaissance')
        scores['reconnaissance']['user_agent'] = self._check_suspicious_user_agent(event)
        
        # Additional reconnaissance: 404 errors on common paths
        path = event.get('path', '').lower()
        status = event.get('status_code', 0)
        if status == 404 and any(pattern in path for pattern in ['admin', 'login', 'wp-', 'phpmyadmin', 'test', 'api', 'config', 'backup']):
            scores['reconnaissance']['url_pattern'] = max(scores['reconnaissance']['url_pattern'], 0.5)
        
        # Initial access indicators
        scores['initial_access']['sql_injection'] = self._check_sql_injection(event)
        scores['initial_access']['xss'] = self._check_xss(event)
        scores['initial_access']['path_traversal'] = self._check_path_traversal(event)
        scores['initial_access']['failed_logins'] = self._check_failed_logins(all_events, event)
        
        # Lateral movement indicators
        scores['lateral_movement']['internal_ips'] = self._check_internal_ips(event)
        protocol = event.get('protocol', '').lower()
        scores['lateral_movement']['protocols'] = 1.0 if protocol in ['ssh', 'rdp', 'smb', 'winrm'] else 0.0
        
        # Exfiltration indicators
        path = event.get('path', '').lower()
        exfil_endpoints = ['/api/export', '/api/download', '/backup', '/export']
        scores['exfiltration']['endpoints'] = 1.0 if any(ep in path for ep in exfil_endpoints) else 0.0
        scores['exfiltration']['large_transfers'] = self._check_large_transfers(event)
        
        # Calculate confidence for each phase
        phase_confidences = {}
        for phase in scores:
            phase_confidences[phase] = self._calculate_confidence(event, phase, scores[phase])
        
        # Determine primary phase
        primary_phase = max(phase_confidences.items(), key=lambda x: x[1])
        
        # Lower threshold to 0.1 to catch more events, but still prefer higher confidence
        # If confidence is very low (< 0.1), mark as unknown
        # If confidence is low but > 0.1, still assign the phase but with lower confidence
        phase_threshold = 0.1
        
        classified_event = event.copy()
        if primary_phase[1] > phase_threshold:
            classified_event['attack_phase'] = primary_phase[0]
        else:
            # Try to infer phase from context even with low confidence
            # Check if any indicator scored > 0
            max_score = max([max(scores[phase].values()) if scores[phase] else 0 for phase in scores])
            if max_score > 0:
                # Use the phase with the highest individual indicator score
                best_phase = None
                best_indicator_score = 0
                for phase in scores:
                    for indicator, score in scores[phase].items():
                        if score > best_indicator_score:
                            best_indicator_score = score
                            best_phase = phase
                if best_phase:
                    classified_event['attack_phase'] = best_phase
                else:
                    classified_event['attack_phase'] = 'unknown'
            else:
                classified_event['attack_phase'] = 'unknown'
        
        classified_event['phase_confidence'] = primary_phase[1]
        classified_event['phase_scores'] = phase_confidences
        
        return classified_event
    
    def classify_all(self, events: List[Dict]) -> List[Dict]:
        """Classify all events"""
        self.classified_events = []
        self.phase_statistics = defaultdict(lambda: {'count': 0, 'total_confidence': 0.0})
        
        for event in events:
            classified = self.classify_event(event, events)
            self.classified_events.append(classified)
            
            phase = classified['attack_phase']
            self.phase_statistics[phase]['count'] += 1
            self.phase_statistics[phase]['total_confidence'] += classified['phase_confidence']
        
        return self.classified_events
    
    def get_statistics(self) -> Dict:
        """Get phase classification statistics"""
        stats = {}
        
        for phase, data in self.phase_statistics.items():
            count = data['count']
            avg_confidence = data['total_confidence'] / count if count > 0 else 0.0
            stats[phase] = {
                'count': count,
                'percentage': (count / len(self.classified_events) * 100) if self.classified_events else 0,
                'average_confidence': avg_confidence,
            }
        
        return stats
    
    def get_phase_events(self, phase: str) -> List[Dict]:
        """Get all events for a specific phase"""
        return [e for e in self.classified_events if e.get('attack_phase') == phase]
