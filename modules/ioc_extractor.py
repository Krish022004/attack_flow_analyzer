"""
IOC Extractor
Extracts Indicators of Compromise from events
"""

from typing import List, Dict, Set
from collections import defaultdict
from datetime import datetime
import config
import ipaddress


class IOCExtractor:
    """Extracts IOCs from classified events"""
    
    def __init__(self):
        self.iocs: Dict[str, Dict] = {}
        self.ioc_categories = {
            'ip': set(),
            'domain': set(),
            'hash': set(),
            'url': set(),
            'user_agent': set(),
        }
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Basic domain validation"""
        # Filter out common false positives
        invalid_patterns = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            'example.com',
            'test.com',
        ]
        
        domain_lower = domain.lower()
        for pattern in invalid_patterns:
            if pattern in domain_lower:
                return False
        
        # Must have at least one dot and valid TLD
        if '.' not in domain or len(domain.split('.')) < 2:
            return False
        
        return True
    
    def extract_ips(self, events: List[Dict]) -> Dict[str, Dict]:
        """Extract IP addresses from events"""
        ip_iocs = {}
        
        for event in events:
            # Extract source IPs
            source_ip = event.get('source_ip', '')
            if source_ip:
                ip_match = config.IOC_PATTERNS['ipv4'].match(source_ip)
                if ip_match:
                    ip = ip_match.group()
                    if ip not in ip_iocs:
                        ip_iocs[ip] = {
                            'value': ip,
                            'type': 'ip',
                            'category': 'source',
                            'first_seen': event.get('timestamp'),
                            'last_seen': event.get('timestamp'),
                            'associated_phases': set(),
                            'event_count': 0,
                            'is_private': self._is_private_ip(ip),
                        }
                    
                    ioc = ip_iocs[ip]
                    ioc['event_count'] += 1
                    ioc['associated_phases'].add(event.get('attack_phase', 'unknown'))
                    
                    timestamp = event.get('timestamp')
                    if timestamp:
                        if not ioc['first_seen'] or timestamp < ioc['first_seen']:
                            ioc['first_seen'] = timestamp
                        if not ioc['last_seen'] or timestamp > ioc['last_seen']:
                            ioc['last_seen'] = timestamp
            
            # Extract destination IPs
            dest_ip = event.get('destination_ip', '')
            if dest_ip:
                ip_match = config.IOC_PATTERNS['ipv4'].match(dest_ip)
                if ip_match:
                    ip = ip_match.group()
                    if ip not in ip_iocs:
                        ip_iocs[ip] = {
                            'value': ip,
                            'type': 'ip',
                            'category': 'destination',
                            'first_seen': event.get('timestamp'),
                            'last_seen': event.get('timestamp'),
                            'associated_phases': set(),
                            'event_count': 0,
                            'is_private': self._is_private_ip(ip),
                        }
                    
                    ioc = ip_iocs[ip]
                    ioc['event_count'] += 1
                    ioc['associated_phases'].add(event.get('attack_phase', 'unknown'))
                    
                    timestamp = event.get('timestamp')
                    if timestamp:
                        if not ioc['first_seen'] or timestamp < ioc['first_seen']:
                            ioc['first_seen'] = timestamp
                        if not ioc['last_seen'] or timestamp > ioc['last_seen']:
                            ioc['last_seen'] = timestamp
        
        return ip_iocs
    
    def extract_domains(self, events: List[Dict]) -> Dict[str, Dict]:
        """Extract domain names from events"""
        domain_iocs = {}
        
        for event in events:
            # Extract from path, referer, user agent, message
            text_fields = [
                event.get('path', ''),
                event.get('referer', ''),
                event.get('user_agent', ''),
                event.get('message', ''),
            ]
            
            for text in text_fields:
                matches = config.IOC_PATTERNS['domain'].findall(text)
                for domain in matches:
                    if self._is_valid_domain(domain):
                        if domain not in domain_iocs:
                            domain_iocs[domain] = {
                                'value': domain,
                                'type': 'domain',
                                'first_seen': event.get('timestamp'),
                                'last_seen': event.get('timestamp'),
                                'associated_phases': set(),
                                'event_count': 0,
                            }
                        
                        ioc = domain_iocs[domain]
                        ioc['event_count'] += 1
                        ioc['associated_phases'].add(event.get('attack_phase', 'unknown'))
                        
                        timestamp = event.get('timestamp')
                        if timestamp:
                            if not ioc['first_seen'] or timestamp < ioc['first_seen']:
                                ioc['first_seen'] = timestamp
                            if not ioc['last_seen'] or timestamp > ioc['last_seen']:
                                ioc['last_seen'] = timestamp
        
        return domain_iocs
    
    def extract_hashes(self, events: List[Dict]) -> Dict[str, Dict]:
        """Extract file hashes from events"""
        hash_iocs = {}
        
        for event in events:
            text_fields = [
                event.get('path', ''),
                event.get('message', ''),
                event.get('raw_line', ''),
            ]
            
            for text in text_fields:
                # MD5
                md5_matches = config.IOC_PATTERNS['md5'].findall(text)
                for hash_val in md5_matches:
                    if hash_val not in hash_iocs:
                        hash_iocs[hash_val] = {
                            'value': hash_val,
                            'type': 'hash',
                            'hash_type': 'md5',
                            'first_seen': event.get('timestamp'),
                            'last_seen': event.get('timestamp'),
                            'associated_phases': set(),
                            'event_count': 0,
                        }
                    
                    ioc = hash_iocs[hash_val]
                    ioc['event_count'] += 1
                    ioc['associated_phases'].add(event.get('attack_phase', 'unknown'))
                
                # SHA1
                sha1_matches = config.IOC_PATTERNS['sha1'].findall(text)
                for hash_val in sha1_matches:
                    if hash_val not in hash_iocs:
                        hash_iocs[hash_val] = {
                            'value': hash_val,
                            'type': 'hash',
                            'hash_type': 'sha1',
                            'first_seen': event.get('timestamp'),
                            'last_seen': event.get('timestamp'),
                            'associated_phases': set(),
                            'event_count': 0,
                        }
                    
                    ioc = hash_iocs[hash_val]
                    ioc['event_count'] += 1
                    ioc['associated_phases'].add(event.get('attack_phase', 'unknown'))
                
                # SHA256
                sha256_matches = config.IOC_PATTERNS['sha256'].findall(text)
                for hash_val in sha256_matches:
                    if hash_val not in hash_iocs:
                        hash_iocs[hash_val] = {
                            'value': hash_val,
                            'type': 'hash',
                            'hash_type': 'sha256',
                            'first_seen': event.get('timestamp'),
                            'last_seen': event.get('timestamp'),
                            'associated_phases': set(),
                            'event_count': 0,
                        }
                    
                    ioc = hash_iocs[hash_val]
                    ioc['event_count'] += 1
                    ioc['associated_phases'].add(event.get('attack_phase', 'unknown'))
        
        return hash_iocs
    
    def extract_urls(self, events: List[Dict]) -> Dict[str, Dict]:
        """Extract URLs from events"""
        url_iocs = {}
        
        for event in events:
            text_fields = [
                event.get('path', ''),
                event.get('referer', ''),
                event.get('message', ''),
            ]
            
            for text in text_fields:
                matches = config.IOC_PATTERNS['url'].findall(text)
                for url in matches:
                    # Filter out common benign URLs
                    if any(skip in url.lower() for skip in ['localhost', '127.0.0.1', 'example.com']):
                        continue
                    
                    if url not in url_iocs:
                        url_iocs[url] = {
                            'value': url,
                            'type': 'url',
                            'first_seen': event.get('timestamp'),
                            'last_seen': event.get('timestamp'),
                            'associated_phases': set(),
                            'event_count': 0,
                        }
                    
                    ioc = url_iocs[url]
                    ioc['event_count'] += 1
                    ioc['associated_phases'].add(event.get('attack_phase', 'unknown'))
                    
                    timestamp = event.get('timestamp')
                    if timestamp:
                        if not ioc['first_seen'] or timestamp < ioc['first_seen']:
                            ioc['first_seen'] = timestamp
                        if not ioc['last_seen'] or timestamp > ioc['last_seen']:
                            ioc['last_seen'] = timestamp
        
        return url_iocs
    
    def extract_user_agents(self, events: List[Dict]) -> Dict[str, Dict]:
        """Extract suspicious user agents"""
        ua_iocs = {}
        
        for event in events:
            user_agent = event.get('user_agent', '')
            if not user_agent or user_agent == '-':
                continue
            
            # Check if suspicious
            is_suspicious = any(sus in user_agent.lower() for sus in config.SUSPICIOUS_USER_AGENTS)
            
            if is_suspicious or event.get('attack_phase') != 'unknown':
                if user_agent not in ua_iocs:
                    ua_iocs[user_agent] = {
                        'value': user_agent,
                        'type': 'user_agent',
                        'first_seen': event.get('timestamp'),
                        'last_seen': event.get('timestamp'),
                        'associated_phases': set(),
                        'event_count': 0,
                        'is_suspicious': is_suspicious,
                    }
                
                ioc = ua_iocs[user_agent]
                ioc['event_count'] += 1
                ioc['associated_phases'].add(event.get('attack_phase', 'unknown'))
                
                timestamp = event.get('timestamp')
                if timestamp:
                    if not ioc['first_seen'] or timestamp < ioc['first_seen']:
                        ioc['first_seen'] = timestamp
                    if not ioc['last_seen'] or timestamp > ioc['last_seen']:
                        ioc['last_seen'] = timestamp
        
        return ua_iocs
    
    def extract_all(self, events: List[Dict]) -> Dict[str, Dict]:
        """Extract all IOCs from events"""
        self.iocs = {}
        
        # Extract all IOC types
        ip_iocs = self.extract_ips(events)
        domain_iocs = self.extract_domains(events)
        hash_iocs = self.extract_hashes(events)
        url_iocs = self.extract_urls(events)
        ua_iocs = self.extract_user_agents(events)
        
        # Merge all IOCs
        self.iocs.update(ip_iocs)
        self.iocs.update(domain_iocs)
        self.iocs.update(hash_iocs)
        self.iocs.update(url_iocs)
        self.iocs.update(ua_iocs)
        
        # Convert sets to lists for JSON serialization
        for ioc in self.iocs.values():
            if 'associated_phases' in ioc and isinstance(ioc['associated_phases'], set):
                ioc['associated_phases'] = list(ioc['associated_phases'])
            if isinstance(ioc.get('first_seen'), datetime):
                ioc['first_seen'] = ioc['first_seen'].isoformat()
            if isinstance(ioc.get('last_seen'), datetime):
                ioc['last_seen'] = ioc['last_seen'].isoformat()
        
        return self.iocs
    
    def get_statistics(self) -> Dict:
        """Get IOC extraction statistics"""
        stats = {
            'total_iocs': len(self.iocs),
            'by_type': defaultdict(int),
            'by_phase': defaultdict(int),
        }
        
        for ioc in self.iocs.values():
            stats['by_type'][ioc['type']] += 1
            for phase in ioc.get('associated_phases', []):
                stats['by_phase'][phase] += 1
        
        return stats
