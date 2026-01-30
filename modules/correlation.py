"""
Correlation Engine
Groups events by user, IP, and session using efficient algorithms
"""

from typing import List, Dict, Set, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import config


class CorrelationGroup:
    """Represents a group of correlated events"""
    
    def __init__(self, group_id: str, correlation_type: str):
        self.group_id = group_id
        self.correlation_type = correlation_type  # 'user', 'ip', 'session'
        self.events: List[Dict] = []
        self.metadata: Dict = {}
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None
    
    def add_event(self, event: Dict):
        """Add event to correlation group"""
        self.events.append(event)
        timestamp = event.get('timestamp')
        
        if timestamp:
            if self.first_seen is None or timestamp < self.first_seen:
                self.first_seen = timestamp
            if self.last_seen is None or timestamp > self.last_seen:
                self.last_seen = timestamp
    
    def get_duration(self) -> timedelta:
        """Get duration of correlation group"""
        if self.first_seen and self.last_seen:
            return self.last_seen - self.first_seen
        return timedelta(0)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'group_id': self.group_id,
            'correlation_type': self.correlation_type,
            'event_count': len(self.events),
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'duration_seconds': self.get_duration().total_seconds(),
            'metadata': self.metadata,
        }


class CorrelationEngine:
    """Efficient correlation engine using hash-based grouping"""
    
    def __init__(self):
        self.groups: Dict[str, CorrelationGroup] = {}
        self.event_to_groups: Dict[int, Set[str]] = defaultdict(set)  # event index -> group IDs
        self.correlation_settings = config.CORRELATION_SETTINGS
    
    def correlate_by_ip(self, events: List[Dict]) -> Dict[str, CorrelationGroup]:
        """Correlate events by IP address"""
        ip_groups: Dict[str, CorrelationGroup] = {}
        window = self.correlation_settings['ip_correlation_window']
        
        # Sort events by timestamp for efficient windowing
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', datetime.min))
        
        for idx, event in enumerate(sorted_events):
            # Extract IPs from event
            source_ip = event.get('source_ip', '')
            dest_ip = event.get('destination_ip', '')
            timestamp = event.get('timestamp')
            
            if not timestamp:
                continue
            
            # Correlate by source IP
            if source_ip:
                group_key = f"ip_src_{source_ip}"
                if group_key not in ip_groups:
                    ip_groups[group_key] = CorrelationGroup(group_key, 'ip')
                    ip_groups[group_key].metadata['ip'] = source_ip
                    ip_groups[group_key].metadata['ip_type'] = 'source'
                
                # Check time window
                group = ip_groups[group_key]
                if not group.last_seen or (timestamp - group.last_seen) <= window:
                    group.add_event(event)
                    self.event_to_groups[idx].add(group_key)
            
            # Correlate by destination IP
            if dest_ip and dest_ip != source_ip:
                group_key = f"ip_dst_{dest_ip}"
                if group_key not in ip_groups:
                    ip_groups[group_key] = CorrelationGroup(group_key, 'ip')
                    ip_groups[group_key].metadata['ip'] = dest_ip
                    ip_groups[group_key].metadata['ip_type'] = 'destination'
                
                group = ip_groups[group_key]
                if not group.last_seen or (timestamp - group.last_seen) <= window:
                    group.add_event(event)
                    self.event_to_groups[idx].add(group_key)
        
        return ip_groups
    
    def correlate_by_user(self, events: List[Dict]) -> Dict[str, CorrelationGroup]:
        """Correlate events by username"""
        user_groups: Dict[str, CorrelationGroup] = {}
        window = self.correlation_settings['user_correlation_window']
        
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', datetime.min))
        
        for idx, event in enumerate(sorted_events):
            user = event.get('user', '')
            timestamp = event.get('timestamp')
            
            if not user or user == '-' or not timestamp:
                continue
            
            group_key = f"user_{user}"
            if group_key not in user_groups:
                user_groups[group_key] = CorrelationGroup(group_key, 'user')
                user_groups[group_key].metadata['user'] = user
            
            group = user_groups[group_key]
            if not group.last_seen or (timestamp - group.last_seen) <= window:
                group.add_event(event)
                self.event_to_groups[idx].add(group_key)
        
        return user_groups
    
    def correlate_by_session(self, events: List[Dict]) -> Dict[str, CorrelationGroup]:
        """Correlate events by session (time-based and IP-based)"""
        session_groups: Dict[str, CorrelationGroup] = {}
        timeout = self.correlation_settings['session_timeout']
        
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', datetime.min))
        
        current_sessions: Dict[str, CorrelationGroup] = {}  # IP -> active session
        
        for idx, event in enumerate(sorted_events):
            source_ip = event.get('source_ip', '')
            timestamp = event.get('timestamp')
            
            if not source_ip or not timestamp:
                continue
            
            # Check if existing session is still active
            if source_ip in current_sessions:
                session = current_sessions[source_ip]
                if (timestamp - session.last_seen) <= timeout:
                    # Continue existing session
                    session.add_event(event)
                    self.event_to_groups[idx].add(session.group_id)
                    continue
                else:
                    # Session expired, start new one
                    session_id = f"session_{source_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                    current_sessions[source_ip] = CorrelationGroup(session_id, 'session')
                    current_sessions[source_ip].metadata['ip'] = source_ip
                    current_sessions[source_ip].add_event(event)
                    session_groups[session_id] = current_sessions[source_ip]
                    self.event_to_groups[idx].add(session_id)
            else:
                # New session
                session_id = f"session_{source_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                current_sessions[source_ip] = CorrelationGroup(session_id, 'session')
                current_sessions[source_ip].metadata['ip'] = source_ip
                current_sessions[source_ip].add_event(event)
                session_groups[session_id] = current_sessions[source_ip]
                self.event_to_groups[idx].add(session_id)
        
        return session_groups
    
    def correlate_all(self, events: List[Dict]) -> Dict[str, Dict[str, CorrelationGroup]]:
        """Perform all correlation types"""
        self.groups = {}
        self.event_to_groups = defaultdict(set)
        
        # Perform correlations
        ip_groups = self.correlate_by_ip(events)
        user_groups = self.correlate_by_user(events)
        session_groups = self.correlate_by_session(events)
        
        # Merge all groups
        self.groups.update(ip_groups)
        self.groups.update(user_groups)
        self.groups.update(session_groups)
        
        return {
            'ip': ip_groups,
            'user': user_groups,
            'session': session_groups,
        }
    
    def get_correlated_events(self, event_index: int) -> List[Dict]:
        """Get all events correlated with a given event"""
        group_ids = self.event_to_groups.get(event_index, set())
        correlated_events = []
        
        for group_id in group_ids:
            if group_id in self.groups:
                correlated_events.extend(self.groups[group_id].events)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_events = []
        for event in correlated_events:
            event_id = id(event)
            if event_id not in seen:
                seen.add(event_id)
                unique_events.append(event)
        
        return unique_events
    
    def get_statistics(self) -> Dict:
        """Get correlation statistics"""
        stats = {
            'total_groups': len(self.groups),
            'by_type': defaultdict(int),
            'largest_groups': [],
        }
        
        for group in self.groups.values():
            stats['by_type'][group.correlation_type] += 1
        
        # Find largest groups
        sorted_groups = sorted(self.groups.values(), key=lambda g: len(g.events), reverse=True)
        stats['largest_groups'] = [
            {
                'group_id': g.group_id,
                'type': g.correlation_type,
                'event_count': len(g.events),
                'duration_hours': g.get_duration().total_seconds() / 3600,
            }
            for g in sorted_groups[:10]
        ]
        
        return stats
