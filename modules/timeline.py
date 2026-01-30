"""
Timeline Builder
Creates chronological sequences and calculates phase durations
"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta
from collections import defaultdict


class TimelineBuilder:
    """Builds chronological timeline of attack events"""
    
    def __init__(self):
        self.timeline_events: List[Dict] = []
        self.phase_groups: Dict[str, List[Dict]] = defaultdict(list)
        self.phase_durations: Dict[str, timedelta] = {}
        self.phase_transitions: List[Dict] = []
    
    def build_timeline(self, events: List[Dict]) -> List[Dict]:
        """Build chronological timeline from events"""
        # Sort events by timestamp
        sorted_events = sorted(
            [e for e in events if e.get('timestamp')],
            key=lambda x: x['timestamp']
        )
        
        self.timeline_events = sorted_events
        
        # Group by phase
        self._group_by_phase()
        
        # Calculate phase durations
        self._calculate_phase_durations()
        
        # Identify phase transitions
        self._identify_transitions()
        
        return self.timeline_events
    
    def _group_by_phase(self):
        """Group events by attack phase"""
        self.phase_groups = defaultdict(list)
        
        for event in self.timeline_events:
            phase = event.get('attack_phase', 'unknown')
            self.phase_groups[phase].append(event)
    
    def _calculate_phase_durations(self):
        """Calculate duration of each attack phase"""
        self.phase_durations = {}
        
        for phase, events in self.phase_groups.items():
            if not events:
                continue
            
            timestamps = [e['timestamp'] for e in events if e.get('timestamp')]
            if timestamps:
                duration = max(timestamps) - min(timestamps)
                self.phase_durations[phase] = duration
            else:
                self.phase_durations[phase] = timedelta(0)
    
    def _identify_transitions(self):
        """Identify transitions between attack phases"""
        self.phase_transitions = []
        
        if len(self.timeline_events) < 2:
            return
        
        current_phase = None
        
        for i, event in enumerate(self.timeline_events):
            phase = event.get('attack_phase', 'unknown')
            
            if current_phase is None:
                current_phase = phase
                continue
            
            if phase != current_phase:
                transition = {
                    'from_phase': current_phase,
                    'to_phase': phase,
                    'timestamp': event.get('timestamp'),
                    'event_index': i,
                    'event': event,
                }
                self.phase_transitions.append(transition)
                current_phase = phase
    
    def get_timeline_data(self) -> Dict:
        """Get timeline data for visualization"""
        return {
            'events': [
                {
                    'timestamp': e['timestamp'].isoformat() if isinstance(e['timestamp'], datetime) else str(e['timestamp']),
                    'phase': e.get('attack_phase', 'unknown'),
                    'confidence': e.get('phase_confidence', 0.0),
                    'source_ip': e.get('source_ip', ''),
                    'path': e.get('path', ''),
                    'status_code': e.get('status_code', 0),
                    'log_type': e.get('log_type', ''),
                    'message': e.get('message', '')[:100],  # Truncate long messages
                }
                for e in self.timeline_events
            ],
            'phases': {
                phase: {
                    'count': len(events),
                    'duration_seconds': self.phase_durations.get(phase, timedelta(0)).total_seconds(),
                    'start': min([e['timestamp'] for e in events if e.get('timestamp')]).isoformat() if events else None,
                    'end': max([e['timestamp'] for e in events if e.get('timestamp')]).isoformat() if events else None,
                }
                for phase, events in self.phase_groups.items()
            },
            'transitions': [
                {
                    'from_phase': t['from_phase'],
                    'to_phase': t['to_phase'],
                    'timestamp': t['timestamp'].isoformat() if isinstance(t['timestamp'], datetime) else str(t['timestamp']),
                }
                for t in self.phase_transitions
            ],
            'statistics': self.get_statistics(),
        }
    
    def get_phase_statistics(self) -> Dict:
        """Get statistics for each phase"""
        stats = {}
        
        for phase, events in self.phase_groups.items():
            if not events:
                continue
            
            timestamps = [e['timestamp'] for e in events if e.get('timestamp')]
            confidences = [e.get('phase_confidence', 0.0) for e in events]
            
            stats[phase] = {
                'count': len(events),
                'duration_seconds': self.phase_durations.get(phase, timedelta(0)).total_seconds(),
                'duration_hours': self.phase_durations.get(phase, timedelta(0)).total_seconds() / 3600,
                'average_confidence': sum(confidences) / len(confidences) if confidences else 0.0,
                'start_time': min(timestamps).isoformat() if timestamps else None,
                'end_time': max(timestamps).isoformat() if timestamps else None,
            }
        
        return stats
    
    def get_statistics(self) -> Dict:
        """Get overall timeline statistics"""
        if not self.timeline_events:
            return {}
        
        timestamps = [e['timestamp'] for e in self.timeline_events if e.get('timestamp')]
        
        total_duration = (max(timestamps) - min(timestamps)) if timestamps else timedelta(0)
        
        # Find most frequent phase
        phase_counts = {phase: len(events) for phase, events in self.phase_groups.items()}
        most_frequent = max(phase_counts.items(), key=lambda x: x[1]) if phase_counts else ('unknown', 0)
        
        # Find longest phase
        longest_phase = max(self.phase_durations.items(), key=lambda x: x[1]) if self.phase_durations else ('unknown', timedelta(0))
        
        return {
            'total_events': len(self.timeline_events),
            'total_duration_seconds': total_duration.total_seconds(),
            'total_duration_hours': total_duration.total_seconds() / 3600,
            'start_time': min(timestamps).isoformat() if timestamps else None,
            'end_time': max(timestamps).isoformat() if timestamps else None,
            'most_frequent_phase': {
                'phase': most_frequent[0],
                'count': most_frequent[1],
            },
            'longest_phase': {
                'phase': longest_phase[0],
                'duration_seconds': longest_phase[1].total_seconds(),
                'duration_hours': longest_phase[1].total_seconds() / 3600,
            },
            'phase_transitions': len(self.phase_transitions),
        }
    
    def get_events_by_time_range(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Get events within a specific time range"""
        return [
            e for e in self.timeline_events
            if e.get('timestamp') and start_time <= e['timestamp'] <= end_time
        ]
    
    def get_events_by_phase(self, phase: str) -> List[Dict]:
        """Get all events for a specific phase"""
        return self.phase_groups.get(phase, [])
