"""
Configuration settings for Attack Flow Analyzer
"""

import re
from datetime import timedelta

# Log format patterns
LOG_PATTERNS = {
    'apache_common': re.compile(
        r'(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\S+)'
    ),
    'apache_combined': re.compile(
        r'(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\S+) '
        r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    ),
    'syslog_auth': re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (?P<hostname>\S+) '
        r'(?P<service>\S+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)'
    ),
    'firewall_generic': re.compile(
        r'(?P<timestamp>.*?) (?P<action>\w+) (?P<protocol>\w+) '
        r'(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+) -> '
        r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)'
    ),
}

# Attack phase indicators
ATTACK_PHASES = {
    'reconnaissance': {
        'keywords': ['scan', 'nmap', 'enum', 'directory', 'robots.txt', 'sitemap', 'probe', 'crawl'],
        'status_codes': [404, 403],
        'patterns': [
            r'/\.(git|svn|env|config)/',
            r'/wp-admin|/phpmyadmin|/admin',
            r'\.(php|asp|jsp|py|sh|exe)$',
        ],
        'threshold': 10,  # Number of similar events to trigger
    },
    'initial_access': {
        'keywords': ['login', 'auth', 'failed', 'unauthorized', 'exploit', 'sql', 'xss', 'injection'],
        'status_codes': [401, 403, 500],
        'patterns': [
            r'SELECT.*FROM|UNION.*SELECT|DROP.*TABLE',
            r'<script|javascript:|onerror=',
            r'\.\./|\.\.\\|/etc/passwd',
        ],
        'threshold': 3,
    },
    'lateral_movement': {
        'keywords': ['ssh', 'rdp', 'smb', 'winrm', 'psexec', 'wmic', 'powershell'],
        'status_codes': [200, 302],
        'patterns': [
            r'10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+',
            r'cmd\.exe|powershell\.exe|wmic\.exe',
        ],
        'threshold': 5,
    },
    'exfiltration': {
        'keywords': ['upload', 'download', 'transfer', 'export', 'backup', 'archive'],
        'status_codes': [200, 201],
        'patterns': [
            r'\.(zip|tar|gz|rar|7z)$',
            r'/api/export|/api/download|/backup',
        ],
        'size_threshold': 10485760,  # 10MB
        'threshold': 2,
    },
}

# IOC extraction patterns
IOC_PATTERNS = {
    'ipv4': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    'ipv6': re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
    'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
    'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
}

# Suspicious user agents
SUSPICIOUS_USER_AGENTS = [
    'sqlmap', 'nikto', 'nmap', 'masscan', 'zmap', 'scanner',
    'bot', 'crawler', 'spider', 'scraper', 'hack', 'exploit',
]

# Correlation settings
CORRELATION_SETTINGS = {
    'session_timeout': timedelta(minutes=30),
    'ip_correlation_window': timedelta(hours=24),
    'user_correlation_window': timedelta(days=7),
}

# Export settings
EXPORT_FORMATS = ['json', 'csv']

# Visualization settings
VISUALIZATION = {
    'timeline_height': 600,
    'event_spacing': 20,
    'phase_colors': {
        'reconnaissance': '#FF6B6B',
        'initial_access': '#4ECDC4',
        'lateral_movement': '#45B7D1',
        'exfiltration': '#FFA07A',
        'unknown': '#95A5A6',
    },
}
