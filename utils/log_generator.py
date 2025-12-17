"""
Sample Log Generator
Generates realistic attack scenario logs for testing
"""

import random
from datetime import datetime, timedelta
from pathlib import Path


class LogGenerator:
    """Generates sample attack scenario logs"""
    
    def __init__(self):
        self.attacker_ips = [
            '203.0.113.45',
            '198.51.100.23',
            '192.0.2.67',
            '203.0.113.89',
        ]
        self.victim_ips = [
            '10.0.0.100',
            '192.168.1.50',
            '172.16.0.10',
        ]
        self.suspicious_domains = [
            'malicious-site.com',
            'evil-domain.net',
            'attacker-c2.org',
        ]
        self.suspicious_user_agents = [
            'sqlmap/1.0',
            'nikto/2.1.6',
            'Mozilla/5.0 (compatible; scanner/1.0)',
        ]
        self.normal_user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        ]
    
    def generate_apache_log(self, output_path: Path, num_events: int = 100):
        """Generate Apache access log with attack scenario"""
        start_time = datetime.now() - timedelta(hours=24)
        
        with open(output_path, 'w') as f:
            # Phase 1: Reconnaissance (first 30 events)
            for i in range(30):
                timestamp = start_time + timedelta(minutes=i*2)
                attacker_ip = random.choice(self.attacker_ips)
                
                # Reconnaissance patterns
                paths = [
                    '/.git/config',
                    '/.env',
                    '/wp-admin',
                    '/phpmyadmin',
                    '/admin',
                    '/robots.txt',
                    '/sitemap.xml',
                    '/.well-known/security.txt',
                ]
                
                path = random.choice(paths)
                status = random.choice([404, 403, 200])
                
                log_line = (
                    f'{attacker_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
                    f'"GET {path} HTTP/1.1" {status} {random.randint(100, 1000)} '
                    f'"-" "{random.choice(self.suspicious_user_agents)}"\n'
                )
                f.write(log_line)
            
            # Phase 2: Initial Access (next 20 events)
            for i in range(20):
                timestamp = start_time + timedelta(minutes=60 + i*3)
                attacker_ip = random.choice(self.attacker_ips)
                
                # SQL injection attempts
                sql_paths = [
                    '/login.php?id=1\' OR \'1\'=\'1',
                    '/search.php?q=admin\' UNION SELECT * FROM users',
                    '/api/user?id=1; DROP TABLE users--',
                ]
                
                # XSS attempts
                xss_paths = [
                    '/comment.php?msg=<script>alert(1)</script>',
                    '/search?q=javascript:alert(document.cookie)',
                ]
                
                paths = sql_paths + xss_paths
                path = random.choice(paths)
                status = random.choice([200, 401, 403, 500])
                
                log_line = (
                    f'{attacker_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
                    f'"GET {path} HTTP/1.1" {status} {random.randint(500, 2000)} '
                    f'"-" "{random.choice(self.suspicious_user_agents)}"\n'
                )
                f.write(log_line)
            
            # Phase 3: Lateral Movement (next 15 events)
            for i in range(15):
                timestamp = start_time + timedelta(minutes=120 + i*5)
                attacker_ip = random.choice(self.attacker_ips)
                internal_ip = random.choice(self.victim_ips)
                
                # Internal connections
                paths = [
                    f'/api/internal?target={internal_ip}',
                    '/ssh/connect',
                    '/rdp/session',
                ]
                
                path = random.choice(paths)
                status = random.choice([200, 302])
                
                log_line = (
                    f'{attacker_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
                    f'"POST {path} HTTP/1.1" {status} {random.randint(1000, 5000)} '
                    f'"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n'
                )
                f.write(log_line)
            
            # Phase 4: Exfiltration (last 10 events)
            for i in range(10):
                timestamp = start_time + timedelta(minutes=195 + i*10)
                attacker_ip = random.choice(self.attacker_ips)
                
                # Large data transfers
                paths = [
                    '/api/export?format=json',
                    '/backup/download',
                    '/data/export.zip',
                ]
                
                path = random.choice(paths)
                size = random.randint(10485760, 52428800)  # 10-50 MB
                
                log_line = (
                    f'{attacker_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
                    f'"GET {path} HTTP/1.1" 200 {size} '
                    f'"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n'
                )
                f.write(log_line)
            
            # Add some normal traffic
            for i in range(25):
                timestamp = start_time + timedelta(minutes=random.randint(0, 300))
                normal_ip = f'192.168.1.{random.randint(100, 200)}'
                
                paths = ['/', '/index.html', '/about', '/contact', '/products']
                path = random.choice(paths)
                status = 200
                
                log_line = (
                    f'{normal_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
                    f'"GET {path} HTTP/1.1" {status} {random.randint(5000, 50000)} '
                    f'"-" "{random.choice(self.normal_user_agents)}"\n'
                )
                f.write(log_line)
    
    def generate_auth_log(self, output_path: Path, num_events: int = 50):
        """Generate authentication log"""
        start_time = datetime.now() - timedelta(hours=24)
        hostname = 'web-server-01'
        
        with open(output_path, 'w') as f:
            # Failed login attempts
            for i in range(20):
                timestamp = start_time + timedelta(minutes=i*5)
                attacker_ip = random.choice(self.attacker_ips)
                username = random.choice(['admin', 'root', 'user', 'test'])
                
                log_line = (
                    f'{timestamp.strftime("%b %d %H:%M:%S")} {hostname} sshd[1234]: '
                    f'Failed password for {username} from {attacker_ip} port 22 ssh2\n'
                )
                f.write(log_line)
            
            # Successful login (after many failures)
            timestamp = start_time + timedelta(minutes=100)
            attacker_ip = random.choice(self.attacker_ips)
            log_line = (
                f'{timestamp.strftime("%b %d %H:%M:%S")} {hostname} sshd[1235]: '
                f'Accepted password for admin from {attacker_ip} port 22 ssh2\n'
            )
            f.write(log_line)
            
            # Normal logins
            for i in range(10):
                timestamp = start_time + timedelta(minutes=random.randint(0, 300))
                normal_ip = f'192.168.1.{random.randint(100, 200)}'
                username = random.choice(['john', 'jane', 'user1'])
                
                log_line = (
                    f'{timestamp.strftime("%b %d %H:%M:%S")} {hostname} sshd[1236]: '
                    f'Accepted publickey for {username} from {normal_ip} port 22 ssh2\n'
                )
                f.write(log_line)
    
    def generate_firewall_log(self, output_path: Path, num_events: int = 30):
        """Generate firewall log"""
        start_time = datetime.now() - timedelta(hours=24)
        
        with open(output_path, 'w') as f:
            # Blocked connections
            for i in range(15):
                timestamp = start_time + timedelta(minutes=i*8)
                attacker_ip = random.choice(self.attacker_ips)
                victim_ip = random.choice(self.victim_ips)
                
                log_line = (
                    f'{timestamp.strftime("%Y-%m-%d %H:%M:%S")} BLOCK TCP '
                    f'{attacker_ip}:{random.randint(40000, 50000)} -> '
                    f'{victim_ip}:{random.choice([22, 80, 443, 3389])}\n'
                )
                f.write(log_line)
            
            # Allowed connections (internal)
            for i in range(10):
                timestamp = start_time + timedelta(minutes=random.randint(0, 200))
                internal_ip1 = random.choice(self.victim_ips)
                internal_ip2 = random.choice(self.victim_ips)
                
                log_line = (
                    f'{timestamp.strftime("%Y-%m-%d %H:%M:%S")} ALLOW TCP '
                    f'{internal_ip1}:{random.randint(30000, 40000)} -> '
                    f'{internal_ip2}:{random.choice([22, 80, 443])}\n'
                )
                f.write(log_line)
            
            # Allowed but suspicious
            for i in range(5):
                timestamp = start_time + timedelta(minutes=120 + i*10)
                attacker_ip = random.choice(self.attacker_ips)
                victim_ip = random.choice(self.victim_ips)
                
                log_line = (
                    f'{timestamp.strftime("%Y-%m-%d %H:%M:%S")} ALLOW TCP '
                    f'{attacker_ip}:{random.randint(40000, 50000)} -> '
                    f'{victim_ip}:80\n'
                )
                f.write(log_line)
    
    def generate_all(self, output_dir: Path):
        """Generate all sample logs"""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        self.generate_apache_log(output_dir / 'access.log')
        self.generate_auth_log(output_dir / 'auth.log')
        self.generate_firewall_log(output_dir / 'firewall.log')
        
        print(f"Generated sample logs in {output_dir}")


if __name__ == '__main__':
    generator = LogGenerator()
    output_dir = Path(__file__).parent.parent / 'data' / 'sample_logs'
    generator.generate_all(output_dir)
