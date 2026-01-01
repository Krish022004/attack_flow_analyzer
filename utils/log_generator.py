"""
Enhanced Sample Log Generator for Demo
Generates comprehensive attack scenario logs showcasing all features
"""

import random
from datetime import datetime, timedelta
from pathlib import Path


class LogGenerator:
    """Generates comprehensive sample attack scenario logs for demo"""
    
    def __init__(self):
        # Primary attacker IPs - used across multiple phases for correlation
        self.attacker_ips = [
            '203.0.113.45',   # Primary attacker
            '198.51.100.23',  # Secondary attacker
            '192.0.2.67',     # Additional attacker IP
        ]
        
        # Internal network IPs for lateral movement
        self.victim_ips = [
            '10.0.0.100',     # Web server
            '10.0.0.101',     # Database server
            '10.0.0.102',     # Internal workstation
            '192.168.1.50',   # Another internal host
            '172.16.0.10',    # DMZ host
        ]
        
        # Suspicious domains for IOC extraction
        self.suspicious_domains = [
            'malicious-c2.com',
            'evil-domain.net',
            'attacker-c2.org',
            'suspicious-site.io',
            'badactor-domain.com',
        ]
        
        # Diverse suspicious user agents for IOC extraction
        self.suspicious_user_agents = [
            'sqlmap/1.7.5',
            'nikto/2.1.6',
            'Mozilla/5.0 (compatible; scanner/1.0)',
            'Python-requests/2.28.0',
            'masscan/1.0',
            'nmap/7.90',
            'Burp Suite Professional',
        ]
        
        # Normal user agents for contrast
        self.normal_user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]
        
        # Usernames for authentication logs
        self.attack_usernames = ['admin', 'root', 'administrator', 'test', 'guest']
        self.normal_usernames = ['john.doe', 'jane.smith', 'user1', 'developer', 'operator']
    
    def generate_apache_log(self, output_path: Path, num_events: int = 150):
        """Generate comprehensive Apache access log with full attack scenario"""
        start_time = datetime.now() - timedelta(hours=48)
        primary_attacker = self.attacker_ips[0]  # Use same IP for correlation
        
        with open(output_path, 'w') as f:
            current_time = start_time
            
            # ===== PHASE 1: RECONNAISSANCE (0-2 hours) =====
            print(f"Generating Reconnaissance phase...")
            for i in range(40):
                current_time += timedelta(minutes=random.randint(2, 5))
                attacker_ip = primary_attacker if i < 30 else random.choice(self.attacker_ips)
                
                # Various reconnaissance patterns
                recon_paths = [
                    '/.git/config',
                    '/.env',
                    '/.gitignore',
                    '/.htaccess',
                    '/wp-admin',
                    '/wp-login.php',
                    '/phpmyadmin',
                    '/admin',
                    '/administrator',
                    '/robots.txt',
                    '/sitemap.xml',
                    '/.well-known/security.txt',
                    '/backup',
                    '/old',
                    '/test',
                    '/dev',
                    '/.svn/entries',
                    '/.DS_Store',
                    '/config.php.bak',
                    '/wp-config.php',
                ]
                
                path = random.choice(recon_paths)
                status = random.choice([404, 403, 200, 301])
                
                # Use suspicious user agents
                user_agent = random.choice(self.suspicious_user_agents) if i < 25 else random.choice(self.normal_user_agents)
                
                log_line = (
                    f'{attacker_ip} - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
                    f'"GET {path} HTTP/1.1" {status} {random.randint(100, 2000)} '
                    f'"-" "{user_agent}"\n'
                )
                f.write(log_line)
            
            # ===== PHASE 2: INITIAL ACCESS (2-4 hours) =====
            print(f"Generating Initial Access phase...")
            for i in range(35):
                current_time += timedelta(minutes=random.randint(2, 4))
                attacker_ip = primary_attacker if i < 25 else random.choice(self.attacker_ips[1:])
                
                # SQL Injection attempts
                sql_paths = [
                    "/login.php?id=1' OR '1'='1",
                    "/search.php?q=admin' UNION SELECT * FROM users--",
                    "/api/user?id=1; DROP TABLE users--",
                    "/products.php?id=1' AND 1=1--",
                    "/login.php?user=admin'--",
                    "/api/data?id=1 UNION SELECT username,password FROM users",
                ]
                
                # XSS attempts
                xss_paths = [
                    "/comment.php?msg=<script>alert(document.cookie)</script>",
                    "/search?q=javascript:alert(1)",
                    "/contact?name=<img src=x onerror=alert(1)>",
                    "/feedback?text=<svg onload=alert(1)>",
                ]
                
                # Path traversal
                traversal_paths = [
                    "/download?file=../../../etc/passwd",
                    "/view?path=..\\..\\windows\\system32\\config\\sam",
                    "/api/file?name=....//....//etc/shadow",
                ]
                
                all_paths = sql_paths + xss_paths + traversal_paths
                path = random.choice(all_paths)
                status = random.choice([200, 401, 403, 500, 404])
                
                user_agent = random.choice(self.suspicious_user_agents)
                
                log_line = (
                    f'{attacker_ip} - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
                    f'"GET {path} HTTP/1.1" {status} {random.randint(500, 3000)} '
                    f'"-" "{user_agent}"\n'
                )
                f.write(log_line)
            
            # ===== PHASE 3: LATERAL MOVEMENT (4-6 hours) =====
            print(f"Generating Lateral Movement phase...")
            for i in range(25):
                current_time += timedelta(minutes=random.randint(3, 6))
                attacker_ip = primary_attacker
                internal_target = random.choice(self.victim_ips)
                
                # Internal network connections
                lateral_paths = [
                    f"/api/internal/connect?target={internal_target}",
                    "/ssh/tunnel",
                    "/rdp/proxy",
                    "/api/service/scan?network=10.0.0.0/8",
                    f"/internal?host={internal_target}",
                    "/smb/share?path=//10.0.0.101/shared",
                    "/winrm/execute?host=10.0.0.102",
                ]
                
                path = random.choice(lateral_paths)
                status = random.choice([200, 302, 401, 403])
                size = random.randint(1000, 10000)
                
                log_line = (
                    f'{attacker_ip} - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
                    f'"POST {path} HTTP/1.1" {status} {size} '
                    f'"http://{random.choice(self.suspicious_domains)}/index.html" '
                    f'"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n'
                )
                f.write(log_line)
            
            # ===== PHASE 4: EXFILTRATION (6-8 hours) =====
            print(f"Generating Exfiltration phase...")
            for i in range(20):
                current_time += timedelta(minutes=random.randint(5, 15))
                attacker_ip = primary_attacker
                
                # Large data transfers
                exfil_paths = [
                    "/api/export?format=json&table=users",
                    "/backup/download?file=database.sql",
                    "/data/export.zip",
                    "/api/dump?type=full",
                    "/download/customer_data.csv",
                    "/export/all_data.tar.gz",
                ]
                
                path = random.choice(exfil_paths)
                # Large transfer sizes (10-100 MB)
                size = random.randint(10485760, 104857600)
                status = 200
                
                log_line = (
                    f'{attacker_ip} - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
                    f'"GET {path} HTTP/1.1" {status} {size} '
                    f'"http://{random.choice(self.suspicious_domains)}/panel" '
                    f'"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n'
                )
                f.write(log_line)
            
            # Add some normal traffic for contrast (mixed throughout)
            print(f"Adding normal traffic...")
            for i in range(30):
                current_time = start_time + timedelta(minutes=random.randint(0, 480))
                normal_ip = f'192.168.1.{random.randint(100, 200)}'
                
                normal_paths = ['/', '/index.html', '/about', '/contact', '/products', '/services']
                path = random.choice(normal_paths)
                status = 200
                size = random.randint(5000, 50000)
                
                log_line = (
                    f'{normal_ip} - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
                    f'"GET {path} HTTP/1.1" {status} {size} '
                    f'"http://example.com/" "{random.choice(self.normal_user_agents)}"\n'
                )
                f.write(log_line)
    
    def generate_auth_log(self, output_path: Path, num_events: int = 80):
        """Generate authentication log with attack pattern"""
        start_time = datetime.now() - timedelta(hours=48)
        hostname = 'web-server-01'
        primary_attacker = self.attacker_ips[0]  # Same IP for correlation
        primary_user = 'admin'  # Same user for correlation
        
        with open(output_path, 'w') as f:
            current_time = start_time + timedelta(hours=2)  # Start after reconnaissance
            
            # ===== FAILED LOGIN ATTEMPTS (Initial Access Phase) =====
            print(f"Generating failed login attempts...")
            for i in range(25):
                current_time += timedelta(minutes=random.randint(2, 5))
                attacker_ip = primary_attacker if i < 20 else random.choice(self.attacker_ips[1:])
                username = random.choice(self.attack_usernames) if i < 20 else primary_user
                
                log_line = (
                    f'{current_time.strftime("%b %d %H:%M:%S")} {hostname} sshd[{1234 + i}]: '
                    f'Failed password for {username} from {attacker_ip} port {random.randint(40000, 50000)} ssh2\n'
                )
                f.write(log_line)
            
            # Successful login after many failures (indicating breach)
            current_time += timedelta(minutes=10)
            log_line = (
                f'{current_time.strftime("%b %d %H:%M:%S")} {hostname} sshd[2000]: '
                f'Accepted password for {primary_user} from {primary_attacker} port {random.randint(40000, 50000)} ssh2\n'
            )
            f.write(log_line)
            
            # More SSH sessions from same IP (Lateral Movement)
            print(f"Generating additional SSH sessions...")
            for i in range(8):
                current_time += timedelta(hours=random.randint(2, 4), minutes=random.randint(0, 30))
                internal_target = random.choice(self.victim_ips)
                username = random.choice(['root', 'admin', 'operator'])
                
                log_line = (
                    f'{current_time.strftime("%b %d %H:%M:%S")} {hostname} sshd[{2001 + i}]: '
                    f'Accepted publickey for {username} from {primary_attacker} port {random.randint(40000, 50000)} ssh2\n'
                )
                f.write(log_line)
            
            # Normal logins for contrast
            print(f"Adding normal authentication events...")
            for i in range(15):
                current_time = start_time + timedelta(minutes=random.randint(0, 600))
                normal_ip = f'192.168.1.{random.randint(100, 200)}'
                username = random.choice(self.normal_usernames)
                
                log_line = (
                    f'{current_time.strftime("%b %d %H:%M:%S")} {hostname} sshd[{3000 + i}]: '
                    f'Accepted publickey for {username} from {normal_ip} port 22 ssh2\n'
                )
                f.write(log_line)
            
            # Some logout events
            for i in range(5):
                current_time = start_time + timedelta(minutes=random.randint(100, 500))
                normal_ip = f'192.168.1.{random.randint(100, 200)}'
                username = random.choice(self.normal_usernames)
                
                log_line = (
                    f'{current_time.strftime("%b %d %H:%M:%S")} {hostname} sshd[{4000 + i}]: '
                    f'Connection closed by {username} from {normal_ip} port 22 [preauth]\n'
                )
                f.write(log_line)
    
    def generate_firewall_log(self, output_path: Path, num_events: int = 50):
        """Generate firewall log with attack patterns"""
        start_time = datetime.now() - timedelta(hours=48)
        primary_attacker = self.attacker_ips[0]  # Same IP for correlation
        
        with open(output_path, 'w') as f:
            current_time = start_time
            
            # ===== BLOCKED CONNECTIONS (Reconnaissance & Initial Access) =====
            print(f"Generating blocked connections...")
            for i in range(20):
                current_time += timedelta(minutes=random.randint(3, 10))
                attacker_ip = primary_attacker if i < 15 else random.choice(self.attacker_ips[1:])
                victim_ip = random.choice(self.victim_ips)
                
                # Various blocked port attempts
                ports = [22, 80, 443, 3389, 3306, 5432, 8080, 8443]
                
                log_line = (
                    f'{current_time.strftime("%Y-%m-%d %H:%M:%S")} BLOCK TCP '
                    f'{attacker_ip}:{random.randint(40000, 50000)} -> '
                    f'{victim_ip}:{random.choice(ports)}\n'
                )
                f.write(log_line)
            
            # ===== ALLOWED BUT SUSPICIOUS (After initial access) =====
            print(f"Generating allowed suspicious connections...")
            current_time = start_time + timedelta(hours=4)
            for i in range(12):
                current_time += timedelta(minutes=random.randint(5, 15))
                attacker_ip = primary_attacker
                victim_ip = random.choice(self.victim_ips)
                
                log_line = (
                    f'{current_time.strftime("%Y-%m-%d %H:%M:%S")} ALLOW TCP '
                    f'{attacker_ip}:{random.randint(40000, 50000)} -> '
                    f'{victim_ip}:{random.choice([80, 443, 8080])}\n'
                )
                f.write(log_line)
            
            # ===== INTERNAL LATERAL MOVEMENT (Lateral Movement Phase) =====
            print(f"Generating internal lateral movement...")
            current_time = start_time + timedelta(hours=5)
            for i in range(10):
                current_time += timedelta(minutes=random.randint(8, 20))
                source_ip = random.choice(self.victim_ips)
                dest_ip = random.choice([ip for ip in self.victim_ips if ip != source_ip])
                
                log_line = (
                    f'{current_time.strftime("%Y-%m-%d %H:%M:%S")} ALLOW TCP '
                    f'{source_ip}:{random.randint(30000, 40000)} -> '
                    f'{dest_ip}:{random.choice([22, 445, 5985, 5986])}\n'
                )
                f.write(log_line)
            
            # ===== LARGE OUTBOUND TRANSFERS (Exfiltration Phase) =====
            print(f"Generating exfiltration events...")
            current_time = start_time + timedelta(hours=6)
            for i in range(5):
                current_time += timedelta(minutes=random.randint(10, 30))
                internal_ip = random.choice(self.victim_ips)
                external_ip = random.choice(self.attacker_ips)
                
                log_line = (
                    f'{current_time.strftime("%Y-%m-%d %H:%M:%S")} ALLOW TCP '
                    f'{internal_ip}:{random.randint(50000, 60000)} -> '
                    f'{external_ip}:{random.choice([443, 8080, 8443])}\n'
                )
                f.write(log_line)
            
            # Normal internal traffic
            print(f"Adding normal firewall events...")
            for i in range(8):
                current_time = start_time + timedelta(minutes=random.randint(0, 600))
                internal_ip1 = random.choice(self.victim_ips)
                internal_ip2 = random.choice([ip for ip in self.victim_ips if ip != internal_ip1])
                
                log_line = (
                    f'{current_time.strftime("%Y-%m-%d %H:%M:%S")} ALLOW TCP '
                    f'{internal_ip1}:{random.randint(30000, 40000)} -> '
                    f'{internal_ip2}:{random.choice([80, 443, 22])}\n'
                )
                f.write(log_line)
    
    def generate_all(self, output_dir: Path):
        """Generate all sample logs for comprehensive demo"""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print("=" * 60)
        print("Generating Comprehensive Demo Log Files")
        print("=" * 60)
        print()
        
        print("1. Generating Apache Access Log...")
        self.generate_apache_log(output_dir / 'access.log', num_events=150)
        print("   ✓ Generated access.log with all attack phases\n")
        
        print("2. Generating Authentication Log...")
        self.generate_auth_log(output_dir / 'auth.log', num_events=80)
        print("   ✓ Generated auth.log with failed/successful logins\n")
        
        print("3. Generating Firewall Log...")
        self.generate_firewall_log(output_dir / 'firewall.log', num_events=50)
        print("   ✓ Generated firewall.log with blocked/allowed connections\n")
        
        print("=" * 60)
        print(f"✓ All demo logs generated successfully in: {output_dir}")
        print("=" * 60)
        print()
        print("Demo Log Summary:")
        print("  - Access Log: ~150 events covering all 4 attack phases")
        print("  - Auth Log: ~80 events including failed/successful logins")
        print("  - Firewall Log: ~50 events with blocked and allowed connections")
        print()
        print("Key Features Demonstrated:")
        print("  ✓ All 4 attack phases (Reconnaissance → Initial Access → Lateral Movement → Exfiltration)")
        print("  ✓ Multiple IOCs (IPs, domains, URLs, user agents)")
        print("  ✓ Event correlation (same IPs/users across logs)")
        print("  ✓ Realistic attack timeline")
        print("  ✓ Mixed normal and attack traffic")
        print()


if __name__ == '__main__':
    generator = LogGenerator()
    output_dir = Path(__file__).parent.parent / 'data' / 'sample_logs'
    generator.generate_all(output_dir)
