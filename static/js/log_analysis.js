let attackChartInstance = null;

// Check for captured packets on page load
document.addEventListener('DOMContentLoaded', function() {
    checkCapturedPackets();
    // Check every 5 seconds for new packets
    setInterval(checkCapturedPackets, 5000);
});

function checkCapturedPackets() {
    fetch('/capture/packets')
        .then(response => response.json())
        .then(data => {
            const packetCount = data.total || 0;
            const packetCountText = document.getElementById('packet-count-text');
            const analyzeButton = document.getElementById('analyze-packets-button');
            const downloadButton = document.getElementById('download-packets-button');
            const statusDiv = document.getElementById('packet-status');
            
            if (packetCount > 0) {
                packetCountText.textContent = `${packetCount} packet(s) captured and ready for analysis`;
                statusDiv.innerHTML = `<div class="alert alert-success">
                    <i class="fas fa-check-circle me-2"></i>
                    <span id="packet-count-text">${packetCount} packet(s) captured and ready for analysis</span>
                </div>`;
                analyzeButton.disabled = false;
                downloadButton.disabled = false;
            } else {
                packetCountText.textContent = 'No packets captured yet. Go to Packet Capture page to capture packets.';
                statusDiv.innerHTML = `<div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>
                    <span id="packet-count-text">No packets captured yet. Go to Packet Capture page to capture packets.</span>
                </div>`;
                analyzeButton.disabled = true;
                downloadButton.disabled = true;
            }
        })
        .catch(error => {
            console.error('Error checking captured packets:', error);
            const statusDiv = document.getElementById('packet-status');
            statusDiv.innerHTML = `<div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <span id="packet-count-text">Unable to check packet status. Packet capture may not be available.</span>
            </div>`;
        });
}

function analyzeCapturedPackets() {
    const analyzeButton = document.getElementById('analyze-packets-button');
    analyzeButton.disabled = true;
    analyzeButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
    
    fetch('/capture/packets')
        .then(response => response.json())
        .then(data => {
            if (!data.packets || data.packets.length === 0) {
                alert('No packets captured. Please capture packets first.');
                analyzeButton.disabled = false;
                analyzeButton.innerHTML = '<i class="fas fa-search me-2"></i>Analyze Captured Packets';
                return;
            }
            
            // Convert packets to log format
            const logText = convertPacketsToLog(data.packets);
            
            // Analyze the converted log
            const attackData = parseLog(logText, 'captured_packets.log');
            updateUI(attackData);
            
            analyzeButton.disabled = false;
            analyzeButton.innerHTML = '<i class="fas fa-search me-2"></i>Analyze Captured Packets';
        })
        .catch(error => {
            console.error('Error analyzing packets:', error);
            alert('Error analyzing captured packets: ' + error.message);
            analyzeButton.disabled = false;
            analyzeButton.innerHTML = '<i class="fas fa-search me-2"></i>Analyze Captured Packets';
        });
}

function downloadCapturedPackets() {
    window.location.href = '/capture/download';
}

function convertPacketsToLog(packets) {
    const logLines = [];
    
    packets.forEach(packet => {
        const timestamp = packet.timestamp || new Date().toISOString();
        const sourceIp = packet.source_ip || 'unknown';
        const destIp = packet.destination_ip || 'unknown';
        const protocol = packet.protocol || 'UNKNOWN';
        const sourcePort = packet.source_port || '';
        const destPort = packet.destination_port || '';
        const length = packet.length || 0;
        const info = packet.info || '';
        
        // Format: [timestamp] PROTOCOL source_ip:port -> dest_ip:port LEN:length INFO:details
        const logLine = `[${timestamp}] ${protocol.toUpperCase()} ${sourceIp}:${sourcePort} -> ${destIp}:${destPort} LEN:${length} INFO:${info}`;
        logLines.push(logLine);
    });
    
    return logLines.join('\n');
}

function runAnalysis() {
    const fileInput = document.getElementById('direct-log-file');
    if (!fileInput || fileInput.files.length === 0) {
        alert("Please provide a log file to analyze.");
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();
    
    reader.onload = function(e) {
        const text = e.target.result;
        const attackData = parseLog(text, file.name);
        updateUI(attackData);
    };
    
    reader.readAsText(file);
}

function updateUI(attackData) {
    const now = new Date().toLocaleString();

    // 1️⃣ Attack chart
    const chartLabels = Object.keys(attackData);
    const chartCounts = chartLabels.map(k => attackData[k].count);

    const chartCard = document.getElementById('attack-chart-card');
    chartCard.style.display = 'block';

    const ctx = document.getElementById('attack-chart').getContext('2d');
    if (attackChartInstance) attackChartInstance.destroy();

    attackChartInstance = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: chartLabels,
            datasets: [{
                label: 'Number of Attacks',
                data: chartCounts,
                backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { 
                legend: { position: 'bottom' } 
            }
        }
    });

    // Show or hide "no attacks" message
    const noAttacksMsg = document.getElementById('no-attacks-msg');
    noAttacksMsg.style.display = chartCounts.some(c => c > 0) ? 'none' : 'block';

    // 2️⃣ Attack list
    const attackList = document.getElementById('attack-list');
    attackList.innerHTML = '';
    let anyDetected = false;
    Object.keys(attackData).forEach(k => {
        if (attackData[k].count > 0) {
            anyDetected = true;
            const li = document.createElement('li');
            li.className = 'list-group-item d-flex justify-content-between align-items-center';
            li.innerHTML = `<span>${k}</span><span class="badge bg-danger rounded-pill">${attackData[k].count}</span>`;
            attackList.appendChild(li);
        }
    });
    if (!anyDetected) {
        attackList.innerHTML = '<li class="list-group-item text-muted">No attacks detected.</li>';
    }

    // 3️⃣ Attack details table
    const tbody = document.getElementById('attackTableBody');
    tbody.innerHTML = '';
    Object.keys(attackData).forEach(k => {
        const attack = attackData[k];
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${k}</td>
            <td class="text-center">${attack.count}</td>
            <td class="text-center">${attack.severity}</td>
            <td class="text-center">${attack.count > 0 ? now : '-'}</td>
            <td>${attack.suggestion}</td>
        `;
        tbody.appendChild(tr);
    });
}

function parseLog(text, filename = '') {
    const attacks = {
        "Brute Force": { count:0, suggestion:"Use strong passwords & rate-limiting", severity:"Low", last_detected:"-" },
        "SQL Injection": { count:0, suggestion:"Validate & sanitize inputs", severity:"Low", last_detected:"-" },
        "XSS": { count:0, suggestion:"Escape user inputs on web pages", severity:"Low", last_detected:"-" },
        "DDoS": { count:0, suggestion:"Use firewall and rate-limiting", severity:"Low", last_detected:"-" },
        "Port Scan": { count:0, suggestion:"Monitor for multiple connection attempts to different ports", severity:"Medium", last_detected:"-" },
        "Suspicious Port": { count:0, suggestion:"Review connections to non-standard ports", severity:"Medium", last_detected:"-" }
    };

    const now = new Date().toLocaleString();
    const lines = text.split("\n");
    
    // Track IPs and ports for port scan detection (for packet logs)
    const ipPortMap = {};
    const suspiciousPorts = [4444, 5555, 6666, 6667, 8080, 31337, 12345, 54321]; // Common malicious ports

    lines.forEach(line => {
        // Auth logs
        if (/auth/i.test(filename) || /login/i.test(filename)) {
            if (/failed password|authentication failure|invalid user/i.test(line)) {
                attacks["Brute Force"].count++;
                attacks["Brute Force"].severity = "High";
                attacks["Brute Force"].last_detected = now;
            }
        }

        // Access logs
        if (/access/i.test(filename)) {
            if (/select .* from|union .* select|insert into|update .* set/i.test(line)) {
                attacks["SQL Injection"].count++;
                attacks["SQL Injection"].severity = "High";
                attacks["SQL Injection"].last_detected = now;
            }
            if (/<script>|alert\(|onerror=|onload=/i.test(line)) {
                attacks["XSS"].count++;
                attacks["XSS"].severity = "High";
                attacks["XSS"].last_detected = now;
            }
        }

        // Firewall logs
        if (/firewall/i.test(filename)) {
            if (/blocked|denied|dropped|syn flood|port scan|connection reset/i.test(line)) {
                attacks["DDoS"].count++;
                attacks["DDoS"].severity = "High";
                attacks["DDoS"].last_detected = now;
            }
        }
        
        // Packet capture logs (format: [timestamp] PROTOCOL source_ip:port -> dest_ip:port LEN:length INFO:details)
        if (/captured_packets|packet/i.test(filename) || /LEN:/i.test(line)) {
            // Extract IP and port information
            const ipPortMatch = line.match(/(\d+\.\d+\.\d+\.\d+):(\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+):(\d+)/);
            if (ipPortMatch) {
                const sourceIp = ipPortMatch[1];
                const sourcePort = parseInt(ipPortMatch[2]);
                const destIp = ipPortMatch[3];
                const destPort = parseInt(ipPortMatch[4]);
                
                // Track connections for port scan detection
                if (!ipPortMap[sourceIp]) {
                    ipPortMap[sourceIp] = new Set();
                }
                ipPortMap[sourceIp].add(destPort);
                
                // Check for suspicious ports
                if (suspiciousPorts.includes(destPort) || suspiciousPorts.includes(sourcePort)) {
                    attacks["Suspicious Port"].count++;
                    attacks["Suspicious Port"].severity = "High";
                    attacks["Suspicious Port"].last_detected = now;
                }
            }
            
            // DDoS detection - high volume of packets
            if (/LEN:\d{4,}/i.test(line)) { // Large packets
                attacks["DDoS"].count++;
                attacks["DDoS"].severity = "High";
                attacks["DDoS"].last_detected = now;
            }
            
            // Check for port scan patterns in info field
            if (/port scan|scanning|probe/i.test(line)) {
                attacks["Port Scan"].count++;
                attacks["Port Scan"].severity = "High";
                attacks["Port Scan"].last_detected = now;
            }
        }
    });
    
    // Detect port scans: same IP connecting to many different ports
    Object.keys(ipPortMap).forEach(ip => {
        if (ipPortMap[ip].size > 10) { // More than 10 different ports from same IP
            attacks["Port Scan"].count++;
            attacks["Port Scan"].severity = "High";
            attacks["Port Scan"].last_detected = now;
        }
    });

    return attacks;
}
