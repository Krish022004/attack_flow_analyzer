/**
 * Packet Capture page JavaScript
 */

let selectedPcapFiles = [];
let captureStatusInterval = null;
let socket = null;
let packetList = [];
let filteredPackets = [];
let autoScrollEnabled = true;
let selectedPacketIndex = -1;

// Update navigation active state
document.addEventListener('DOMContentLoaded', function() {
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });

    setupPcapUpload();
    setupLiveCapture();
    setupAnalyzeButton();
});

// ============ PCAP File Upload ============

function setupPcapUpload() {
    const uploadArea = document.getElementById('pcap-upload-area');
    const fileInput = document.getElementById('pcap-files');

    if (!uploadArea || !fileInput) return;

    // Drag and drop
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, preventDefaults, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        uploadArea.addEventListener(eventName, () => {
            uploadArea.classList.add('dragover');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, () => {
            uploadArea.classList.remove('dragover');
        }, false);
    });

    uploadArea.addEventListener('drop', (e) => {
        const files = Array.from(e.dataTransfer.files).filter(f => 
            f.name.endsWith('.pcap') || f.name.endsWith('.pcapng')
        );
        handlePcapFiles(files);
    }, false);

    uploadArea.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', (e) => {
        handlePcapFiles(Array.from(e.target.files));
    });

    // Upload button
    const uploadButton = document.getElementById('pcap-upload-button');
    if (uploadButton) {
        uploadButton.addEventListener('click', uploadPcapFiles);
    }
}

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

function handlePcapFiles(files) {
    selectedPcapFiles = files;
    displayPcapFileList();
    document.getElementById('pcap-upload-button-container').style.display = 'block';
}

function displayPcapFileList() {
    const fileListDiv = document.getElementById('pcap-file-list');
    const fileItemsDiv = document.getElementById('pcap-file-items');

    if (selectedPcapFiles.length === 0) {
        fileListDiv.style.display = 'none';
        return;
    }

    fileListDiv.style.display = 'block';
    fileItemsDiv.innerHTML = '';

    selectedPcapFiles.forEach((file, index) => {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-upload-item';
        fileItem.innerHTML = `
            <div class="file-info">
                <div class="file-icon">
                    <i class="fas fa-file-code"></i>
                </div>
                <div class="file-details">
                    <div class="file-name">${file.name}</div>
                    <div class="file-size">${AttackFlowUtils.formatFileSize(file.size)}</div>
                </div>
            </div>
            <div class="file-actions">
                <button class="btn btn-sm btn-outline-danger" onclick="removePcapFile(${index})">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        fileItemsDiv.appendChild(fileItem);
    });
}

function removePcapFile(index) {
    selectedPcapFiles.splice(index, 1);
    displayPcapFileList();
    if (selectedPcapFiles.length === 0) {
        document.getElementById('pcap-upload-button-container').style.display = 'none';
    }
}

async function uploadPcapFiles() {
    if (selectedPcapFiles.length === 0) {
        AttackFlowUtils.toast.warning('Please select at least one pcap file');
        return;
    }

    const formData = new FormData();
    selectedPcapFiles.forEach(file => {
        formData.append('files[]', file, file.name);
    });

    const statusDiv = document.getElementById('pcap-upload-status');
    statusDiv.innerHTML = '<div class="alert alert-info">Uploading files...</div>';

    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (response.ok) {
            AttackFlowUtils.toast.success(`Successfully uploaded ${selectedPcapFiles.length} pcap file(s)`);
            statusDiv.innerHTML = `
                <div class="alert alert-success">
                    <i class="fas fa-check-circle me-2"></i>Files uploaded successfully!
                    <div class="mt-2">
                        <a href="/upload" class="btn btn-sm btn-primary">
                            <i class="fas fa-chart-line me-1"></i>Go to Analysis
                        </a>
                    </div>
                </div>
            `;
            selectedPcapFiles = [];
            displayPcapFileList();
        } else {
            AttackFlowUtils.toast.error('Upload failed: ' + (data.error || 'Unknown error'));
            statusDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
        }
    } catch (error) {
        AttackFlowUtils.toast.error('Upload error: ' + error.message);
        statusDiv.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
    }
}

// ============ Live Capture ============

function setupLiveCapture() {
    const startButton = document.getElementById('start-capture-button');
    const stopButton = document.getElementById('stop-capture-button');
    const clearButton = document.getElementById('clear-packets-button');
    const autoScrollToggle = document.getElementById('auto-scroll-toggle');

    if (startButton) {
        startButton.addEventListener('click', startCapture);
    }

    if (stopButton) {
        stopButton.addEventListener('click', stopCapture);
    }

    if (clearButton) {
        clearButton.addEventListener('click', clearPackets);
    }

    if (autoScrollToggle) {
        autoScrollToggle.addEventListener('change', (e) => {
            autoScrollEnabled = e.target.checked;
        });
    }

    // Setup packet filters
    setupPacketFilters();

    // Check initial status
    updateCaptureStatus();
    
    // Initialize WebSocket connection
    initializeWebSocket();
    
    // Load any previously captured packets
    loadCapturedPackets();
}

async function startCapture() {
    const interface = document.getElementById('capture-interface').value.trim() || null;
    const packetCount = parseInt(document.getElementById('capture-count').value) || 1000;
    const duration = document.getElementById('capture-duration').value ? 
        parseInt(document.getElementById('capture-duration').value) : null;

    const startButton = document.getElementById('start-capture-button');
    const stopButton = document.getElementById('stop-capture-button');
    const statusDiv = document.getElementById('capture-status');

    startButton.disabled = true;
    statusDiv.innerHTML = '<div class="alert alert-info">Starting capture...</div>';

    try {
        const response = await fetch('/capture/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                interface: interface,
                packet_count: packetCount,
                duration: duration
            })
        });

        const data = await response.json();

        if (response.ok) {
            AttackFlowUtils.toast.success('Live capture started');
            startButton.disabled = true;
            stopButton.disabled = false;
            statusDiv.innerHTML = '<div class="alert alert-success">Capture is running...</div>';
            
            // Connect to WebSocket FIRST, then start capture
            // This ensures WebSocket is ready before packets start arriving
            connectPacketStream();
            
            // Wait a moment for WebSocket to connect before starting capture
            setTimeout(() => {
                // Start polling for status
                if (captureStatusInterval) {
                    clearInterval(captureStatusInterval);
                }
                captureStatusInterval = setInterval(updateCaptureStatus, 2000);
            }, 500);
        } else {
            AttackFlowUtils.toast.error('Failed to start capture: ' + (data.error || 'Unknown error'));
            statusDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
            startButton.disabled = false;
        }
    } catch (error) {
        AttackFlowUtils.toast.error('Error: ' + error.message);
        statusDiv.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
        startButton.disabled = false;
    }
}

async function stopCapture() {
    const startButton = document.getElementById('start-capture-button');
    const stopButton = document.getElementById('stop-capture-button');
    const statusDiv = document.getElementById('capture-status');

    stopButton.disabled = true;
    statusDiv.innerHTML = '<div class="alert alert-info">Stopping capture...</div>';

    try {
        const response = await fetch('/capture/stop', {
            method: 'POST'
        });

        const data = await response.json();

        if (response.ok) {
            AttackFlowUtils.toast.success(`Capture stopped. Captured ${data.packets_captured} packets.`);
            startButton.disabled = false;
            stopButton.disabled = true;
            statusDiv.innerHTML = `
                <div class="alert alert-success">
                    <i class="fas fa-check-circle me-2"></i>Capture stopped successfully
                    <p class="mb-0 mt-2">Packets captured: ${data.packets_captured}</p>
                </div>
            `;
            
            if (captureStatusInterval) {
                clearInterval(captureStatusInterval);
                captureStatusInterval = null;
            }
            
            // Keep WebSocket connected briefly to receive final packets, then disconnect
            setTimeout(() => {
                disconnectPacketStream();
            }, 2000);
            
            // Load captured packets into the display
            if (data.packets_captured > 0) {
                loadCapturedPackets();
            }
            
            updateCaptureStatistics(data.status);
        } else {
            AttackFlowUtils.toast.error('Failed to stop capture: ' + (data.error || 'Unknown error'));
            statusDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
            stopButton.disabled = false;
        }
    } catch (error) {
        AttackFlowUtils.toast.error('Error: ' + error.message);
        statusDiv.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
        stopButton.disabled = false;
    }
}

async function updateCaptureStatus() {
    try {
        const response = await fetch('/capture/status');
        const data = await response.json();

        const statusDiv = document.getElementById('capture-status');
        
        if (data.is_capturing) {
            statusDiv.innerHTML = `
                <div class="alert alert-success">
                    <i class="fas fa-circle me-2" style="color: red;"></i>Capture is running
                    <p class="mb-0 mt-2">Queued packets: ${data.queued_packets || 0}</p>
                </div>
            `;
            updateCaptureStatistics(data);
        } else if (data.has_captured_packets) {
            // Show status for captured but not currently capturing
            const analyzedStatus = data.packets_analyzed ? 
                '<span class="badge bg-success ms-2">Analyzed</span>' : 
                '<span class="badge bg-warning ms-2">Not Analyzed</span>';
            
            statusDiv.innerHTML = `
                <div class="alert alert-info">
                    <i class="fas fa-check-circle me-2"></i>Packets captured: ${data.packets_captured}
                    ${analyzedStatus}
                    ${!data.packets_analyzed ? '<p class="mb-0 mt-2"><small>Click "Analyze Packets" to analyze captured packets</small></p>' : ''}
                </div>
            `;
            
            if (data.packets_captured > 0) {
                updateCaptureStatistics({ packets_captured: data.packets_captured });
            }
        } else {
            statusDiv.innerHTML = `
                <div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>Ready to capture
                </div>
            `;
        }
    } catch (error) {
        console.error('Error updating capture status:', error);
    }
}

function updateCaptureStatistics(status) {
    const statsDiv = document.getElementById('capture-statistics');
    const statsContent = document.getElementById('capture-stats-content');

    if (!status || !status.statistics) {
        statsDiv.style.display = 'none';
        return;
    }

    statsDiv.style.display = 'block';
    
    let html = '<div class="row">';
    html += `<div class="col-md-6"><strong>Total Packets:</strong> ${status.packets_captured || 0}</div>`;
    
    if (status.statistics) {
        html += '<div class="col-md-12 mt-2"><strong>Protocols:</strong><ul class="list-unstyled">';
        for (const [protocol, count] of Object.entries(status.statistics)) {
            html += `<li>${protocol}: ${count}</li>`;
        }
        html += '</ul></div>';
    }
    
    html += '</div>';
    statsContent.innerHTML = html;
}

// ============ Analyze Packets ============

function setupAnalyzeButton() {
    const analyzeButton = document.getElementById('analyze-packets-button');
    if (analyzeButton) {
        analyzeButton.addEventListener('click', analyzePackets);
        
        // Setup download button
        const downloadButton = document.getElementById('download-packets-button');
        if (downloadButton) {
            downloadButton.addEventListener('click', downloadCapturedPackets);
        }
    }
}

async function analyzePackets() {
    const analyzeButton = document.getElementById('analyze-packets-button');
    const statusDiv = document.getElementById('analyze-status');

    analyzeButton.disabled = true;
    statusDiv.innerHTML = '<div class="alert alert-info">Analyzing packets...</div>';

    try {
        const response = await fetch('/analyze/packets', {
            method: 'POST'
        });

        const data = await response.json();

        if (response.ok) {
            AttackFlowUtils.toast.success('Packet analysis completed successfully!');
            statusDiv.innerHTML = `
                <div class="alert alert-success">
                    <i class="fas fa-check-circle me-2"></i>Analysis completed successfully!
                    <p class="mb-0 mt-2">Total events: ${data.total_events}</p>
                    <div class="mt-2">
                        <a href="/timeline" class="btn btn-sm btn-primary me-2">
                            <i class="fas fa-timeline me-1"></i>View Timeline
                        </a>
                        <a href="/" class="btn btn-sm btn-outline-primary">
                            <i class="fas fa-home me-1"></i>Go to Dashboard
                        </a>
                    </div>
                </div>
            `;
        } else {
            AttackFlowUtils.toast.error('Analysis failed: ' + (data.error || 'Unknown error'));
            statusDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
        }
    } catch (error) {
        AttackFlowUtils.toast.error('Error: ' + error.message);
        statusDiv.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
    } finally {
        analyzeButton.disabled = false;
    }
}

function downloadCapturedPackets() {
    window.location.href = '/capture/download';
}

// ============ WebSocket Packet Streaming ============

function initializeWebSocket() {
    // Check if Socket.IO is available
    if (typeof io === 'undefined') {
        console.warn('Socket.IO not available. Live packet streaming disabled.');
        return;
    }
    
    // WebSocket will be connected when capture starts
}

function connectPacketStream() {
    if (typeof io === 'undefined') {
        console.error('Socket.IO library not loaded. Live packet streaming disabled.');
        AttackFlowUtils.toast.warning('WebSocket library not available. Live packet display may not work.');
        return;
    }
    
    if (!socket) {
        console.log('Connecting to WebSocket server...');
        
        // Configure Socket.IO with reconnection and fallback to polling
        socket = io({
            transports: ['websocket', 'polling'],  // Try websocket first, fallback to polling
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            reconnectionAttempts: 5,
            timeout: 20000
        });
        
        socket.on('connect', () => {
            console.log('WebSocket connected, session ID:', socket.id, 'Transport:', socket.io.engine.transport.name);
            socket.emit('start_stream');
            AttackFlowUtils.toast.success('Live packet streaming connected');
        });
        
        socket.on('connect_error', (error) => {
            console.error('WebSocket connection error:', error);
            // Don't show error toast on every reconnect attempt
            if (socket.io.engine && socket.io.engine.transport && socket.io.engine.transport.name === 'polling') {
                console.log('Falling back to polling transport');
            }
        });
        
        socket.on('reconnect', (attemptNumber) => {
            console.log('WebSocket reconnected after', attemptNumber, 'attempts');
            socket.emit('start_stream');
        });
        
        socket.on('reconnect_attempt', (attemptNumber) => {
            console.log('WebSocket reconnection attempt', attemptNumber);
        });
        
        socket.on('reconnect_failed', () => {
            console.error('WebSocket reconnection failed');
            AttackFlowUtils.toast.error('Failed to reconnect to live packet stream');
        });
        
        socket.on('disconnect', (reason) => {
            console.log('WebSocket disconnected:', reason);
            if (reason === 'io server disconnect') {
                // Server disconnected, need to manually reconnect
                socket.connect();
            }
        });
        
        socket.on('packet_captured', (packetData) => {
            console.log('Packet received via WebSocket:', packetData);
            if (packetData && (packetData.packet_number || packetData.source_ip)) {
                handlePacketReceived(packetData);
            } else {
                console.warn('Received invalid packet data:', packetData);
            }
        });
        
        socket.on('stream_started', (data) => {
            console.log('Packet streaming started:', data);
        });
        
        socket.on('stream_stopped', (data) => {
            console.log('Packet streaming stopped:', data);
        });
        
        socket.on('connected', (data) => {
            console.log('Socket.IO connected:', data);
        });
    } else if (socket.connected) {
        console.log('WebSocket already connected, re-registering stream');
        socket.emit('start_stream');
    } else {
        console.log('WebSocket exists but not connected, reconnecting...');
        socket.connect();
    }
}

function disconnectPacketStream() {
    if (socket) {
        socket.emit('stop_stream');
        socket.disconnect();
        socket = null;
    }
}

async function loadCapturedPackets() {
    try {
        const response = await fetch('/capture/packets');
        
        if (!response.ok) {
            console.error(`Failed to load packets: ${response.status} ${response.statusText}`);
            const errorText = await response.text();
            console.error('Error response:', errorText);
            return;
        }
        
        const data = await response.json();
        
        if (data.packets && data.packets.length > 0) {
            console.log(`Loading ${data.packets.length} captured packets into display`);
            
            // Clear existing packets if needed
            packetList = [];
            filteredPackets = [];
            
            // Add packet numbers if missing
            data.packets.forEach((packet, index) => {
                if (!packet.packet_number) {
                    packet.packet_number = index + 1;
                }
                packetList.push(packet);
            });
            
            filteredPackets = [...packetList];
            
            // Update display
            updatePacketCount();
            applyPacketFilters();
            updatePacketTable();
            
            console.log(`Loaded ${packetList.length} packets into display`);
        } else {
            console.log('No captured packets to load');
        }
    } catch (error) {
        console.error('Error loading captured packets:', error);
        if (error instanceof SyntaxError) {
            console.error('JSON parsing error - server response may not be valid JSON');
            // Try to get the raw response
            try {
                const response = await fetch('/capture/packets');
                const text = await response.text();
                console.error('Raw response:', text.substring(0, 500));
            } catch (e) {
                console.error('Could not fetch raw response:', e);
            }
        }
    }
}

function handlePacketReceived(packetData) {
    try {
        console.log('Processing packet:', packetData);
        
        // Add packet to list
        packetList.push(packetData);
        filteredPackets = [...packetList];
        
        // Update packet count badge
        updatePacketCount();
        
        // Apply filters
        applyPacketFilters();
        
        // Update table
        updatePacketTable();
        
        // Auto-scroll if enabled
        if (autoScrollEnabled) {
            scrollToBottom();
        }
    } catch (error) {
        console.error('Error handling packet:', error, packetData);
    }
}

function updatePacketTable() {
    const tbody = document.getElementById('packet-table-body');
    if (!tbody) return;
    
    // Clear existing rows (except placeholder)
    if (filteredPackets.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center text-muted py-4">
                    <i class="fas fa-filter fa-2x mb-2"></i><br>
                    No packets match current filters.
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = '';
    
    filteredPackets.forEach((packet, index) => {
        const row = tbody.insertRow();
        row.className = selectedPacketIndex === index ? 'table-primary' : '';
        row.style.cursor = 'pointer';
        row.onclick = () => showPacketDetails(packet, index);
        
        const protocol = packet.protocol || 'unknown';
        const protocolColor = getProtocolColor(protocol);
        
        row.innerHTML = `
            <td>${packet.packet_number || index + 1}</td>
            <td>${formatPacketTime(packet.timestamp)}</td>
            <td><code>${formatAddress(packet.source_ip, packet.source_port)}</code></td>
            <td><code>${formatAddress(packet.destination_ip, packet.destination_port)}</code></td>
            <td><span class="badge" style="background-color: ${protocolColor}">${protocol.toUpperCase()}</span></td>
            <td>${packet.packet_size || packet.length || '-'}</td>
            <td>${formatPacketInfo(packet)}</td>
        `;
    });
}

function formatPacketTime(timestamp) {
    if (!timestamp) return '-';
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { 
        hour12: false, 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit',
        fractionalSecondDigits: 3
    });
}

function formatAddress(ip, port) {
    if (!ip) return '-';
    if (port) {
        return `${ip}:${port}`;
    }
    return ip;
}

function formatPacketInfo(packet) {
    const info = [];
    
    if (packet.method && packet.path) {
        info.push(`${packet.method} ${packet.path}`);
    } else if (packet.path) {
        info.push(packet.path);
    }
    
    if (packet.status_code) {
        info.push(`HTTP ${packet.status_code}`);
    }
    
    if (packet.raw_data) {
        if (packet.raw_data.dns_query) {
            info.push(`DNS Query: ${packet.raw_data.dns_query}`);
        }
        if (packet.raw_data.dns_answer) {
            info.push(`DNS Answer: ${packet.raw_data.dns_answer}`);
        }
    }
    
    if (packet.attack_indicator) {
        info.push(`[${packet.attack_indicator}]`);
    }
    
    return info.join(' ') || '-';
}

function getProtocolColor(protocol) {
    const colors = {
        'tcp': '#4ECDC4',
        'udp': '#45B7D1',
        'icmp': '#FF6B6B',
        'dns': '#FFA07A',
        'http': '#95A5A6',
        'unknown': '#95A5A6'
    };
    return colors[protocol.toLowerCase()] || colors['unknown'];
}

function updatePacketCount() {
    const badge = document.getElementById('packet-count-badge');
    if (badge) {
        badge.textContent = `${packetList.length} packet${packetList.length !== 1 ? 's' : ''}`;
    }
}

function scrollToBottom() {
    const container = document.getElementById('packet-table-container');
    if (container) {
        container.scrollTop = container.scrollHeight;
    }
}

function clearPackets() {
    packetList = [];
    filteredPackets = [];
    selectedPacketIndex = -1;
    updatePacketCount();
    updatePacketTable();
    AttackFlowUtils.toast.info('Packet list cleared');
}

function setupPacketFilters() {
    const protocolFilter = document.getElementById('packet-filter-protocol');
    const sourceFilter = document.getElementById('packet-filter-source');
    const destFilter = document.getElementById('packet-filter-dest');
    const infoFilter = document.getElementById('packet-filter-info');
    
    const applyFilters = () => {
        applyPacketFilters();
    };
    
    if (protocolFilter) {
        protocolFilter.addEventListener('input', debounce(applyFilters, 300));
    }
    if (sourceFilter) {
        sourceFilter.addEventListener('input', debounce(applyFilters, 300));
    }
    if (destFilter) {
        destFilter.addEventListener('input', debounce(applyFilters, 300));
    }
    if (infoFilter) {
        infoFilter.addEventListener('input', debounce(applyFilters, 300));
    }
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function applyPacketFilters() {
    const protocolFilter = (document.getElementById('packet-filter-protocol')?.value || '').toLowerCase();
    const sourceFilter = (document.getElementById('packet-filter-source')?.value || '').toLowerCase();
    const destFilter = (document.getElementById('packet-filter-dest')?.value || '').toLowerCase();
    const infoFilter = (document.getElementById('packet-filter-info')?.value || '').toLowerCase();
    
    filteredPackets = packetList.filter(packet => {
        if (protocolFilter && !(packet.protocol || '').toLowerCase().includes(protocolFilter)) {
            return false;
        }
        if (sourceFilter && !formatAddress(packet.source_ip, packet.source_port).toLowerCase().includes(sourceFilter)) {
            return false;
        }
        if (destFilter && !formatAddress(packet.destination_ip, packet.destination_port).toLowerCase().includes(destFilter)) {
            return false;
        }
        if (infoFilter && !formatPacketInfo(packet).toLowerCase().includes(infoFilter)) {
            return false;
        }
        return true;
    });
    
    updatePacketTable();
}

function showPacketDetails(packet, index) {
    selectedPacketIndex = index;
    updatePacketTable(); // Update to highlight selected row
    
    const modalBody = document.getElementById('packet-details-body');
    if (!modalBody) return;
    
    let html = '<div class="row">';
    
    // Basic Information
    html += '<div class="col-12 mb-3"><h6><i class="fas fa-info-circle me-2"></i>Basic Information</h6>';
    html += '<table class="table table-sm table-bordered">';
    html += `<tr><th style="width: 200px;">Packet Number</th><td>${packet.packet_number || '-'}</td></tr>`;
    html += `<tr><th>Timestamp</th><td>${packet.timestamp ? new Date(packet.timestamp).toLocaleString() : '-'}</td></tr>`;
    html += `<tr><th>Packet Size</th><td>${packet.packet_size || packet.length || '-'} bytes</td></tr>`;
    html += `<tr><th>Protocol</th><td><span class="badge" style="background-color: ${getProtocolColor(packet.protocol)}">${(packet.protocol || 'unknown').toUpperCase()}</span></td></tr>`;
    html += '</table></div>';
    
    // Network Layer (IP)
    if (packet.source_ip || packet.destination_ip) {
        html += '<div class="col-12 mb-3"><h6><i class="fas fa-network-wired me-2"></i>Network Layer (IP)</h6>';
        html += '<table class="table table-sm table-bordered">';
        html += `<tr><th style="width: 200px;">Source IP</th><td><code>${packet.source_ip || '-'}</code></td></tr>`;
        html += `<tr><th>Destination IP</th><td><code>${packet.destination_ip || '-'}</code></td></tr>`;
        html += '</table></div>';
    }
    
    // Transport Layer (TCP/UDP)
    if (packet.source_port || packet.destination_port) {
        html += '<div class="col-12 mb-3"><h6><i class="fas fa-exchange-alt me-2"></i>Transport Layer</h6>';
        html += '<table class="table table-sm table-bordered">';
        html += `<tr><th style="width: 200px;">Source Port</th><td>${packet.source_port || '-'}</td></tr>`;
        html += `<tr><th>Destination Port</th><td>${packet.destination_port || '-'}</td></tr>`;
        if (packet.raw_data && packet.raw_data.tcp_flags) {
            html += `<tr><th>TCP Flags</th><td><code>0x${packet.raw_data.tcp_flags.toString(16)}</code></td></tr>`;
        }
        html += '</table></div>';
    }
    
    // Application Layer (HTTP)
    if (packet.method || packet.path || packet.status_code) {
        html += '<div class="col-12 mb-3"><h6><i class="fas fa-globe me-2"></i>Application Layer (HTTP)</h6>';
        html += '<table class="table table-sm table-bordered">';
        if (packet.method) html += `<tr><th style="width: 200px;">Method</th><td><code>${packet.method}</code></td></tr>`;
        if (packet.path) html += `<tr><th>Path</th><td><code>${packet.path}</code></td></tr>`;
        if (packet.status_code) html += `<tr><th>Status Code</th><td>${packet.status_code}</td></tr>`;
        if (packet.user_agent) html += `<tr><th>User Agent</th><td><code>${packet.user_agent}</code></td></tr>`;
        html += '</table></div>';
    }
    
    // DNS Layer
    if (packet.raw_data && (packet.raw_data.dns_query || packet.raw_data.dns_answer)) {
        html += '<div class="col-12 mb-3"><h6><i class="fas fa-server me-2"></i>DNS Layer</h6>';
        html += '<table class="table table-sm table-bordered">';
        if (packet.raw_data.dns_query) html += `<tr><th style="width: 200px;">Query</th><td><code>${packet.raw_data.dns_query}</code></td></tr>`;
        if (packet.raw_data.dns_answer) html += `<tr><th>Answer</th><td><code>${packet.raw_data.dns_answer}</code></td></tr>`;
        html += '</table></div>';
    }
    
    // ICMP Layer
    if (packet.raw_data && (packet.raw_data.icmp_type !== undefined)) {
        html += '<div class="col-12 mb-3"><h6><i class="fas fa-broadcast-tower me-2"></i>ICMP Layer</h6>';
        html += '<table class="table table-sm table-bordered">';
        html += `<tr><th style="width: 200px;">Type</th><td>${packet.raw_data.icmp_type}</td></tr>`;
        html += `<tr><th>Code</th><td>${packet.raw_data.icmp_code || '-'}</td></tr>`;
        html += '</table></div>';
    }
    
    // Attack Indicators
    if (packet.attack_indicator) {
        html += '<div class="col-12 mb-3"><h6><i class="fas fa-exclamation-triangle me-2 text-warning"></i>Attack Indicators</h6>';
        html += '<table class="table table-sm table-bordered">';
        html += `<tr><th style="width: 200px;">Indicator</th><td><span class="badge bg-warning">${packet.attack_indicator}</span></td></tr>`;
        if (packet.attack_confidence) {
            html += `<tr><th>Confidence</th><td>${(packet.attack_confidence * 100).toFixed(1)}%</td></tr>`;
        }
        html += '</table></div>';
    }
    
    // Raw Data
    if (packet.raw_data && Object.keys(packet.raw_data).length > 0) {
        html += '<div class="col-12 mb-3"><h6><i class="fas fa-code me-2"></i>Raw Data</h6>';
        html += '<pre class="bg-light p-3 rounded"><code>' + JSON.stringify(packet.raw_data, null, 2) + '</code></pre></div>';
    }
    
    html += '</div>';
    modalBody.innerHTML = html;
    
    const modal = new bootstrap.Modal(document.getElementById('packetDetailsModal'));
    modal.show();
}

