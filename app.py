"""
Attack Flow Analyzer - Flask Web Application
Main application entry point
"""

import os
import json
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from werkzeug.utils import secure_filename
import tempfile
import shutil

from modules.log_ingestion import LogIngestionEngine
from modules.correlation import CorrelationEngine
from modules.phase_classifier import PhaseClassifier
from modules.timeline import TimelineBuilder
from modules.ioc_extractor import IOCExtractor
from modules.ioc_exporter import IOCExporter
from utils.log_generator import LogGenerator

try:
    from modules.packet_capture import LiveCapture
    from modules.packet_analyzer import PacketAnalyzer
    PCAP_AVAILABLE = True
except ImportError:
    PCAP_AVAILABLE = False

try:
    from flask_socketio import SocketIO, emit
    from flask import request as flask_request
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False
    flask_request = None

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = Path(tempfile.gettempdir()) / 'attack_flow_uploads'
app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)
app.config['SECRET_KEY'] = 'attack-flow-analyzer-secret-key'  # Required for SocketIO

# Initialize SocketIO if available
if SOCKETIO_AVAILABLE:
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=True, engineio_logger=True)
else:
    socketio = None

# Global analysis state
analysis_state = {
    'events': [],
    'correlated': {},
    'classified': [],
    'timeline': None,
    'iocs': {},
    'statistics': {},
}

# Global capture state
capture_state = {
    'live_capture': None,
    'captured_events': [],
    'streaming_clients': set(),
}


@app.route('/')
def index():
    """Main dashboard"""
    stats = analysis_state.get('statistics', {})
    return render_template('index.html', statistics=stats)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """File upload interface"""
    if request.method == 'POST':
        try:
            # Debug: Log request info
            print(f"Upload request - Content-Type: {request.content_type}")
            print(f"Upload request - Files keys: {list(request.files.keys())}")
            
            # Check if files are in the request
            if 'files[]' not in request.files:
                # Try alternative key names
                if 'files' in request.files:
                    files = request.files.getlist('files')
                    print(f"Using 'files' key, found {len(files)} files")
                else:
                    print("No files found in request")
                    return jsonify({'error': 'No files provided. Please select files to upload.'}), 400
            else:
                files = request.files.getlist('files[]')
                print(f"Using 'files[]' key, found {len(files)} files")
            
            uploaded_files = []
            
            for file in files:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    print(f"Processing file: {file.filename} -> {filename}")
                    if not filename:
                        print(f"  Skipped: secure_filename returned empty")
                        continue
                    
                    # Ensure unique filename to avoid overwrites
                    filepath = app.config['UPLOAD_FOLDER'] / filename
                    counter = 1
                    while filepath.exists():
                        name_parts = filename.rsplit('.', 1)
                        if len(name_parts) == 2:
                            new_filename = f"{name_parts[0]}_{counter}.{name_parts[1]}"
                        else:
                            new_filename = f"{filename}_{counter}"
                        filepath = app.config['UPLOAD_FOLDER'] / new_filename
                        counter += 1
                    
                    try:
                        file.save(str(filepath))
                        print(f"  Saved to: {filepath}")
                        uploaded_files.append(str(filepath))
                    except Exception as e:
                        print(f"  Error saving file: {str(e)}")
                        return jsonify({'error': f'Failed to save file {filename}: {str(e)}'}), 500
                else:
                    print(f"Skipping invalid file object: {file}")
            
            if uploaded_files:
                return jsonify({
                    'message': f'Uploaded {len(uploaded_files)} file(s)',
                    'files': uploaded_files
                })
            else:
                return jsonify({'error': 'No valid files uploaded. Please check file selection.'}), 400
                
        except Exception as e:
            return jsonify({'error': f'Upload error: {str(e)}'}), 500
    
    return render_template('upload.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """Perform analysis on uploaded logs"""
    try:
        data = request.get_json()
        log_files = [Path(f) for f in data.get('files', [])]
        
        if not log_files:
            return jsonify({'error': 'No log files provided'}), 400
        
        # Step 1: Ingest logs
        ingestion_engine = LogIngestionEngine()
        events = ingestion_engine.ingest(log_files)
        
        if not events:
            return jsonify({'error': 'No events extracted from logs'}), 400
        
        # Step 2: Correlate events
        correlation_engine = CorrelationEngine()
        correlated = correlation_engine.correlate_all(events)
        
        # Step 3: Classify phases
        phase_classifier = PhaseClassifier()
        classified = phase_classifier.classify_all(events)
        
        # Step 4: Build timeline
        timeline_builder = TimelineBuilder()
        timeline = timeline_builder.build_timeline(classified)
        
        # Step 5: Extract IOCs
        ioc_extractor = IOCExtractor()
        iocs = ioc_extractor.extract_all(classified)
        
        # Update global state
        analysis_state['events'] = events
        analysis_state['correlated'] = {
            'ip': {k: v.to_dict() for k, v in correlated['ip'].items()},
            'user': {k: v.to_dict() for k, v in correlated['user'].items()},
            'session': {k: v.to_dict() for k, v in correlated['session'].items()},
        }
        analysis_state['classified'] = classified
        analysis_state['timeline'] = timeline_builder
        analysis_state['iocs'] = iocs
        
        # Collect statistics
        analysis_state['statistics'] = {
            'ingestion': ingestion_engine.get_statistics(),
            'correlation': correlation_engine.get_statistics(),
            'phases': phase_classifier.get_statistics(),
            'timeline': timeline_builder.get_statistics(),
            'iocs': ioc_extractor.get_statistics(),
        }
        
        return jsonify({
            'success': True,
            'message': 'Analysis completed successfully',
            'statistics': analysis_state['statistics'],
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/timeline')
def timeline():
    """Timeline visualization page"""
    return render_template('timeline.html')


@app.route('/log-analysis')
def log_analysis():
    """Log analysis page with client-side attack detection"""
    return render_template('log_analysis.html')


@app.route('/api/timeline')
def api_timeline():
    """API endpoint for timeline data"""
    timeline_builder = analysis_state.get('timeline')
    
    if not timeline_builder:
        return jsonify({'error': 'No timeline data available'}), 404
    
    # Check if timeline has events
    if not hasattr(timeline_builder, 'timeline_events') or not timeline_builder.timeline_events:
        return jsonify({'error': 'No timeline data available'}), 404
    
    try:
        timeline_data = timeline_builder.get_timeline_data()
        return jsonify(timeline_data)
    except Exception as e:
        import traceback
        return jsonify({'error': f'Error retrieving timeline data: {str(e)}'}), 500


@app.route('/phases')
def phases():
    """Attack phase breakdown page"""
    phase_stats = analysis_state.get('statistics', {}).get('phases', {})
    timeline_stats = analysis_state.get('statistics', {}).get('timeline', {})
    return render_template('phases.html', phase_stats=phase_stats, timeline_stats=timeline_stats)


@app.route('/iocs')
def iocs():
    """IOC display page"""
    iocs_data = analysis_state.get('iocs', {})
    ioc_stats = analysis_state.get('statistics', {}).get('iocs', {})
    return render_template('iocs.html', iocs=iocs_data, statistics=ioc_stats)


@app.route('/api/iocs')
def api_iocs():
    """API endpoint for IOC data"""
    iocs = analysis_state.get('iocs', {})
    return jsonify(list(iocs.values()))


@app.route('/export/iocs/<format>')
def export_iocs(format):
    """Export IOCs in specified format"""
    iocs = analysis_state.get('iocs', {})
    
    if not iocs:
        return jsonify({'error': 'No IOCs to export'}), 404
    
    exporter = IOCExporter(iocs)
    output_dir = Path(tempfile.gettempdir()) / 'attack_flow_exports'
    output_dir.mkdir(exist_ok=True)
    
    if format == 'json':
        output_path = output_dir / 'iocs.json'
        if exporter.export_json(output_path):
            return send_file(output_path, as_attachment=True, download_name='iocs.json')
    elif format == 'csv':
        output_path = output_dir / 'iocs.csv'
        if exporter.export_csv(output_path):
            return send_file(output_path, as_attachment=True, download_name='iocs.csv')
    else:
        return jsonify({'error': 'Invalid format. Use json or csv'}), 400
    
    return jsonify({'error': 'Export failed'}), 500


@app.route('/generate-samples', methods=['POST'])
def generate_samples():
    """Generate sample log files"""
    try:
        output_dir = Path(__file__).parent / 'data' / 'sample_logs'
        generator = LogGenerator()
        generator.generate_all(output_dir)
        
        return jsonify({
            'success': True,
            'message': 'Sample logs generated',
            'location': str(output_dir),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/statistics')
def api_statistics():
    """API endpoint for overall statistics"""
    return jsonify(analysis_state.get('statistics', {}))


@app.route('/api/correlation')
def api_correlation():
    """API endpoint for correlation data"""
    return jsonify(analysis_state.get('correlated', {}))


@app.route('/packet-capture')
def packet_capture():
    """Packet capture interface page"""
    return render_template('packet_capture.html')


@app.route('/capture/start', methods=['POST'])
def capture_start():
    """Start live packet capture"""
    if not PCAP_AVAILABLE:
        return jsonify({'error': 'Packet capture not available. Please install scapy: pip install scapy'}), 503
    
    try:
        data = request.get_json() or {}
        interface = data.get('interface', None)
        duration = data.get('duration', None)
        packet_count = data.get('packet_count', 1000)
        
        # Stop existing capture if any
        if capture_state.get('live_capture'):
            try:
                capture_state['live_capture'].stop_capture()
            except:
                pass
        
        # Start new capture
        if not PCAP_AVAILABLE:
            return jsonify({'error': 'Packet capture not available. Install scapy library.'}), 503
        
        # Define packet callback for WebSocket streaming
        def packet_callback(packet_event):
            """Callback to emit packet to WebSocket clients"""
            try:
                if socketio:
                    # Ensure streaming_clients exists
                    if 'streaming_clients' not in capture_state:
                        capture_state['streaming_clients'] = set()
                    
                    # Convert packet_event to JSON-serializable format
                    serializable_event = {}
                    for key, value in packet_event.items():
                        if isinstance(value, datetime):
                            serializable_event[key] = value.isoformat()
                        elif isinstance(value, bytes):
                            # Skip payload bytes - too large
                            if key == 'payload':
                                continue
                            else:
                                serializable_event[key] = f"<bytes:{len(value)}>"
                        elif isinstance(value, (dict, list)):
                            try:
                                json.dumps(value)  # Test if serializable
                                serializable_event[key] = value
                            except (TypeError, ValueError):
                                serializable_event[key] = str(value)[:200]
                        elif isinstance(value, (str, int, float, bool, type(None))):
                            serializable_event[key] = value
                        else:
                            serializable_event[key] = str(value)[:200]
                    
                    # Emit to all connected clients (omitting 'to' parameter broadcasts to all)
                    # Use app context to ensure proper Flask context for background thread
                    with app.app_context():
                        socketio.emit('packet_captured', serializable_event, namespace='/')
                        # Print packet number to terminal for monitoring
                        packet_num = serializable_event.get('packet_number', '?')
                        client_count = len(capture_state.get('streaming_clients', set()))
                        protocol = serializable_event.get('protocol', 'unknown')
                        src_ip = serializable_event.get('source_ip', '?')
                        dst_ip = serializable_event.get('destination_ip', '?')
                        
                        # Print every packet to terminal (user requested this)
                        if isinstance(packet_num, int):
                            print(f"[Packet #{packet_num}] {protocol.upper()} {src_ip} -> {dst_ip} (sent to {client_count} client(s))")
                        else:
                            print(f"[Packet {packet_num}] {protocol.upper()} {src_ip} -> {dst_ip} (sent to {client_count} client(s))")
            except Exception as e:
                # Log error but don't fail capture
                import traceback
                print(f"Error emitting packet via WebSocket: {e}")
                traceback.print_exc()
            
        # Log capture parameters
        interface_str = interface or "default interface (auto-detect)"
        duration_str = f"{duration} seconds" if duration else "unlimited"
        print(f"[Capture Start] Interface: {interface_str}, Duration: {duration_str}, Max packets: {packet_count}")
        
        live_capture = LiveCapture(interface=interface, packet_count=packet_count)
        if live_capture.start_capture(duration=duration, packet_callback=packet_callback):
            capture_state['live_capture'] = live_capture
            print(f"[Capture Start] Live capture started successfully. Waiting for packets...")
            return jsonify({
                'success': True,
                'message': 'Live capture started',
                'status': live_capture.get_status()
            })
        else:
            errors = live_capture.errors if hasattr(live_capture, 'errors') else []
            error_msg = errors[0] if errors else 'Failed to start capture'
            print(f"[Capture Start] ERROR: {error_msg}")
            return jsonify({'error': error_msg}), 500
            
    except NameError as e:
        return jsonify({'error': 'Packet capture module not available. Install scapy: pip install scapy'}), 503
    except Exception as e:
        import traceback
        return jsonify({'error': f'Error starting capture: {str(e)}'}), 500


@app.route('/capture/stop', methods=['POST'])
def capture_stop():
    """Stop live packet capture"""
    if not PCAP_AVAILABLE:
        return jsonify({'error': 'Packet capture not available'}), 503
    
    try:
        if not capture_state['live_capture']:
            return jsonify({'error': 'No active capture'}), 400
        
        # Stop capture and process packets
        events = capture_state['live_capture'].stop_capture()
        
        # Get status after stopping (includes processed packet count)
        status = capture_state['live_capture'].get_status()
        
        # Store events in global state
        capture_state['captured_events'] = events
        
        # Emit all captured packets via WebSocket to connected clients
        if socketio and capture_state.get('streaming_clients'):
            # Convert events to JSON-serializable format for WebSocket
            # Create a copy so we don't modify the original events (which need datetime objects for analysis)
            for event in events:
                try:
                    # Create a copy for WebSocket emission
                    ws_event = event.copy()
                    # Ensure timestamp is ISO format string for JSON serialization
                    if isinstance(ws_event.get('timestamp'), datetime):
                        ws_event['timestamp'] = ws_event['timestamp'].isoformat()
                    # Convert other non-serializable fields
                    serializable_event = {}
                    for key, value in ws_event.items():
                        if isinstance(value, datetime):
                            serializable_event[key] = value.isoformat()
                        elif isinstance(value, bytes):
                            if key == 'payload':
                                continue  # Skip payload
                            else:
                                serializable_event[key] = f"<bytes:{len(value)}>"
                        elif isinstance(value, (dict, list)):
                            try:
                                json.dumps(value)
                                serializable_event[key] = value
                            except (TypeError, ValueError):
                                serializable_event[key] = str(value)[:200]
                        elif isinstance(value, (str, int, float, bool, type(None))):
                            serializable_event[key] = value
                        else:
                            serializable_event[key] = str(value)[:200]
                    socketio.emit('packet_captured', serializable_event, namespace='/')
                except Exception as e:
                    print(f"Error emitting captured packet: {e}")
        
        return jsonify({
            'success': True,
            'message': f'Capture stopped. Processed {len(events)} packets.',
            'packets_captured': len(events),
            'queued_packets': status.get('queued_packets', 0),
            'status': status
        })
    except Exception as e:
        import traceback
        error_msg = f'Error stopping capture: {str(e)}\n{traceback.format_exc()}'
        return jsonify({'error': error_msg}), 500


@app.route('/capture/status', methods=['GET'])
def capture_status():
    """Get current capture status"""
    if not PCAP_AVAILABLE:
        return jsonify({'error': 'Packet capture not available'}), 503
    
    # Check if there's an active capture
    if capture_state.get('live_capture'):
        status = capture_state['live_capture'].get_status()
        return jsonify(status)
    
    # No active capture, but return captured events info if available
    captured_events = capture_state.get('captured_events', [])
    return jsonify({
        'is_capturing': False,
        'packets_captured': len(captured_events),
        'queued_packets': 0,
        'statistics': {},
        'has_captured_packets': len(captured_events) > 0,
        'packets_analyzed': len(analysis_state.get('events', [])) > 0 if captured_events else False
    })


@app.route('/capture/packets', methods=['GET'])
def get_captured_packets():
    """Get all captured packets"""
    if not PCAP_AVAILABLE:
        return jsonify({'error': 'Packet capture not available'}), 503
    
    try:
        captured_events = capture_state.get('captured_events', [])
        
        # Convert events to JSON-serializable format
        serializable_events = []
        for event in captured_events:
            try:
                event_copy = {}
                for key, value in event.items():
                    # Skip non-serializable fields or convert them
                    if isinstance(value, datetime):
                        event_copy[key] = value.isoformat()
                    elif isinstance(value, bytes):
                        # Skip payload bytes - too large and not needed for display
                        if key == 'payload':
                            continue  # Skip payload field entirely
                        else:
                            event_copy[key] = f"<bytes:{len(value)}>"  # Just indicate it's bytes
                    elif isinstance(value, (dict, list)):
                        # Recursively handle nested structures
                        try:
                            json.dumps(value)  # Test if serializable
                            event_copy[key] = value
                        except (TypeError, ValueError):
                            # Skip non-serializable nested objects
                            event_copy[key] = str(value)[:200]  # Truncate long strings
                    elif isinstance(value, (str, int, float, bool, type(None))):
                        event_copy[key] = value
                    else:
                        # Convert other types to string
                        event_copy[key] = str(value)[:200]
                
                serializable_events.append(event_copy)
            except Exception as e:
                import traceback
                print(f"Error serializing event: {e}")
                traceback.print_exc()
                continue
        
        return jsonify({
            'packets': serializable_events,
            'total': len(serializable_events)
        })
    except Exception as e:
        import traceback
        error_msg = f'Error getting captured packets: {str(e)}\n{traceback.format_exc()}'
        print(error_msg)
        return jsonify({'error': f'Error getting captured packets: {str(e)}'}), 500


@app.route('/capture/download', methods=['GET'])
def download_captured_packets():
    """Download captured packets as a log file"""
    if not PCAP_AVAILABLE:
        return jsonify({'error': 'Packet capture not available'}), 503
    
    try:
        captured_events = capture_state.get('captured_events', [])
        
        if not captured_events:
            return jsonify({'error': 'No packets captured. Please capture packets first.'}), 400
        
        # Convert packets to log file format
        log_lines = []
        for event in captured_events:
            try:
                timestamp = event.get('timestamp', datetime.now())
                if isinstance(timestamp, str):
                    timestamp_str = timestamp
                elif isinstance(timestamp, datetime):
                    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    timestamp_str = str(timestamp)
                
                source_ip = event.get('source_ip', 'unknown')
                dest_ip = event.get('destination_ip', 'unknown')
                protocol = event.get('protocol', 'UNKNOWN')
                source_port = event.get('source_port', '')
                dest_port = event.get('destination_port', '')
                length = event.get('length', 0)
                info = event.get('info', '')
                
                # Format: [timestamp] PROTOCOL source_ip:port -> dest_ip:port LEN:length INFO:details
                log_line = f"[{timestamp_str}] {protocol.upper()} {source_ip}:{source_port} -> {dest_ip}:{dest_port} LEN:{length} INFO:{info}"
                log_lines.append(log_line)
            except Exception as e:
                print(f"Error formatting packet for log: {e}")
                continue
        
        # Create log file content
        log_content = '\n'.join(log_lines)
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False)
        temp_file.write(log_content)
        temp_file.close()
        
        # Generate filename with timestamp
        filename = f"captured_packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=filename,
            mimetype='text/plain'
        )
    except Exception as e:
        import traceback
        error_msg = f'Error downloading captured packets: {str(e)}\n{traceback.format_exc()}'
        print(error_msg)
        return jsonify({'error': f'Error downloading captured packets: {str(e)}'}), 500


@app.route('/analyze/packets', methods=['POST'])
def analyze_packets():
    """Analyze captured packets"""
    if not PCAP_AVAILABLE:
        return jsonify({'error': 'Packet capture not available'}), 503
    
    try:
        # Get captured events - check both live_capture and captured_events
        events = []
        
        # First, try to get from live_capture object (if capture was stopped)
        if capture_state.get('live_capture'):
            events = capture_state['live_capture'].get_captured_events()
        
        # Fallback to captured_events in state
        if not events:
            events = capture_state.get('captured_events', [])
        
        if not events:
            return jsonify({'error': 'No packets captured. Please capture packets first.'}), 400
        
        # Analyze packets for attack patterns
        packet_analyzer = PacketAnalyzer()
        analyzed_events = packet_analyzer.analyze_all(events)
        packet_stats = packet_analyzer.get_statistics(analyzed_events)
        
        # Merge with existing events if any
        existing_events = analysis_state.get('events', [])
        all_events = existing_events + analyzed_events  # Create new list to avoid mutating
        
        # Run through normal analysis pipeline
        correlation_engine = CorrelationEngine()
        correlated = correlation_engine.correlate_all(all_events)
        
        phase_classifier = PhaseClassifier()
        classified = phase_classifier.classify_all(all_events)
        
        timeline_builder = TimelineBuilder()
        timeline_builder.build_timeline(classified)
        
        ioc_extractor = IOCExtractor()
        iocs = ioc_extractor.extract_all(classified)
        
        # Update correlation state (convert to dict format)
        analysis_state['correlated'] = {
            'ip': {k: v.to_dict() if hasattr(v, 'to_dict') else v for k, v in correlated.get('ip', {}).items()},
            'user': {k: v.to_dict() if hasattr(v, 'to_dict') else v for k, v in correlated.get('user', {}).items()},
            'session': {k: v.to_dict() if hasattr(v, 'to_dict') else v for k, v in correlated.get('session', {}).items()},
        }
        
        # Update global state
        analysis_state['events'] = all_events
        analysis_state['classified'] = classified
        analysis_state['timeline'] = timeline_builder
        analysis_state['iocs'] = iocs
        
        # IMPORTANT: Keep captured_events in capture_state for persistence
        # This allows the packet capture page to show that packets were analyzed
        capture_state['captured_events'] = events  # Keep original events
        
        # Merge statistics (preserve existing, add new)
        existing_stats = analysis_state.get('statistics', {})
        analysis_state['statistics'] = {
            **existing_stats,  # Preserve existing statistics
            'correlation': correlation_engine.get_statistics(),
            'phases': phase_classifier.get_statistics(),
            'timeline': timeline_builder.get_statistics(),
            'iocs': ioc_extractor.get_statistics(),
            'packet_analysis': packet_stats,
        }
        
        return jsonify({
            'success': True,
            'message': 'Packet analysis completed',
            'packet_statistics': packet_stats,
            'total_events': len(all_events),
            'packets_analyzed': len(events),
            'statistics': analysis_state['statistics'],  # Include full statistics for frontend
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# WebSocket event handlers for live packet streaming
if socketio:
    @socketio.on('connect', namespace='/')
    def handle_connect(auth):
        """Handle WebSocket client connection"""
        from flask import request as flask_request
        if 'streaming_clients' not in capture_state:
            capture_state['streaming_clients'] = set()
        capture_state['streaming_clients'].add(flask_request.sid)
        print(f"Client connected: {flask_request.sid}, total clients: {len(capture_state['streaming_clients'])}")
        emit('connected', {'status': 'connected'})
    
    @socketio.on('disconnect', namespace='/')
    def handle_disconnect(reason):
        """Handle WebSocket client disconnection"""
        from flask import request as flask_request
        if 'streaming_clients' in capture_state:
            capture_state['streaming_clients'].discard(flask_request.sid)
            print(f"Client disconnected: {flask_request.sid}, total clients: {len(capture_state['streaming_clients'])}")
    
    @socketio.on('start_stream', namespace='/')
    def handle_start_stream():
        """Handle start streaming request"""
        from flask import request as flask_request
        if 'streaming_clients' not in capture_state:
            capture_state['streaming_clients'] = set()
        capture_state['streaming_clients'].add(flask_request.sid)
        emit('stream_started', {'status': 'Streaming started'})
    
    @socketio.on('stop_stream', namespace='/')
    def handle_stop_stream():
        """Handle stop streaming request"""
        from flask import request as flask_request
        if 'streaming_clients' in capture_state:
            capture_state['streaming_clients'].discard(flask_request.sid)
        emit('stream_stopped', {'status': 'Streaming stopped'})


if __name__ == '__main__':
    # Generate sample logs on first run if they don't exist
    sample_logs_dir = Path(__file__).parent / 'data' / 'sample_logs'
    if not sample_logs_dir.exists() or not list(sample_logs_dir.glob('*.log')):
        print("Generating sample logs...")
        generator = LogGenerator()
        generator.generate_all(sample_logs_dir)
    
    if socketio:
        socketio.run(app, debug=True, host='0.0.0.0', port=5001)
    else:
        app.run(debug=True, host='0.0.0.0', port=5001)
