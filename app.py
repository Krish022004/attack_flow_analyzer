"""
Attack Flow Analyzer - Flask Web Application
Main application entry point
"""

import os
import json
from pathlib import Path
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

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = Path(tempfile.gettempdir()) / 'attack_flow_uploads'
app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)

# Global analysis state
analysis_state = {
    'events': [],
    'correlated': {},
    'classified': [],
    'timeline': None,
    'iocs': {},
    'statistics': {},
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


@app.route('/api/timeline')
def api_timeline():
    """API endpoint for timeline data"""
    if not analysis_state.get('timeline'):
        return jsonify({'error': 'No timeline data available'}), 404
    
    timeline_data = analysis_state['timeline'].get_timeline_data()
    return jsonify(timeline_data)


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


if __name__ == '__main__':
    # Generate sample logs on first run if they don't exist
    sample_logs_dir = Path(__file__).parent / 'data' / 'sample_logs'
    if not sample_logs_dir.exists() or not list(sample_logs_dir.glob('*.log')):
        print("Generating sample logs...")
        generator = LogGenerator()
        generator.generate_all(sample_logs_dir)
    
    app.run(debug=True, host='0.0.0.0', port=5001)
