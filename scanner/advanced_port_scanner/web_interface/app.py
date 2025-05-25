"""
Flask Web Interface for Advanced Port Scanner
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import sys
import json
from datetime import datetime
import sqlite3
import threading
import time

# Add scanner module to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.core_scanner import AdvancedPortScanner

app = Flask(__name__)
app.secret_key = 'advanced_port_scanner_2024'

# Global scanner instance
scanner = AdvancedPortScanner()

# Store active scans
active_scans = {}

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Scan interface"""
    if request.method == 'GET':
        return render_template('scan.html')
    
    # Handle scan request
    data = request.get_json()
    targets = data.get('targets', '')
    ports = data.get('ports', '1-1000')
    scan_type = data.get('scan_type', 'tcp_connect')
    
    # Generate scan ID
    scan_id = f"scan_{int(time.time())}"
    
    # Start scan in background thread
    def run_scan():
        try:
            results = scanner.comprehensive_scan(targets, ports, scan_type)
            active_scans[scan_id] = {
                'status': 'completed',
                'results': results,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            active_scans[scan_id] = {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    active_scans[scan_id] = {'status': 'running', 'timestamp': datetime.now().isoformat()}
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id, 'status': 'started'})

@app.route('/scan/<scan_id>')
def scan_status(scan_id):
    """Get scan status"""
    if scan_id in active_scans:
        return jsonify(active_scans[scan_id])
    else:
        return jsonify({'status': 'not_found'}), 404

@app.route('/history')
def history():
    """Scan history"""
    results = scanner.get_scan_history()
    return render_template('history.html', results=results)

@app.route('/api/history')
def api_history():
    """API endpoint for scan history"""
    results = scanner.get_scan_history()
    return jsonify(results)

@app.route('/settings')
def settings():
    """Settings page"""
    return render_template('settings.html')

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5558, debug=False)
