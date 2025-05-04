#!/usr/bin/env python3

import os
import logging
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from pykms_Database import create_backend

app = Flask(__name__)
loggersrv = logging.getLogger('logsrv')

# Global database backend instance
db = None

@app.template_filter('format_datetime')
def format_datetime(value):
    """Format datetime objects for display"""
    if value is None:
        return ''
    try:
        if isinstance(value, (int, float)):
            value = datetime.fromtimestamp(value)
        return value.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, AttributeError):
        return str(value)

@app.route('/')
def index():
    """Dashboard showing activation statistics"""
    clients = db.get_all_clients()
    stats = {
        'total_clients': len(clients),
        'active_clients': sum(1 for c in clients if c.licenseStatus == 'Licensed'),
        'windows_clients': sum(1 for c in clients if 'Windows' in c.applicationId),
        'office_clients': sum(1 for c in clients if 'Office' in c.applicationId)
    }
    return render_template('dashboard.html', stats=stats, clients=clients)

@app.route('/clients')
def client_list():
    """Client management interface"""
    clients = db.get_all_clients()
    return render_template('clients.html', clients=clients)

@app.route('/config', methods=['GET', 'POST'])
def config():
    """Configuration settings interface"""
    if request.method == 'POST':
        # Update configuration
        new_config = {
            'db_type': request.form.get('db_type', 'sqlite'),
            'db_host': request.form.get('db_host', ''),
            'db_user': request.form.get('db_user', ''),
            'db_password': request.form.get('db_password', ''),
            'db_name': request.form.get('db_name', ''),
            'sqlite_path': request.form.get('sqlite_path', 'pykms_database.db'),
            'web_port': request.form.get('web_port', 8080),
        }
        # Save configuration
        save_config(new_config)
        return jsonify({'status': 'success'})
    
    return render_template('config.html', config=load_config())

@app.route('/logs')
def logs():
    """Real-time logs viewer"""
    return render_template('logs.html')

@app.route('/api/logs')
def get_logs():
    """API endpoint for fetching logs"""
    try:
        logfile = app.config['LOGFILE']
        
        # Handle different logfile configurations
        if isinstance(logfile, list):
            # For FILESTDOUT or STDOUTOFF, use the second element (actual file path)
            if len(logfile) > 1 and logfile[0] in ['FILESTDOUT', 'STDOUTOFF']:
                logfile = logfile[1]
            # For FILE configuration, use the first element
            elif logfile[0] not in ['STDOUT', 'FILEOFF']:
                logfile = logfile[0]
            else:
                return jsonify({'error': 'Logging to file is not enabled'})
        
        # If logging is disabled or set to stdout only
        if logfile in ['STDOUT', 'FILEOFF']:
            return jsonify({'error': 'Logging to file is not enabled'})
            
        with open(logfile, 'r') as f:
            logs = f.readlines()[-100:]  # Get last 100 lines
        return jsonify({'logs': logs})
    except Exception as e:
        return jsonify({'error': str(e)})

def save_config(config):
    """Save configuration to file"""
    import json
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)

def load_config():
    """Load configuration from file"""
    import json
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except:
        return {
            'db_type': 'sqlite',
            'sqlite_path': 'pykms_database.db',
            'web_port': 8080
        }

def init_web_gui(config):
    """Initialize the web GUI with the given configuration.
    
    Args:
        config: Dictionary containing web GUI configuration
    
    Returns:
        Flask application instance
    """
    # Initialize database
    db = create_backend(config)
    
    # Configure Flask
    app.config.update(
        DATABASE=db,
        ENV='production',  # Set to production mode
        DEBUG=False,       # Disable debug mode
    )
    
    # Configure logging to match KMS server format
    import logging
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.protocol_version = "HTTP/1.1"  # Reduce logging noise
    
    # Disable Werkzeug's default logger
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    # Use our own logger for Flask
    flask_logger = logging.getLogger('logsrv')
    app.logger.handlers = flask_logger.handlers
    app.logger.setLevel(flask_logger.level)
    
    return app

if __name__ == '__main__':
    config = load_config()
    app = init_web_gui(config)
    app.run(host='0.0.0.0', port=config.get('web_port', 8080)) 