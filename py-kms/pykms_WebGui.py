#!/usr/bin/env python3

import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, current_app
from pykms_Database import create_backend
import yaml # Import yaml

app = Flask(__name__)
loggersrv = logging.getLogger('logsrv')

# Global database backend instance

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
    db = current_app.config['db']
    if not db:
        return "Database not initialized", 500
    clients = db.get_all_clients()
    unknown_activations = db.get_unknown_activations()
    stats = {
        'total_clients': len(clients),
        'active_clients': sum(1 for c in clients if c.licenseStatus == 'Activated'),
        'windows_clients': sum(
            1 for c in clients
            if (getattr(c, 'applicationName', None) and 'Windows' in str(c.applicationName))
            or (getattr(c, 'skuName', None) and 'Windows' in str(c.skuName))
        ),
        'office_clients': sum(
            1 for c in clients
            if (getattr(c, 'applicationName', None) and 'Office' in str(c.applicationName))
            or (getattr(c, 'skuName', None) and 'Office' in str(c.skuName))
        )
    }
    # Recent activations: last 7 days, max 10, deduplicated by (clientMachineId, applicationId)
    cutoff = datetime.now() - timedelta(days=7)
    seen = set()
    recent_activations = []
    # Sort by lastRequestTime descending
    sorted_clients = sorted(
        [c for c in clients if c.lastRequestTime and c.lastRequestTime >= cutoff],
        key=lambda c: c.lastRequestTime,
        reverse=True
    )
    for c in sorted_clients:
        key = (getattr(c, 'clientMachineId', None), getattr(c, 'applicationId', None))
        if key not in seen:
            seen.add(key)
            recent_activations.append(c)
        if len(recent_activations) >= 10:
            break
    return render_template('dashboard.html', stats=stats, clients=clients, unknown_activations=unknown_activations, recent_activations=recent_activations)

@app.route('/clients')
def client_list():
    """Client management interface"""
    db = current_app.config['db']
    if not db:
        return "Database not initialized", 500
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
        logfile = app.config['lfile']
        
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

@app.route('/api/notifications')
def get_notifications():
    """API endpoint for fetching unknown activation attempts"""
    db = current_app.config['db']
    if not db:
        return jsonify({'error': 'Database not initialized'}), 500
    
    notifications = db.get_unknown_activations()
    return jsonify({
        'notifications': [{
            'id': n.id,
            'timestamp': format_datetime(n.timestamp),
            'client_ip': n.client_ip,
            'sku_id': n.sku_id
        } for n in notifications]
    })

@app.route('/api/notifications/resolve/<int:activation_id>', methods=['POST'])
def resolve_notification(activation_id):
    """API endpoint for marking an unknown activation as resolved"""
    db = current_app.config['db']
    if not db:
        return jsonify({'error': 'Database not initialized'}), 500
    
    db.mark_activation_resolved(activation_id)
    return jsonify({'status': 'success'})

def save_config(config):
    """Save configuration to file"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    try:
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
    except Exception as e:
        loggersrv.error(f"Error saving config.yaml: {e}")

def load_config():
    """Load configuration from file"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    try:
        with open(config_path, 'r') as f:
            loaded_config = yaml.safe_load(f)
            return loaded_config if isinstance(loaded_config, dict) else {}
    except FileNotFoundError:
        loggersrv.warning(f"config.yaml not found at {config_path}. Using defaults.")
        return {}
    except Exception as e:
        loggersrv.error(f"Error loading config.yaml: {e}. Using defaults.")
        return {}

def init_web_gui(config):
    """Initialize the web GUI with the given configuration.
    
    Args:
        config: Dictionary containing web GUI configuration
    
    Returns:
        Flask application instance
    """
    # Initialize database
    db_instance = create_backend(config)
    app.config['db'] = db_instance
    app.config.update(config)
    
    # Configure Flask
    app.config.update(
        ENV='production',  # Set to production mode
        DEBUG=False,       # Disable debug mode
    )
    
    # Configure logging to match KMS server format
    import logging
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.protocol_version = "HTTP/1.1"  # Reduce logging noise
    
    # Disable Werkzeug's default logger
    log = logging.getLogger('werkzeug')
    # log.setLevel(logging.ERROR) # Don't suppress INFO logs
    
    # Use our own logger for Flask
    flask_logger = logging.getLogger('logsrv') 
    app.logger.handlers = flask_logger.handlers
    app.logger.setLevel(flask_logger.level)
    
    # Set Werkzeug logger level to match Flask/main logger
    log.setLevel(flask_logger.level)
    
    """Initialize the web GUI with configuration"""
    db_instance = create_backend(config)
    app.config['db'] = db_instance
    app.config.update(config)
    return app

if __name__ == '__main__':
    config = load_config()
    app = init_web_gui(config)
    app.run(host='0.0.0.0', port=config.get('web_port', 8080)) 