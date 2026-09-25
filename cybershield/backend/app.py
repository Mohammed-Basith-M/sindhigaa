"""
CyberShield PCAP Analyzer Backend API Service
Main Flask / WSGI Entry Point exposing REST APIs.
"""

import os
import sys
import uuid
import json

# Ensure backend root is in sys.path
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from config import UPLOAD_FOLDER, ALLOWED_EXTENSIONS, MAX_CONTENT_LENGTH, PORT, HOST
from services.analysis_service import (
    process_pcap_file, 
    get_demo_analysis, 
    get_analysis, 
    get_history, 
    delete_analysis, 
    get_dashboard_stats
)
from models.database import init_db

# Try importing real Flask, or fall back to native FlaskShim
try:
    from flask import Flask, request, jsonify, send_from_directory
    from flask_cors import CORS
    USE_REAL_FLASK = True
except ImportError:
    from flask_shim import FlaskShim
    USE_REAL_FLASK = False

init_db()

if USE_REAL_FLASK:
    app = Flask(__name__, static_folder='static')
    CORS(app)
    app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
else:
    app = FlaskShim(__name__, static_folder=os.path.join(BASE_DIR, 'static'))

def is_allowed_file(filename: str) -> bool:
    ext = os.path.splitext(filename.lower())[1]
    return ext in ALLOWED_EXTENSIONS

# ----------------- ROUTE HANDLERS -----------------

def health_handler(req=None):
    return {"status": "ok", "service": "CyberShield Backend"}

def upload_handler(req=None):
    request_obj = req if not USE_REAL_FLASK else request
    
    files = request_obj.files
    if not files or 'file' not in files:
        return {"error": "No file part in request. Please upload a .pcap or .pcapng file."}, 400
        
    uploaded_file = files['file']
    filename = uploaded_file.filename
    if not filename or filename.strip() == '':
        return {"error": "No selected file provided."}, 400
        
    if not is_allowed_file(filename):
        return {
            "error": "Invalid file type. Only .pcap and .pcapng files are supported."
        }, 400
        
    # Generate unique secure storage path
    safe_id = str(uuid.uuid4())[:8]
    sanitized_filename = os.path.basename(filename)
    saved_name = f"{safe_id}_{sanitized_filename}"
    filepath = os.path.join(UPLOAD_FOLDER, saved_name)
    
    try:
        uploaded_file.save(filepath)
    except Exception as e:
        return {"error": f"Failed to save file: {str(e)}"}, 500
        
    # Check file size limit
    file_size = os.path.getsize(filepath)
    if file_size > MAX_CONTENT_LENGTH:
        if os.path.exists(filepath):
            os.remove(filepath)
        return {"error": "File exceeds the 50 MB limit."}, 400
        
    # Execute actual analysis immediately
    try:
        result = process_pcap_file(filepath, sanitized_filename, is_demo=False)
        return result, 200
    except ValueError as ve:
        if os.path.exists(filepath):
            os.remove(filepath)
        return {"error": str(ve)}, 400
    except Exception as ex:
        if os.path.exists(filepath):
            os.remove(filepath)
        return {"error": f"The uploaded PCAP could not be parsed: {str(ex)}"}, 500

def get_results_handler(req=None, analysis_id=None):
    if not analysis_id:
        return {"error": "Analysis ID required"}, 400
    data = get_analysis(analysis_id)
    if not data:
        return {"error": f"Analysis with ID '{analysis_id}' not found."}, 404
    return data, 200

def history_handler(req=None):
    request_obj = req if not USE_REAL_FLASK else request
    args = request_obj.args
    search = args.get('search', '')
    severity = args.get('severity', 'all')
    records = get_history(search=search, severity=severity)
    return {"history": records}, 200

def delete_history_handler(req=None, analysis_id=None):
    if not analysis_id:
        return {"error": "Analysis ID required"}, 400
    success = delete_analysis(analysis_id)
    if success:
        return {"message": f"Analysis '{analysis_id}' deleted successfully."}, 200
    return {"error": f"Analysis '{analysis_id}' not found."}, 404

def demo_handler(req=None):
    data = get_demo_analysis()
    return data, 200

def stats_handler(req=None):
    stats = get_dashboard_stats()
    return stats, 200

# ----------------- ROUTE REGISTRATION -----------------

if USE_REAL_FLASK:
    @app.route('/health', methods=['GET'])
    def flask_health():
        return jsonify(health_handler())
        
    @app.route('/upload', methods=['POST'])
    def flask_upload():
        resp, code = upload_handler()
        return jsonify(resp), code
        
    @app.route('/results/<analysis_id>', methods=['GET'])
    def flask_results(analysis_id):
        res = get_results_handler(analysis_id=analysis_id)
        if isinstance(res, tuple):
            return jsonify(res[0]), res[1]
        return jsonify(res), 200
        
    @app.route('/history', methods=['GET'])
    def flask_history():
        resp, code = history_handler()
        return jsonify(resp), code
        
    @app.route('/history/<analysis_id>', methods=['DELETE'])
    def flask_delete_history(analysis_id):
        resp, code = delete_history_handler(analysis_id=analysis_id)
        return jsonify(resp), code
        
    @app.route('/demo', methods=['GET'])
    def flask_demo():
        data, code = demo_handler()
        return jsonify(data), code
        
    @app.route('/stats', methods=['GET'])
    def flask_stats():
        data, code = stats_handler()
        return jsonify(data), code

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def serve_frontend(path):
        if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
            return send_from_directory(app.static_folder, path)
        return send_from_directory(app.static_folder, 'index.html')

else:
    app.route('/health', methods=['GET'])(health_handler)
    app.route('/upload', methods=['POST'])(upload_handler)
    app.route('/results/<analysis_id>', methods=['GET'])(get_results_handler)
    app.route('/history', methods=['GET'])(history_handler)
    app.route('/history/<analysis_id>', methods=['DELETE'])(delete_history_handler)
    app.route('/demo', methods=['GET'])(demo_handler)
    app.route('/stats', methods=['GET'])(stats_handler)

if __name__ == '__main__':
    print(f"[*] Starting CyberShield PCAP Analyzer Backend on port {PORT}...")
    app.run(host=HOST, port=PORT, debug=True)
