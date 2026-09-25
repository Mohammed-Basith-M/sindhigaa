"""
CyberShield Python Standard Library WSGI/HTTP Server
Enables the CyberShield backend to execute and serve REST APIs with zero external dependencies
whenever Flask is not installed in the local Python environment.
"""

import sys
import os
import json
import urllib.parse
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class RequestContext:
    def __init__(self, method, path, headers, query_params, body_bytes):
        self.method = method
        self.path = path
        self.headers = headers
        self.args = query_params
        self.data = body_bytes
        self.files = {}
        self.form = {}
        self._parse_body()
        
    def _parse_body(self):
        content_type = self.headers.get('Content-Type', '')
        if 'multipart/form-data' in content_type:
            boundary_match = re.search(r'boundary=([^;]+)', content_type)
            if boundary_match:
                boundary = boundary_match.group(1).strip().strip('"').encode('utf-8')
                self._parse_multipart(boundary)
        elif 'application/json' in content_type and self.data:
            try:
                self.json = json.loads(self.data.decode('utf-8'))
            except Exception:
                self.json = {}
        else:
            self.json = {}

    def _parse_multipart(self, boundary: bytes):
        delimiter = b'--' + boundary
        parts = self.data.split(delimiter)
        for part in parts:
            if not part or part == b'--\r\n' or part == b'--':
                continue
            if b'\r\n\r\n' in part:
                header_part, body_part = part.split(b'\r\n\r\n', 1)
                body_part = body_part.rstrip(b'\r\n')
                hdr_str = header_part.decode('latin-1', errors='ignore')
                
                # Check for file
                file_match = re.search(r'name="([^"]+)";\s+filename="([^"]+)"', hdr_str)
                if file_match:
                    field_name = file_match.group(1)
                    filename = file_match.group(2)
                    self.files[field_name] = UploadedFileShim(filename, body_part)
                else:
                    form_match = re.search(r'name="([^"]+)"', hdr_str)
                    if form_match:
                        field_name = form_match.group(1)
                        self.form[field_name] = body_part.decode('utf-8', errors='ignore')

class UploadedFileShim:
    def __init__(self, filename: str, content: bytes):
        self.filename = filename
        self.content = content
        
    def save(self, destination_path: str):
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        with open(destination_path, 'wb') as f:
            f.write(self.content)
            
    def read(self) -> bytes:
        return self.content

class FlaskShim:
    def __init__(self, name: str, static_folder: str = 'static'):
        self.name = name
        self.static_folder = static_folder
        self.routes = []
        
    def route(self, rule: str, methods: list = None):
        if methods is None:
            methods = ['GET']
        def decorator(f):
            # Convert rule to regex (e.g. /results/<analysis_id> -> /results/(?P<analysis_id>[^/]+))
            regex_rule = re.sub(r'<([^>]+)>', r'(?P<\1>[^/]+)', rule)
            regex = re.compile(f'^{regex_rule}$')
            self.routes.append((methods, regex, f))
            return f
        return decorator

    def run(self, host: str = '0.0.0.0', port: int = 5000, debug: bool = False):
        shim_app = self
        
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                if debug:
                    sys.stderr.write(f"[CyberShield-Shim] {format % args}\n")
                    
            def send_cors_headers(self):
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
                
            def do_OPTIONS(self):
                self.send_response(200)
                self.send_cors_headers()
                self.end_headers()
                
            def do_GET(self):
                self._dispatch('GET')
                
            def do_POST(self):
                self._dispatch('POST')
                
            def do_DELETE(self):
                self._dispatch('DELETE')
                
            def _dispatch(self, method: str):
                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path
                q_params = dict(urllib.parse.parse_qsl(parsed.query))
                
                content_len = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_len) if content_len > 0 else b''
                
                req = RequestContext(method, path, self.headers, q_params, body)
                
                # Match routes
                for methods, regex, handler in shim_app.routes:
                    if method in methods:
                        m = regex.match(path)
                        if m:
                            kwargs = m.groupdict()
                            try:
                                resp = handler(req, **kwargs)
                                self._send_response_object(resp)
                                return
                            except Exception as e:
                                self.send_response(500)
                                self.send_cors_headers()
                                self.send_header('Content-Type', 'application/json')
                                self.end_headers()
                                self.wfile.write(json.dumps({'error': str(e)}).encode('utf-8'))
                                return
                                
                # Check for static file
                static_path = os.path.join(shim_app.static_folder, path.lstrip('/'))
                if os.path.exists(static_path) and not os.path.isdir(static_path):
                    self._serve_file(static_path)
                    return
                elif os.path.exists(os.path.join(shim_app.static_folder, 'index.html')):
                    self._serve_file(os.path.join(shim_app.static_folder, 'index.html'))
                    return
                    
                self.send_response(404)
                self.send_cors_headers()
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Not found'}).encode('utf-8'))

            def _send_response_object(self, resp):
                if isinstance(resp, tuple):
                    data, status_code = resp[0], resp[1]
                else:
                    data, status_code = resp, 200
                    
                self.send_response(status_code)
                self.send_cors_headers()
                if isinstance(data, (dict, list)):
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(data).encode('utf-8'))
                else:
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(str(data).encode('utf-8'))
                    
            def _serve_file(self, filepath: str):
                self.send_response(200)
                self.send_cors_headers()
                content_type = 'text/plain'
                if filepath.endswith('.html'):
                    content_type = 'text/html'
                elif filepath.endswith('.js'):
                    content_type = 'application/javascript'
                elif filepath.endswith('.css'):
                    content_type = 'text/css'
                elif filepath.endswith('.json'):
                    content_type = 'application/json'
                elif filepath.endswith('.svg'):
                    content_type = 'image/svg+xml'
                self.send_header('Content-Type', content_type)
                self.end_headers()
                with open(filepath, 'rb') as f:
                    self.wfile.write(f.read())

        server = ThreadedHTTPServer((host, port), Handler)
        print(f"[*] CyberShield Server running at http://{host}:{port}/")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.server_close()
