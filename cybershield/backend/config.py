"""
CyberShield Backend Configuration
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'.pcap', '.pcapng'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB Maximum file size
DATABASE_PATH = os.path.join(BASE_DIR, 'cybershield.db')

# Safe port selection avoiding clashes with Nginx (8080), Dev Server (3000), or Control Plane (8000)
def get_safe_port():
    explicit = os.environ.get('BACKEND_PORT') or os.environ.get('FLASK_PORT')
    if explicit:
        return int(explicit)
    p = os.environ.get('PORT')
    if p and p not in ('8080', '3000', '8000'):
        return int(p)
    return 5000

PORT = get_safe_port()
HOST = os.environ.get('HOST', '0.0.0.0')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
