"""
CyberShield Backend Configuration
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'.pcap', '.pcapng'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB Maximum file size
DATABASE_PATH = os.path.join(BASE_DIR, 'cybershield.db')
PORT = int(os.environ.get('PORT', 5000))
HOST = os.environ.get('HOST', '0.0.0.0')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
