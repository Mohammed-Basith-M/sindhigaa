"""
CyberShield CLI Analysis Runner
Executes real PCAP analysis from the command line and prints JSON to stdout.
Usage: python3 run_analysis.py <path_to_pcap> [original_filename] [--is-demo]
"""

import sys
import os
import json

# Ensure parent directory is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from services.analysis_service import process_pcap_file, get_demo_analysis

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Missing PCAP filepath argument"}), file=sys.stderr)
        sys.exit(1)
        
    filepath = sys.argv[1]
    
    if filepath == "--demo":
        res = get_demo_analysis()
        print(json.dumps(res))
        return
        
    original_filename = os.path.basename(filepath)
    if len(sys.argv) >= 3 and not sys.argv[2].startswith("--"):
        original_filename = sys.argv[2]
        
    is_demo = "--is-demo" in sys.argv
    
    try:
        result = process_pcap_file(filepath, original_filename, is_demo=is_demo)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
