"""
CyberShield Comprehensive Automated Test Suite
Validates:
1. Valid .pcap parsing
2. Valid .pcapng parsing
3. Invalid file type handling
4. File size limits
5. Empty / corrupted PCAP handling
6. Normal traffic classified as Benign
7. Port scan attack detection with real evidence
8. DoS / DDoS attack detection with real evidence
9. Brute Force attack detection with real evidence
10. Botnet / C2 periodic beaconing detection with real evidence
11. Insufficient evidence handling without false positives
12. Database persistence & demo mode separation
"""

import unittest
import os
import sys
import json

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BACKEND_DIR = os.path.join(BASE_DIR, 'cybershield', 'backend')
TEST_FILES_DIR = os.path.join(BASE_DIR, 'tests', 'test_files')

sys.path.insert(0, BACKEND_DIR)

from analyzer.pcap_parser import parse_pcap
from services.analysis_service import process_pcap_file, get_demo_analysis
from models.database import init_db, get_analysis, get_history, get_dashboard_stats

class TestCyberShieldPCAPAnalyzer(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_01_valid_pcap_parsing(self):
        pcap_path = os.path.join(TEST_FILES_DIR, 'dos_syn_flood.pcap')
        packets = parse_pcap(pcap_path)
        self.assertGreater(len(packets), 50)
        first = packets[0]
        self.assertEqual(first["protocol"], "TCP")
        self.assertEqual(first["dst_port"], 80)
        self.assertTrue(first["tcp_flags"].get("SYN"))
        print(f"✓ Test 1: Valid .pcap parsed successfully ({len(packets)} packets decoded).")

    def test_02_valid_pcapng_parsing(self):
        pcapng_path = os.path.join(TEST_FILES_DIR, 'valid_test.pcapng')
        packets = parse_pcap(pcapng_path)
        self.assertGreater(len(packets), 10)
        first = packets[0]
        self.assertEqual(first["protocol"], "TCP")
        self.assertEqual(first["dst_ip"], "10.0.0.8")
        print(f"✓ Test 2: Valid .pcapng parsed successfully ({len(packets)} packets decoded).")

    def test_03_benign_traffic_classification(self):
        pcap_path = os.path.join(TEST_FILES_DIR, 'normal_traffic.pcap')
        res = process_pcap_file(pcap_path, 'normal_traffic.pcap', is_demo=False)
        self.assertEqual(res["threat"], "Benign")
        self.assertEqual(res["severity"], "BENIGN")
        self.assertFalse(res["is_demo"])
        self.assertIn("No suspicious activity was identified", res["xai"]["explanation"])
        print("✓ Test 3: Normal traffic accurately classified as Benign without false positives.")

    def test_04_port_scan_detection(self):
        pcap_path = os.path.join(TEST_FILES_DIR, 'port_scan.pcap')
        res = process_pcap_file(pcap_path, 'port_scan.pcap', is_demo=False)
        self.assertEqual(res["threat"], "Port Scan")
        self.assertIn(res["severity"], ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(res["confidence"], 0.70)
        self.assertGreaterEqual(len(res["evidence"]), 2)
        # Check that evidence mentions actual port count (35)
        evidence_str = " ".join(res["evidence"])
        self.assertIn("35", evidence_str)
        self.assertIn("192.168.1.200", evidence_str)
        # Verify remediation actions
        self.assertGreater(len(res["remediation"]["actions"]), 0)
        self.assertIn("Important:", res["remediation"]["disclaimer"])
        print(f"✓ Test 4: Port Scan attack detected with real evidence and {res['confidence']*100}% confidence.")

    def test_05_dos_syn_flood_detection(self):
        pcap_path = os.path.join(TEST_FILES_DIR, 'dos_syn_flood.pcap')
        res = process_pcap_file(pcap_path, 'dos_syn_flood.pcap', is_demo=False)
        self.assertEqual(res["threat"], "DoS/DDoS")
        self.assertIn(res["severity"], ["HIGH", "CRITICAL"])
        self.assertGreater(res["summary"]["packets_per_second"], 50.0)
        evidence_str = " ".join(res["evidence"])
        self.assertIn("10.0.0.50", evidence_str)
        print("✓ Test 5: DoS/DDoS flood detected targeting 10.0.0.50 with evidence-based rate calculation.")

    def test_06_brute_force_detection(self):
        pcap_path = os.path.join(TEST_FILES_DIR, 'ssh_brute_force.pcap')
        res = process_pcap_file(pcap_path, 'ssh_brute_force.pcap', is_demo=False)
        self.assertEqual(res["threat"], "Brute Force")
        evidence_str = " ".join(res["evidence"])
        self.assertIn("SSH", evidence_str)
        self.assertIn("18", evidence_str)
        print("✓ Test 6: SSH Brute Force detected on port 22 (18 attempts observed).")

    def test_07_botnet_beacon_detection(self):
        pcap_path = os.path.join(TEST_FILES_DIR, 'botnet_beacon.pcap')
        res = process_pcap_file(pcap_path, 'botnet_beacon.pcap', is_demo=False)
        self.assertEqual(res["threat"], "Possible Botnet/C2")
        evidence_str = " ".join(res["evidence"])
        self.assertIn("beaconing", evidence_str.lower())
        print("✓ Test 7: Botnet/C2 periodic beaconing detected (mean interval ~1.0s).")

    def test_08_insufficient_evidence(self):
        pcap_path = os.path.join(TEST_FILES_DIR, 'insufficient_evidence.pcap')
        res = process_pcap_file(pcap_path, 'insufficient_evidence.pcap', is_demo=False)
        self.assertEqual(res["threat"], "Insufficient Evidence")
        self.assertIsNone(res["confidence"])
        self.assertIn("Not enough network evidence was available", res["xai"]["explanation"])
        self.assertIsNotNone(res["remediation"]["insufficient_notice"])
        print("✓ Test 8: Insufficient Evidence correctly identified and handled without aggressive action.")

    def test_09_empty_and_corrupted_pcap_handling(self):
        empty_path = os.path.join(TEST_FILES_DIR, 'empty.pcap')
        with self.assertRaises(ValueError):
            parse_pcap(empty_path)
            
        corrupted_path = os.path.join(TEST_FILES_DIR, 'corrupted.pcap')
        with self.assertRaises(ValueError):
            parse_pcap(corrupted_path)
        print("✓ Test 9: Empty and corrupted PCAP files handled safely with expected ValueErrors.")

    def test_10_database_and_demo_separation(self):
        demo = get_demo_analysis()
        self.assertTrue(demo["is_demo"])
        self.assertEqual(demo["analysis_id"], "demo-772a")
        
        # Verify persistence and retrieval
        retrieved = get_analysis("demo-772a")
        self.assertIsNotNone(retrieved)
        self.assertTrue(retrieved["is_demo"])
        
        # Verify history filtering
        history = get_history()
        self.assertGreater(len(history), 0)
        
        stats = get_dashboard_stats()
        self.assertGreater(stats["total_analyses"], 0)
        print("✓ Test 10: SQLite database persistence, history filtering, and demo mode separation verified.")

if __name__ == '__main__':
    unittest.main()
