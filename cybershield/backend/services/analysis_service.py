"""
CyberShield Analysis Orchestration Service
Glues parsing, flow extraction, telemetry distribution, threat detection,
remediation generation, and SQLite persistence.
"""

import os
import uuid
import time
from typing import Dict, Any, Optional
try:
    from ..analyzer.pcap_parser import parse_pcap
    from ..analyzer.flow_engine import extract_flows
    from ..analyzer.feature_extractor import extract_features
    from ..detection.engine import analyze_traffic
    from ..remediation.remediation_engine import generate_remediation
    from ..models.database import save_analysis, get_analysis, get_history, delete_analysis, get_dashboard_stats
except (ImportError, ValueError):
    from analyzer.pcap_parser import parse_pcap
    from analyzer.flow_engine import extract_flows
    from analyzer.feature_extractor import extract_features
    from detection.engine import analyze_traffic
    from remediation.remediation_engine import generate_remediation
    from models.database import save_analysis, get_analysis, get_history, delete_analysis, get_dashboard_stats

def process_pcap_file(filepath: str, original_filename: str, is_demo: bool = False) -> Dict[str, Any]:
    """
    Executes real PCAP analysis on uploaded file.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Uploaded file not found: {filepath}")
        
    file_size = os.path.getsize(filepath)
    if file_size > 50 * 1024 * 1024:
        raise ValueError("File exceeds the 50 MB limit.")
        
    analysis_id = str(uuid.uuid4())[:8]
    created_at = time.time()
    
    # 1. Parse packets
    packets = parse_pcap(filepath)
    if not packets:
        raise ValueError("The uploaded PCAP could not be parsed or contains no valid packets.")
        
    # 2. Extract flows
    flows = extract_flows(packets)
    
    # 3. Extract features & telemetry
    features = extract_features(packets, flows)
    
    # 4. Run rule-based detection engine
    detection = analyze_traffic(packets, flows, features)
    
    # 5. Generate remediation recommendations
    remediation = generate_remediation(detection, features)
    
    # 6. Assemble complete JSON response
    result: Dict[str, Any] = {
        "analysis_id": analysis_id,
        "filename": original_filename,
        "file_size": file_size,
        "created_at": created_at,
        "status": "completed",
        "is_demo": is_demo,
        "threat": detection["threat"],
        "severity": detection["severity"],
        "confidence": detection["confidence"],
        "evidence": detection["evidence"],
        "summary": features["summary"],
        "protocols": features["protocols"],
        "top_source_ips": features["top_source_ips"],
        "top_destination_ips": features["top_destination_ips"],
        "top_ports": features["top_ports"],
        "top_source_ports": features["top_source_ports"],
        "unique_source_ips": features["unique_source_ips"],
        "unique_destination_ips": features["unique_destination_ips"],
        "unique_destination_ports": features["unique_destination_ports"],
        "packet_size_distribution": features["packet_size_distribution"],
        "timeline": features["timeline"],
        "timeline_events": detection["timeline_events"],
        "suspicious_ips": detection["suspicious_ips"],
        "attack_summary": detection["attack_summary"],
        "xai": detection["xai"],
        "remediation": remediation
    }
    
    # 7. Persist to SQLite
    save_analysis(result)
    
    return result

def get_demo_analysis() -> Dict[str, Any]:
    """
    Returns realistic sample PCAP analysis data strictly tagged with is_demo: True.
    """
    analysis_id = "demo-772a"
    existing = get_analysis(analysis_id)
    if existing:
        return existing
        
    sample_data: Dict[str, Any] = {
        "analysis_id": analysis_id,
        "filename": "sample_syn_recon_capture.pcap",
        "file_size": 284520,
        "created_at": time.time(),
        "status": "completed",
        "is_demo": True,
        "threat": "Port Scan",
        "severity": "HIGH",
        "confidence": 0.92,
        "evidence": [
            "Source host 192.168.1.105 contacted 42 unique destination ports.",
            "128 SYN probe packets observed (86.5% of source traffic).",
            "38 connections were one-way / unsuccessful without completed handshakes.",
            "Scanning activity concentrated within 8.42 seconds (avg flow duration: 0.042s)."
        ],
        "summary": {
            "total_packets": 1420,
            "total_bytes": 118490,
            "total_flows": 142,
            "duration_seconds": 12.8,
            "start_time": 1727271000.0,
            "end_time": 1727271012.8,
            "avg_packet_size": 83.44,
            "packets_per_second": 110.94,
            "bytes_per_second": 9257.03
        },
        "protocols": {
            "TCP": 1280,
            "UDP": 110,
            "ICMP": 30,
            "OTHER": 0
        },
        "top_source_ips": [
            {"ip": "192.168.1.105", "count": 1280, "bytes": 102400, "percentage": 90.1},
            {"ip": "192.168.1.1", "count": 80, "bytes": 8400, "percentage": 5.6},
            {"ip": "8.8.8.8", "count": 40, "bytes": 4800, "percentage": 2.8},
            {"ip": "192.168.1.254", "count": 20, "bytes": 2890, "percentage": 1.4}
        ],
        "top_destination_ips": [
            {"ip": "10.0.0.15", "count": 940, "bytes": 75200, "percentage": 66.2},
            {"ip": "10.0.0.22", "count": 340, "bytes": 27200, "percentage": 23.9},
            {"ip": "192.168.1.105", "count": 140, "bytes": 16090, "percentage": 9.9}
        ],
        "top_ports": [
            {"port": 80, "service": "HTTP", "label": "80 (HTTP)", "count": 140, "percentage": 9.9},
            {"port": 443, "service": "HTTPS", "label": "443 (HTTPS)", "count": 130, "percentage": 9.2},
            {"port": 22, "service": "SSH", "label": "22 (SSH)", "count": 115, "percentage": 8.1},
            {"port": 21, "service": "FTP", "label": "21 (FTP)", "count": 98, "percentage": 6.9},
            {"port": 3389, "service": "RDP", "label": "3389 (RDP)", "count": 85, "percentage": 6.0},
            {"port": 8080, "service": "HTTP-Proxy", "label": "8080 (HTTP-Proxy)", "count": 76, "percentage": 5.4}
        ],
        "top_source_ports": [
            {"port": 49152, "count": 120},
            {"port": 49153, "count": 110},
            {"port": 49154, "count": 95}
        ],
        "unique_source_ips": 4,
        "unique_destination_ips": 3,
        "unique_destination_ports": 42,
        "packet_size_distribution": {
            "<128B": 1280,
            "128-512B": 110,
            "512-1024B": 20,
            ">1024B": 10
        },
        "timeline": [
            {"time_offset": "+0.0s", "packets": 45, "bytes": 3600, "tcp": 40, "udp": 5, "timestamp": 1727271000.0},
            {"time_offset": "+1.3s", "packets": 120, "bytes": 9800, "tcp": 110, "udp": 10, "timestamp": 1727271001.3},
            {"time_offset": "+2.6s", "packets": 190, "bytes": 15400, "tcp": 180, "udp": 10, "timestamp": 1727271002.6},
            {"time_offset": "+3.8s", "packets": 240, "bytes": 19600, "tcp": 230, "udp": 10, "timestamp": 1727271003.8},
            {"time_offset": "+5.1s", "packets": 210, "bytes": 17200, "tcp": 200, "udp": 10, "timestamp": 1727271005.1},
            {"time_offset": "+6.4s", "packets": 180, "bytes": 14900, "tcp": 170, "udp": 10, "timestamp": 1727271006.4},
            {"time_offset": "+7.7s", "packets": 160, "bytes": 13200, "tcp": 150, "udp": 10, "timestamp": 1727271007.7},
            {"time_offset": "+9.0s", "packets": 140, "bytes": 11600, "tcp": 130, "udp": 10, "timestamp": 1727271009.0},
            {"time_offset": "+10.2s", "packets": 95, "bytes": 8190, "tcp": 85, "udp": 10, "timestamp": 1727271010.2},
            {"time_offset": "+11.5s", "packets": 40, "bytes": 5000, "tcp": 35, "udp": 5, "timestamp": 1727271011.5}
        ],
        "timeline_events": [
            {"time": "+0.00s", "description": "Packet capture acquisition initiated", "type": "INFO"},
            {"time": "+1.25s", "description": "Rapid succession of TCP SYN packets detected from 192.168.1.105", "type": "WARNING"},
            {"time": "+3.40s", "description": "Destination port diversity threshold exceeded (42 unique ports)", "type": "ALERT"},
            {"time": "+8.42s", "description": "Port Scan pattern confirmed (Evidence-based confidence: 0.92)", "type": "ALERT"}
        ],
        "suspicious_ips": [
            {
                "source_ip": "192.168.1.105",
                "destination_ip": "10.0.0.15",
                "source_port": 49152,
                "destination_port": 22,
                "protocol": "TCP",
                "packets": 1,
                "threat": "Port Scan",
                "severity": "HIGH",
                "confidence": 0.92
            },
            {
                "source_ip": "192.168.1.105",
                "destination_ip": "10.0.0.15",
                "source_port": 49153,
                "destination_port": 80,
                "protocol": "TCP",
                "packets": 1,
                "threat": "Port Scan",
                "severity": "HIGH",
                "confidence": 0.92
            },
            {
                "source_ip": "192.168.1.105",
                "destination_ip": "10.0.0.15",
                "source_port": 49154,
                "destination_port": 443,
                "protocol": "TCP",
                "packets": 1,
                "threat": "Port Scan",
                "severity": "HIGH",
                "confidence": 0.92
            },
            {
                "source_ip": "192.168.1.105",
                "destination_ip": "10.0.0.15",
                "source_port": 49155,
                "destination_port": 3389,
                "protocol": "TCP",
                "packets": 1,
                "threat": "Port Scan",
                "severity": "HIGH",
                "confidence": 0.92
            }
        ],
        "attack_summary": [
            {
                "attack_type": "Port Scan",
                "occurrences": 1,
                "severity": "HIGH",
                "evidence": "Source host 192.168.1.105 contacted 42 unique destination ports.",
                "confidence": 0.92
            }
        ],
        "xai": {
            "prediction": "Port Scan",
            "severity": "HIGH",
            "confidence": 0.92,
            "observed_features": {
                "total_packets_analyzed": 1420,
                "unique_destination_ports": 42,
                "traffic_velocity_pps": 110.94,
                "traffic_throughput_kbps": 9.04,
                "total_flows_created": 142,
                "capture_duration_sec": 12.8,
                "syn_packet_percentage": 86.5
            },
            "explanation": "The analyzed traffic exhibits characteristic horizontal/vertical reconnaissance patterns. A single source contacted 42 unique destination ports with 86.5% SYN probe traffic and negligible completed handshakes within an 8.42s window. This pattern is consistent with automated network vulnerability discovery."
        },
        "remediation": {
            "disclaimer": "Important: These recommendations are based only on network evidence available in the analyzed PCAP. They should be validated against the actual network environment before taking action.",
            "actions": [
                {
                    "priority": "HIGH PRIORITY",
                    "action": "Review Exposed Services & Restrict Unnecessary Ports",
                    "reason": "The analyzed traffic demonstrates active reconnaissance against 42 unique ports. Enforce strict egress/ingress firewall policies."
                },
                {
                    "priority": "HIGH PRIORITY",
                    "action": "Implement State-Aware Rate Limiting & SYN Drop Rules",
                    "reason": "Mitigate half-open scanning probes by configuring iptables/nftables to limit SYN connection attempt rates per source IP."
                },
                {
                    "priority": "MEDIUM PRIORITY",
                    "action": "Deploy Snort / Suricata Port-Scan Detection Signatures",
                    "reason": "Enable automated threshold alerts (e.g. sfPortscan) to flag sequential port probes in real-time."
                },
                {
                    "priority": "LOW PRIORITY",
                    "action": "Audit Targeted Host for Rogue Services or Vulnerabilities",
                    "reason": "Ensure targeted endpoint systems are not running unauthenticated administrative daemons."
                }
            ],
            "insufficient_notice": None
        }
    }
    save_analysis(sample_data)
    return sample_data
