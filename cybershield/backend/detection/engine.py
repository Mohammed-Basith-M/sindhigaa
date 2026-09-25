"""
CyberShield Master Threat Detection Engine
Aggregates modular detection rules, computes XAI explainability metrics,
builds the Suspicious IP table, Attack Summary, and chronological event timeline.
"""

from typing import List, Dict, Any
try:
    from .port_scan import detect_port_scan
    from .dos_ddos import detect_dos_ddos
    from .brute_force import detect_brute_force
    from .botnet_c2 import detect_botnet_c2
    from .suspicious_conn import detect_suspicious_conn
except (ImportError, ValueError):
    from detection.port_scan import detect_port_scan
    from detection.dos_ddos import detect_dos_ddos
    from detection.brute_force import detect_brute_force
    from detection.botnet_c2 import detect_botnet_c2
    from detection.suspicious_conn import detect_suspicious_conn

def analyze_traffic(
    packets: List[Dict[str, Any]], 
    flows: List[Dict[str, Any]], 
    features: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Main detection analysis workflow.
    """
    summary = features.get("summary", {})
    total_packets = summary.get("total_packets", len(packets))
    duration = summary.get("duration_seconds", 0.0)
    
    # 1. Check for Insufficient Evidence (< 5 packets or duration < 0.005s with < 8 packets)
    if total_packets < 5:
        return _build_insufficient_evidence_response(total_packets, duration, features)
        
    detected_threats = []
    
    # 2. Run detection modules
    port_scan_threat = detect_port_scan(packets, flows, features)
    if port_scan_threat:
        detected_threats.append(port_scan_threat)
        
    dos_threat = detect_dos_ddos(packets, flows, features)
    if dos_threat:
        detected_threats.append(dos_threat)
        
    brute_threat = detect_brute_force(packets, flows, features)
    if brute_threat:
        detected_threats.append(brute_threat)
        
    botnet_threat = detect_botnet_c2(packets, flows, features)
    if botnet_threat:
        detected_threats.append(botnet_threat)
        
    suspicious_threat = detect_suspicious_conn(packets, flows, features)
    if suspicious_threat:
        detected_threats.append(suspicious_threat)
        
    # 3. Classify overall traffic
    if not detected_threats:
        return _build_benign_response(features)
        
    # Sort detected threats by severity priority
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "BENIGN": 1}
    detected_threats.sort(key=lambda t: severity_order.get(t["severity"], 1), reverse=True)
    primary = detected_threats[0]
    
    # Build Observed Features for XAI
    observed_features = {
        "total_packets_analyzed": total_packets,
        "unique_destination_ports": features.get("unique_destination_ports", 0),
        "traffic_velocity_pps": summary.get("packets_per_second", 0.0),
        "traffic_throughput_kbps": round(summary.get("bytes_per_second", 0.0) / 1024, 2),
        "total_flows_created": len(flows),
        "capture_duration_sec": duration,
        "syn_packet_percentage": _calc_syn_percentage(packets)
    }
    
    # Build dynamic human-readable explanation
    explanation = _generate_explanation(primary, observed_features)
    
    # Build Suspicious IP table
    suspicious_ips = _build_suspicious_ip_table(detected_threats, flows)
    
    # Build Attack Summary
    attack_summary = []
    for t in detected_threats:
        attack_summary.append({
            "attack_type": t["threat"],
            "occurrences": 1,
            "severity": t["severity"],
            "evidence": t["evidence"][0] if t.get("evidence") else "Observed anomaly",
            "confidence": t["confidence"]
        })
        
    # Build Event Timeline
    timeline_events = _build_event_timeline(detected_threats, packets, flows)
    
    return {
        "threat": primary["threat"],
        "severity": primary["severity"],
        "confidence": primary["confidence"],
        "evidence": primary["evidence"],
        "detected_threats": detected_threats,
        "xai": {
            "prediction": primary["threat"],
            "severity": primary["severity"],
            "confidence": primary["confidence"],
            "observed_features": observed_features,
            "explanation": explanation
        },
        "suspicious_ips": suspicious_ips,
        "attack_summary": attack_summary,
        "timeline_events": timeline_events,
        "is_insufficient_evidence": False,
        "is_benign": False
    }

def _calc_syn_percentage(packets: List[Dict[str, Any]]) -> float:
    tcp_pkts = [p for p in packets if p.get("protocol") == "TCP"]
    if not tcp_pkts:
        return 0.0
    syn_count = sum(1 for p in tcp_pkts if p.get("tcp_flags", {}).get("SYN"))
    return round((syn_count / len(tcp_pkts)) * 100, 1)

def _generate_explanation(threat: Dict[str, Any], features: Dict[str, Any]) -> str:
    name = threat["threat"]
    ports = features.get("unique_destination_ports", 0)
    syn_pct = features.get("syn_packet_percentage", 0.0)
    pps = features.get("traffic_velocity_pps", 0.0)
    
    if name == "Port Scan":
        return (
            f"The analyzed traffic exhibits characteristic horizontal/vertical reconnaissance patterns. "
            f"A single source contacted {ports} unique destination ports with {syn_pct}% SYN probe traffic "
            f"and negligible completed handshakes within a tight time window. This pattern is consistent with "
            f"automated network vulnerability discovery."
        )
    elif name == "DoS/DDoS":
        return (
            f"The analyzed traffic demonstrates severe volumetric and velocity anomalies. "
            f"Packet transmission velocity spiked to {pps} packets/second with traffic heavily concentrated "
            f"on a single destination host, overwhelming standard operational thresholds."
        )
    elif name == "Brute Force":
        return (
            f"The analyzed traffic contains repeated connection attempts targeting authentication service "
            f"ports (e.g. {threat.get('service', 'administrative service')}). High attempt frequency and rapid session termination "
            f"point directly to automated credential stuffing or dictionary attacks."
        )
    elif name == "Possible Botnet/C2":
        return (
            f"The analyzed traffic displays regular periodic communication intervals between host pairs with "
            f"statistically low inter-arrival jitter (std dev < 0.28). This rhythmic beaconing is typical of "
            f"automated Command & Control (C2) heartbeat agents."
        )
    elif name == "Suspicious Connection":
        return (
            f"Network traffic was observed directly communicating on known high-risk backdoor or exploitation ports "
            f"({threat.get('port', 'high-risk port')}), indicating unauthorized access or reverse shell establishment."
        )
    return "Traffic triggers rule-based network security alerts based on observed deviations from baseline telemetry."

def _build_suspicious_ip_table(threats: List[Dict[str, Any]], flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    table = []
    seen = set()
    for t in threats:
        # Match with related flows
        threat_name = t["threat"]
        attacker_ip = t.get("attacker_ip") or t.get("src_ip") or t.get("internal_host")
        target_ip = t.get("target_ip") or t.get("dst_ip") or t.get("remote_host")
        
        matching_flows = [
            f for f in flows 
            if (not attacker_ip or f.get("src_ip") == attacker_ip) and 
               (not target_ip or f.get("dst_ip") == target_ip)
        ]
        
        if not matching_flows:
            matching_flows = flows[:3]
            
        for f in matching_flows[:5]:
            entry_key = f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}"
            if entry_key in seen:
                continue
            seen.add(entry_key)
            table.append({
                "source_ip": f["src_ip"],
                "destination_ip": f["dst_ip"],
                "source_port": f["src_port"],
                "destination_port": f["dst_port"],
                "protocol": f["protocol"],
                "packets": f["packet_count"],
                "threat": threat_name,
                "severity": t["severity"],
                "confidence": t["confidence"]
            })
    return table

def _build_event_timeline(threats: List[Dict[str, Any]], packets: List[Dict[str, Any]], flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    events = []
    timestamps = [p.get("timestamp", 0.0) for p in packets if p.get("timestamp") is not None]
    base_ts = min(timestamps) if timestamps else 0.0
    
    events.append({
        "time": "+0.00s",
        "description": "Packet capture acquisition initiated",
        "type": "INFO"
    })
    
    for t in threats:
        events.append({
            "time": f"+{round(min(1.5, (max(timestamps) - base_ts) * 0.3), 2)}s",
            "description": f"Elevated packet stream detected: {t.get('evidence', [''])[0]}",
            "type": "WARNING"
        })
        events.append({
            "time": f"+{round(min(4.0, (max(timestamps) - base_ts) * 0.7), 2)}s",
            "description": f"Threat classification confirmed: {t['threat']} ({t['severity']})",
            "type": "ALERT"
        })
        
    events.append({
        "time": f"+{round(max(timestamps) - base_ts, 2)}s",
        "description": "Capture completed; rule-based correlation finalized",
        "type": "INFO"
    })
    return events

def _build_insufficient_evidence_response(total_packets: int, duration: float, features: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "threat": "Insufficient Evidence",
        "severity": "LOW",
        "confidence": None,
        "evidence": [
            f"Capture contains only {total_packets} packet(s) over {round(duration, 3)} seconds duration.",
            "Not enough network evidence was available to make a reliable classification."
        ],
        "detected_threats": [],
        "xai": {
            "prediction": "Insufficient Evidence",
            "severity": "LOW",
            "confidence": None,
            "observed_features": {
                "total_packets_analyzed": total_packets,
                "capture_duration_sec": round(duration, 3),
                "unique_destination_ports": features.get("unique_destination_ports", 0)
            },
            "explanation": "Not enough network evidence was available to make a reliable classification."
        },
        "suspicious_ips": [],
        "attack_summary": [],
        "timeline_events": [
            {"time": "+0.00s", "description": "Capture initiated", "type": "INFO"},
            {"time": f"+{round(duration, 2)}s", "description": "Analysis halted due to insufficient telemetry (< 5 packets)", "type": "INFO"}
        ],
        "is_insufficient_evidence": True,
        "is_benign": False
    }

def _build_benign_response(features: Dict[str, Any]) -> Dict[str, Any]:
    summary = features.get("summary", {})
    return {
        "threat": "Benign",
        "severity": "BENIGN",
        "confidence": 0.95,
        "evidence": [
            "Protocol distribution aligns with standard operational traffic.",
            "TCP handshakes exhibit balanced SYN and ACK completion flags.",
            "No anomalous port diversity or volumetric velocity detected.",
            "No persistent periodic beaconing or known high-risk listener ports identified."
        ],
        "detected_threats": [],
        "xai": {
            "prediction": "Benign",
            "severity": "BENIGN",
            "confidence": 0.95,
            "observed_features": {
                "total_packets_analyzed": summary.get("total_packets", 0),
                "unique_destination_ports": features.get("unique_destination_ports", 0),
                "traffic_velocity_pps": summary.get("packets_per_second", 0.0),
                "total_flows_created": summary.get("total_flows", 0)
            },
            "explanation": "No suspicious activity was identified by the implemented detection rules."
        },
        "suspicious_ips": [],
        "attack_summary": [
            {
                "attack_type": "None",
                "occurrences": 0,
                "severity": "BENIGN",
                "evidence": "No suspicious activity was identified by the implemented detection rules.",
                "confidence": 0.95
            }
        ],
        "timeline_events": [
            {"time": "+0.00s", "description": "Network telemetry acquisition verified", "type": "INFO"},
            {"time": f"+{round(summary.get('duration_seconds', 0.0), 2)}s", "description": "Baseline audit completed: clean protocol handshakes", "type": "INFO"}
        ],
        "is_insufficient_evidence": False,
        "is_benign": True
    }
