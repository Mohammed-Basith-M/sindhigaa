"""
CyberShield Port Scan Detection Module
Analyzes packet streams and flow states to detect horizontal and vertical port scanning behavior.
Calculates transparent evidence-based confidence metrics based on observed indicators.
"""

from typing import List, Dict, Any, Optional

def detect_port_scan(
    packets: List[Dict[str, Any]], 
    flows: List[Dict[str, Any]], 
    features: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Evaluates traffic for port-scan indicators:
    - Unique destination ports contacted by a single source
    - Elevated ratio of SYN packets with no completed handshakes
    - Short flow durations with rapid teardown
    """
    if len(packets) < 5:
        return None
        
    # Group flows by source IP
    src_flows: Dict[str, List[Dict[str, Any]]] = {}
    for f in flows:
        sip = f.get("src_ip")
        if sip and sip != "unknown":
            src_flows.setdefault(sip, []).append(f)
            
    best_candidate = None
    
    for src_ip, f_list in src_flows.items():
        dst_ports = set(f.get("dst_port") for f in f_list if f.get("dst_port"))
        unique_ports = len(dst_ports)
        total_src_packets = sum(f.get("packet_count", 0) for f in f_list)
        total_syn = sum(f.get("syn_count", 0) for f in f_list)
        syn_only_flows = sum(1 for f in f_list if f.get("is_syn_only"))
        
        start_ts = min(f.get("start_time", 0.0) for f in f_list)
        end_ts = max(f.get("end_time", 0.0) for f in f_list)
        duration = max(0.01, end_ts - start_ts)
        avg_flow_dur = sum(f.get("duration", 0.0) for f in f_list) / len(f_list) if f_list else 0.0
        
        syn_ratio = (total_syn / total_src_packets) if total_src_packets > 0 else 0.0
        
        # Filter out server response traffic where source port is a well-known service daemon (< 1024)
        service_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080}
        src_service_flows = sum(1 for f in f_list if f.get("src_port") in service_ports or (f.get("src_port") and f.get("src_port") < 1024))
        if src_service_flows > len(f_list) * 0.6:
            # Server responding from service port back to multiple client ephemeral ports
            continue

        # Detection Thresholds:
        # 1. Broad scan: >= 15 unique destination ports
        # 2. Targeted/stealth scan: >= 8 ports with high SYN ratio (>= 0.50)
        is_scan = (unique_ports >= 15) or (unique_ports >= 8 and syn_ratio >= 0.5)
        
        if is_scan:
            # Calculate evidence-based confidence
            # Port factor (0.45), SYN factor (0.35), Speed/duration factor (0.20)
            port_factor = min(1.0, unique_ports / 35.0)
            syn_factor = min(1.0, syn_ratio)
            speed_factor = min(1.0, 1.0 / (avg_flow_dur + 0.15))
            
            raw_conf = (0.45 * port_factor) + (0.35 * syn_factor) + (0.20 * speed_factor)
            confidence = round(max(0.65, min(0.98, raw_conf)), 2)
            
            severity = "CRITICAL" if unique_ports >= 50 or (unique_ports >= 25 and syn_ratio > 0.8) else "HIGH"
            
            evidence = [
                f"Source host {src_ip} contacted {unique_ports} unique destination ports.",
                f"{total_syn} SYN probe packets observed ({round(syn_ratio * 100, 1)}% of source traffic).",
                f"{syn_only_flows} connections were one-way / unsuccessful without completed handshakes.",
                f"Scanning activity concentrated within {round(duration, 2)} seconds (avg flow duration: {round(avg_flow_dur, 3)}s)."
            ]
            
            candidate = {
                "threat": "Port Scan",
                "severity": severity,
                "confidence": confidence,
                "evidence": evidence,
                "attacker_ip": src_ip,
                "unique_ports": unique_ports,
                "syn_count": total_syn,
                "duration": round(duration, 2),
                "avg_flow_duration": round(avg_flow_dur, 3)
            }
            
            if not best_candidate or candidate["unique_ports"] > best_candidate["unique_ports"]:
                best_candidate = candidate
                
    return best_candidate
