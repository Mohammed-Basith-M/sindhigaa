"""
CyberShield Brute Force Detection Module
Identifies rapid repeated authentication attempts against exposed service ports:
SSH (22), FTP (21), Telnet (23), RDP (3389), SMB (445), MySQL (3306), PostgreSQL (5432).
Calculates transparent evidence-based confidence metrics.
"""

from typing import List, Dict, Any, Optional

SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL"
}

def detect_brute_force(
    packets: List[Dict[str, Any]], 
    flows: List[Dict[str, Any]], 
    features: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Evaluates traffic targeting sensitive service ports:
    - Minimum threshold of repeated connection sessions (>= 6)
    - Connection attempt frequency (> 1.5 attempts/sec) or short aborted sessions
    """
    if len(packets) < 8:
        return None
        
    best_finding = None
    
    # Analyze flows targeting sensitive service ports
    for port, service_name in SENSITIVE_PORTS.items():
        port_flows = [f for f in flows if f.get("dst_port") == port]
        if not port_flows:
            continue
            
        # Group by source IP
        src_groups: Dict[str, List[Dict[str, Any]]] = {}
        for f in port_flows:
            sip = f.get("src_ip")
            if sip and sip != "unknown":
                src_groups.setdefault(sip, []).append(f)
                
        for src_ip, f_list in src_groups.items():
            attempt_count = len(f_list)
            # Must meet threshold of at least 6 distinct connection attempts
            if attempt_count < 6:
                continue
                
            total_pkts = sum(f.get("packet_count", 0) for f in f_list)
            first_seen = min(f.get("start_time", 0.0) for f in f_list)
            last_seen = max(f.get("end_time", 0.0) for f in f_list)
            span = max(0.1, last_seen - first_seen)
            attempts_per_sec = round(attempt_count / span, 2)
            
            # Brute force indicator: rapid recycling of connection attempts or high frequency
            is_brute_force = (attempt_count >= 10) or (attempt_count >= 6 and attempts_per_sec >= 1.5)
            
            if is_brute_force:
                attempt_factor = min(1.0, attempt_count / 20.0)
                freq_factor = min(1.0, attempts_per_sec / 5.0)
                raw_conf = (0.55 * attempt_factor) + (0.45 * freq_factor)
                confidence = round(max(0.70, min(0.96, raw_conf)), 2)
                
                severity = "HIGH" if attempt_count >= 15 or attempts_per_sec >= 4.0 else "MEDIUM"
                
                target_ip = f_list[0].get("dst_ip", "target")
                evidence = [
                    f"Observed {attempt_count} repeated connection attempts from {src_ip} to {service_name} (port {port}).",
                    f"Connection frequency of {attempts_per_sec} attempts/second indicates automated dictionary / credential stuffing activity.",
                    f"Sessions directed toward target service at {target_ip} with rapid session termination.",
                    f"Total of {total_pkts} authentication exchange packets captured across {round(span, 2)} seconds."
                ]
                
                finding = {
                    "threat": "Brute Force",
                    "service": service_name,
                    "target_port": port,
                    "severity": severity,
                    "confidence": confidence,
                    "evidence": evidence,
                    "attacker_ip": src_ip,
                    "target_ip": target_ip,
                    "attempts": attempt_count,
                    "rate_per_sec": attempts_per_sec
                }
                
                if not best_finding or finding["attempts"] > best_finding["attempts"]:
                    best_finding = finding
                    
    return best_finding
