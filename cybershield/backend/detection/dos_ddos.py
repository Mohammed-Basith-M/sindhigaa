"""
CyberShield DoS / DDoS Detection Module
Identifies packet velocity anomalies, target destination concentration, and volumetric flood patterns.
Calculates transparent evidence-based confidence metrics.
"""

from typing import List, Dict, Any, Optional
from collections import Counter

def detect_dos_ddos(
    packets: List[Dict[str, Any]], 
    flows: List[Dict[str, Any]], 
    features: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Evaluates volumetric indicators:
    - High packet transmission velocity (> 50 pkt/s)
    - High traffic concentration directed at a single destination IP (>= 60%)
    - SYN flood or UDP/ICMP flood patterns
    """
    if len(packets) < 15:
        return None
        
    summary = features.get("summary", {})
    total_packets = summary.get("total_packets", len(packets))
    duration = summary.get("duration_seconds", 0.0)
    pps = summary.get("packets_per_second", 0.0)
    bps = summary.get("bytes_per_second", 0.0)
    
    # Destination concentration analysis
    dst_counter = Counter(p.get("dst_ip") for p in packets if p.get("dst_ip"))
    if not dst_counter:
        return None
        
    target_ip, target_count = dst_counter.most_common(1)[0]
    concentration_ratio = target_count / total_packets if total_packets > 0 else 0.0
    
    # Check TCP SYN flood behavior against the target
    target_packets = [p for p in packets if p.get("dst_ip") == target_ip]
    target_syns = sum(1 for p in target_packets if p.get("tcp_flags", {}).get("SYN") and not p.get("tcp_flags", {}).get("ACK"))
    syn_ratio = (target_syns / len(target_packets)) if target_packets else 0.0
    
    # Target-specific rate
    target_pps = round(len(target_packets) / max(0.01, duration), 1)
    
    # DoS Condition:
    # 1. High rate (> 50 pkt/s) AND high concentration (>= 60% of total packets)
    # OR 2. High SYN flood ratio (>= 65% SYN) against a single target with >= 30 packets
    is_dos = (target_pps >= 50.0 and concentration_ratio >= 0.60) or (syn_ratio >= 0.65 and len(target_packets) >= 30)
    
    if is_dos:
        # Calculate evidence-based confidence
        rate_factor = min(1.0, target_pps / 120.0)
        conc_factor = concentration_ratio
        syn_factor = syn_ratio
        
        raw_conf = (0.40 * rate_factor) + (0.35 * conc_factor) + (0.25 * syn_factor)
        confidence = round(max(0.68, min(0.99, raw_conf)), 2)
        
        severity = "CRITICAL" if target_pps >= 150.0 or syn_ratio >= 0.85 else "HIGH"
        
        attack_subtype = "SYN Flood DoS" if syn_ratio >= 0.5 else "Volumetric Traffic Flood"
        
        evidence = [
            f"Abnormal packet transmission velocity: {target_pps} packets/second focused on target {target_ip}.",
            f"{target_count} packets ({round(concentration_ratio * 100, 1)}% of entire capture) directed at single host {target_ip}.",
            f"{target_syns} SYN requests recorded with negligible connection completions ({round(syn_ratio * 100, 1)}% of target traffic).",
            f"Traffic volume sustained over {round(duration, 2)} seconds at {round(bps / 1024, 2)} KB/s throughput."
        ]
        
        return {
            "threat": "DoS/DDoS",
            "subtype": attack_subtype,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "target_ip": target_ip,
            "target_pps": target_pps,
            "concentration_pct": round(concentration_ratio * 100, 1),
            "syn_count": target_syns
        }
        
    return None
