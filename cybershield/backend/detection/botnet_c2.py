"""
CyberShield Botnet / C2 Communication Detection Module
Identifies periodic beaconing heartbeats and low-jitter repetitive outbound connections.
Calculates transparent evidence-based confidence metrics.
"""

from typing import List, Dict, Any, Optional
import math

def detect_botnet_c2(
    packets: List[Dict[str, Any]], 
    flows: List[Dict[str, Any]], 
    features: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Evaluates periodic beaconing characteristics:
    - Multiple periodic sessions between host pairs (>= 5 sessions)
    - Low coefficient of variation (CV = std_dev / mean < 0.28) of inter-arrival intervals
    - Recurring heartbeat intervals (e.g. every ~1s, 5s, 10s, 30s, 60s)
    """
    if len(packets) < 10:
        return None
        
    # Group timestamps by (src_ip, dst_ip)
    pair_timestamps: Dict[tuple, List[float]] = {}
    for p in packets:
        sip = p.get("src_ip")
        dip = p.get("dst_ip")
        ts = p.get("timestamp")
        if sip and dip and ts is not None and sip != dip:
            pair_timestamps.setdefault((sip, dip), []).append(ts)
            
    best_candidate = None
    
    for (sip, dip), ts_list in pair_timestamps.items():
        if len(ts_list) < 5:
            continue
            
        ts_sorted = sorted(ts_list)
        # Compute inter-arrival times
        intervals = [ts_sorted[i] - ts_sorted[i-1] for i in range(1, len(ts_sorted))]
        intervals = [inv for inv in intervals if inv > 0.05] # Filter sub-bursts
        
        if len(intervals) < 4:
            continue
            
        mean_inv = sum(intervals) / len(intervals)
        if mean_inv < 0.4: # Skip high-speed continuous streams (handled by DoS/brute-force)
            continue
            
        variance = sum((x - mean_inv) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean_inv if mean_inv > 0 else 1.0
        
        # Periodic beaconing heuristic: low jitter across multiple sessions
        if cv < 0.28 and len(intervals) >= 4:
            jitter_factor = max(0.0, 1.0 - (cv / 0.28))
            session_factor = min(1.0, len(intervals) / 10.0)
            raw_conf = (0.55 * jitter_factor) + (0.45 * session_factor)
            confidence = round(max(0.65, min(0.92, raw_conf)), 2)
            
            evidence = [
                f"Periodic beaconing telemetry observed between internal host {sip} and {dip}.",
                f"{len(ts_list)} polling sessions recorded with low inter-arrival jitter (std dev: {round(std_dev, 3)}s).",
                f"Mean beacon interval: {round(mean_inv, 2)} seconds (coefficient of variation: {round(cv, 2)}).",
                f"Communication pattern consistent with automated Command & Control (C2) heartbeat activity."
            ]
            
            candidate = {
                "threat": "Possible Botnet/C2",
                "severity": "HIGH" if len(ts_list) >= 12 else "MEDIUM",
                "confidence": confidence,
                "evidence": evidence,
                "internal_host": sip,
                "remote_host": dip,
                "mean_interval_sec": round(mean_inv, 2),
                "sessions_count": len(ts_list),
                "jitter_cv": round(cv, 3)
            }
            
            if not best_candidate or candidate["sessions_count"] > best_candidate["sessions_count"]:
                best_candidate = candidate
                
    return best_candidate
