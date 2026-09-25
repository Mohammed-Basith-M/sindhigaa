"""
CyberShield Flow Extraction Engine
Extracts 5-tuple network flows from parsed packets:
(src_ip, dst_ip, src_port, dst_port, protocol)
Computes duration, rates, flag counts, and handshake metrics.
"""

from typing import List, Dict, Any

def extract_flows(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups packets into 5-tuple network flows and calculates flow statistics.
    """
    flows_map: Dict[str, Dict[str, Any]] = {}
    
    for pkt in packets:
        src_ip = pkt.get("src_ip") or "unknown"
        dst_ip = pkt.get("dst_ip") or "unknown"
        src_port = pkt.get("src_port") or 0
        dst_port = pkt.get("dst_port") or 0
        protocol = pkt.get("protocol") or "OTHER"
        ts = pkt.get("timestamp", 0.0)
        pkt_len = pkt.get("length", 0)
        payload_len = pkt.get("payload_len", 0)
        tcp_flags = pkt.get("tcp_flags", {})
        
        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}#{protocol}"
        
        if flow_key not in flows_map:
            flows_map[flow_key] = {
                "flow_id": flow_key,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "packet_count": 0,
                "byte_count": 0,
                "payload_bytes": 0,
                "start_time": ts,
                "end_time": ts,
                "duration": 0.0,
                "syn_count": 0,
                "ack_count": 0,
                "fin_count": 0,
                "rst_count": 0,
                "packets_per_sec": 0.0,
                "bytes_per_sec": 0.0,
                "is_syn_only": False,
                "has_payload": False
            }
            
        f = flows_map[flow_key]
        f["packet_count"] += 1
        f["byte_count"] += pkt_len
        f["payload_bytes"] += payload_len
        if ts < f["start_time"] or f["start_time"] == 0.0:
            f["start_time"] = ts
        if ts > f["end_time"]:
            f["end_time"] = ts
            
        if tcp_flags.get("SYN"):
            f["syn_count"] += 1
        if tcp_flags.get("ACK"):
            f["ack_count"] += 1
        if tcp_flags.get("FIN"):
            f["fin_count"] += 1
        if tcp_flags.get("RST"):
            f["rst_count"] += 1
            
        if payload_len > 0:
            f["has_payload"] = True
            
    # Calculate final derived metrics
    result_flows = []
    for f in flows_map.values():
        duration = max(0.0, f["end_time"] - f["start_time"])
        f["duration"] = round(duration, 4)
        
        # Effective duration for rates (avoid division by 0)
        effective_dur = duration if duration > 0.001 else 0.001
        f["packets_per_sec"] = round(f["packet_count"] / effective_dur, 2)
        f["bytes_per_sec"] = round(f["byte_count"] / effective_dur, 2)
        
        f["is_syn_only"] = (f["syn_count"] > 0 and f["ack_count"] == 0 and f["payload_bytes"] == 0)
        result_flows.append(f)
        
    return result_flows
