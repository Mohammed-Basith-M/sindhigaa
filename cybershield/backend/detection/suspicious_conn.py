"""
CyberShield Suspicious Connection Detection Module
Detects traffic engaging known backdoor, trojan, exploitation listeners, and high-risk control ports.
"""

from typing import List, Dict, Any, Optional

HIGH_RISK_PORTS = {
    4444: "Metasploit Default Listener / Reverse Shell",
    31337: "Back Orifice Trojan",
    12345: "NetBus Trojan",
    5555: "Exposed Android Debug Bridge (ADB)",
    6667: "IRC Botnet Control Channel",
    9001: "Tor / Custom Relay Port"
}

def detect_suspicious_conn(
    packets: List[Dict[str, Any]], 
    flows: List[Dict[str, Any]], 
    features: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Scans flows and packets for active engagement with high-risk backdoor/trojan ports.
    """
    for f in flows:
        dst_port = f.get("dst_port")
        src_port = f.get("src_port")
        
        target_port = None
        desc = None
        
        if dst_port in HIGH_RISK_PORTS:
            target_port = dst_port
            desc = HIGH_RISK_PORTS[dst_port]
        elif src_port in HIGH_RISK_PORTS:
            target_port = src_port
            desc = HIGH_RISK_PORTS[src_port]
            
        if target_port:
            pkt_count = f.get("packet_count", 1)
            sip = f.get("src_ip")
            dip = f.get("dst_ip")
            proto = f.get("protocol", "TCP")
            
            evidence = [
                f"Observed network traffic engaging known suspicious port {target_port} ({desc}).",
                f"Communication between {sip} and {dip} over {proto} ({pkt_count} packet(s)).",
                f"Port {target_port} is associated with exploitation frameworks or unauthorized remote access.",
                "Non-standard protocol activity observed on administrative or trojan listening port."
            ]
            
            return {
                "threat": "Suspicious Connection",
                "severity": "HIGH" if pkt_count >= 5 else "MEDIUM",
                "confidence": 0.85 if pkt_count >= 5 else 0.72,
                "evidence": evidence,
                "src_ip": sip,
                "dst_ip": dip,
                "port": target_port,
                "description": desc
            }
            
    return None
