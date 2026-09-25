"""
CyberShield Feature Extraction Engine
Extracts comprehensive telemetry and statistical distributions directly from parsed packets.
Calculates protocol counts, top talkers, port frequencies, traffic velocity, and timeline series.
"""

from typing import List, Dict, Any
from collections import Counter
import math

COMMON_SERVICES = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    4444: "Metasploit",
    31337: "BackOrifice",
    12345: "NetBus"
}

def extract_features(packets: List[Dict[str, Any]], flows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes real summary metrics, distributions, top IPs, ports, and timeline slices.
    """
    if not packets:
        return {
            "summary": {
                "total_packets": 0,
                "total_bytes": 0,
                "total_flows": 0,
                "duration_seconds": 0.0,
                "start_time": 0.0,
                "end_time": 0.0,
                "avg_packet_size": 0.0,
                "packets_per_second": 0.0,
                "bytes_per_second": 0.0
            },
            "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0},
            "top_source_ips": [],
            "top_destination_ips": [],
            "top_ports": [],
            "top_source_ports": [],
            "unique_source_ips": 0,
            "unique_destination_ips": 0,
            "unique_destination_ports": 0,
            "packet_size_distribution": {"<128B": 0, "128-512B": 0, "512-1024B": 0, ">1024B": 0},
            "timeline": []
        }
        
    total_packets = len(packets)
    total_bytes = sum(pkt.get("length", 0) for pkt in packets)
    timestamps = [pkt.get("timestamp", 0.0) for pkt in packets if pkt.get("timestamp") is not None]
    
    start_time = min(timestamps) if timestamps else 0.0
    end_time = max(timestamps) if timestamps else 0.0
    duration_seconds = max(0.0, end_time - start_time)
    
    effective_duration = duration_seconds if duration_seconds > 0.001 else 0.001
    packets_per_sec = round(total_packets / effective_duration, 2)
    bytes_per_sec = round(total_bytes / effective_duration, 2)
    avg_packet_size = round(total_bytes / total_packets, 2) if total_packets > 0 else 0.0
    
    # Protocol distribution
    proto_counter = Counter(pkt.get("protocol", "OTHER") for pkt in packets)
    protocols = {
        "TCP": proto_counter.get("TCP", 0),
        "UDP": proto_counter.get("UDP", 0),
        "ICMP": proto_counter.get("ICMP", 0),
        "OTHER": proto_counter.get("OTHER", 0)
    }
    
    # IP information
    src_ips = [pkt.get("src_ip") for pkt in packets if pkt.get("src_ip")]
    dst_ips = [pkt.get("dst_ip") for pkt in packets if pkt.get("dst_ip")]
    src_ip_counter = Counter(src_ips)
    dst_ip_counter = Counter(dst_ips)
    
    top_src_ips = []
    for ip, count in src_ip_counter.most_common(10):
        # Calculate bytes from this IP
        ip_bytes = sum(p.get("length", 0) for p in packets if p.get("src_ip") == ip)
        percentage = round((count / total_packets) * 100, 1)
        top_src_ips.append({
            "ip": ip,
            "count": count,
            "bytes": ip_bytes,
            "percentage": percentage
        })
        
    top_dst_ips = []
    for ip, count in dst_ip_counter.most_common(10):
        ip_bytes = sum(p.get("length", 0) for p in packets if p.get("dst_ip") == ip)
        percentage = round((count / total_packets) * 100, 1)
        top_dst_ips.append({
            "ip": ip,
            "count": count,
            "bytes": ip_bytes,
            "percentage": percentage
        })
        
    # Ports information
    dst_ports = [pkt.get("dst_port") for pkt in packets if pkt.get("dst_port")]
    src_ports = [pkt.get("src_port") for pkt in packets if pkt.get("src_port")]
    dst_port_counter = Counter(dst_ports)
    src_port_counter = Counter(src_ports)
    
    top_ports = []
    for port, count in dst_port_counter.most_common(10):
        service = COMMON_SERVICES.get(port, "Unknown")
        percentage = round((count / total_packets) * 100, 1)
        top_ports.append({
            "port": port,
            "service": service,
            "label": f"{port} ({service})",
            "count": count,
            "percentage": percentage
        })
        
    top_src_ports = []
    for port, count in src_port_counter.most_common(5):
        top_src_ports.append({"port": port, "count": count})
        
    # Packet size distribution
    size_dist = {"<128B": 0, "128-512B": 0, "512-1024B": 0, ">1024B": 0}
    for pkt in packets:
        l = pkt.get("length", 0)
        if l < 128:
            size_dist["<128B"] += 1
        elif l <= 512:
            size_dist["128-512B"] += 1
        elif l <= 1024:
            size_dist["512-1024B"] += 1
        else:
            size_dist[">1024B"] += 1
            
    # Timeline generation (bin into 10-25 slices across duration)
    num_bins = min(20, max(5, int(math.ceil(duration_seconds)))) if duration_seconds > 0 else 5
    bin_size = duration_seconds / num_bins if duration_seconds > 0 else 1.0
    timeline = []
    
    for i in range(num_bins):
        bin_start = start_time + (i * bin_size)
        bin_end = bin_start + bin_size
        
        bin_pkts = [p for p in packets if bin_start <= p.get("timestamp", 0.0) < (bin_end if i < num_bins - 1 else bin_end + 0.0001)]
        pkt_cnt = len(bin_pkts)
        byte_cnt = sum(p.get("length", 0) for p in bin_pkts)
        tcp_cnt = sum(1 for p in bin_pkts if p.get("protocol") == "TCP")
        udp_cnt = sum(1 for p in bin_pkts if p.get("protocol") == "UDP")
        
        # Relative time offset label
        offset_sec = round(i * bin_size, 1)
        timeline.append({
            "time_offset": f"+{offset_sec}s",
            "packets": pkt_cnt,
            "bytes": byte_cnt,
            "tcp": tcp_cnt,
            "udp": udp_cnt,
            "timestamp": round(bin_start, 2)
        })
        
    return {
        "summary": {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_flows": len(flows),
            "duration_seconds": round(duration_seconds, 2),
            "start_time": round(start_time, 2),
            "end_time": round(end_time, 2),
            "avg_packet_size": avg_packet_size,
            "packets_per_second": packets_per_sec,
            "bytes_per_second": bytes_per_sec
        },
        "protocols": protocols,
        "top_source_ips": top_src_ips,
        "top_destination_ips": top_dst_ips,
        "top_ports": top_ports,
        "top_source_ports": top_src_ports,
        "unique_source_ips": len(src_ip_counter),
        "unique_destination_ips": len(dst_ip_counter),
        "unique_destination_ports": len(dst_port_counter),
        "packet_size_distribution": size_dist,
        "timeline": timeline
    }
