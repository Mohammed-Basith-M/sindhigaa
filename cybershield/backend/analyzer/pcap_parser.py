"""
CyberShield PCAP / PCAPNG Parser
Supports both standard .pcap and .pcapng binary formats.
Extracts Layer 2, Layer 3 (IPv4, IPv6), and Layer 4 (TCP, UDP, ICMP) metadata.
Optional Scapy fallback if Scapy is installed.
"""

import os
import struct
import socket
from typing import List, Dict, Any, Tuple, Optional

# Link layer types
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP = 12
LINKTYPE_RAW_IP_ALT = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

def parse_pcap(filepath: str, max_packets: int = 50000) -> List[Dict[str, Any]]:
    """
    Main entry point for parsing .pcap and .pcapng files.
    Returns a list of packet dictionaries.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    file_size = os.path.getsize(filepath)
    if file_size == 0:
        raise ValueError("The uploaded PCAP file is empty (0 bytes).")
    
    # Try using Scapy if available and preferred
    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP
        scapy_packets = _parse_with_scapy(filepath, max_packets)
        if scapy_packets:
            return scapy_packets
    except Exception:
        # Fall back to native binary parser
        pass
    
    # Native binary parser
    with open(filepath, "rb") as f:
        magic = f.read(4)
        if len(magic) < 4:
            raise ValueError("Corrupted PCAP file: Insufficient header bytes.")
        
        # Check classic PCAP magic numbers
        if magic in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1'):
            f.seek(0)
            return _parse_classic_pcap(f, max_packets)
        
        # Check PCAPNG magic number (Section Header Block 0x0A0D0D0A)
        elif magic == b'\n\r\r\n':
            f.seek(0)
            return _parse_pcapng(f, max_packets)
        
        else:
            raise ValueError(
                "Invalid PCAP file header. The file format is not a recognized .pcap or .pcapng format."
            )

def _parse_with_scapy(filepath: str, max_packets: int) -> List[Dict[str, Any]]:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP
    scapy_pkts = rdpcap(filepath)
    packets = []
    
    for idx, pkt in enumerate(scapy_pkts):
        if idx >= max_packets:
            break
        
        pkt_dict: Dict[str, Any] = {
            "index": idx + 1,
            "timestamp": float(pkt.time),
            "length": len(pkt),
            "protocol": "OTHER",
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "tcp_flags": {},
            "payload_len": 0,
            "icmp_type": None,
            "icmp_code": None
        }
        
        if pkt.haslayer(IP):
            pkt_dict["src_ip"] = pkt[IP].src
            pkt_dict["dst_ip"] = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            pkt_dict["src_ip"] = pkt[IPv6].src
            pkt_dict["dst_ip"] = pkt[IPv6].dst
            
        if pkt.haslayer(TCP):
            pkt_dict["protocol"] = "TCP"
            pkt_dict["src_port"] = pkt[TCP].sport
            pkt_dict["dst_port"] = pkt[TCP].dport
            flags = pkt[TCP].flags
            pkt_dict["tcp_flags"] = {
                "SYN": bool(flags & 0x02),
                "ACK": bool(flags & 0x10),
                "FIN": bool(flags & 0x01),
                "RST": bool(flags & 0x04),
                "PSH": bool(flags & 0x08),
                "URG": bool(flags & 0x20)
            }
            if hasattr(pkt[TCP], 'payload') and pkt[TCP].payload:
                pkt_dict["payload_len"] = len(bytes(pkt[TCP].payload))
        elif pkt.haslayer(UDP):
            pkt_dict["protocol"] = "UDP"
            pkt_dict["src_port"] = pkt[UDP].sport
            pkt_dict["dst_port"] = pkt[UDP].dport
            if hasattr(pkt[UDP], 'payload') and pkt[UDP].payload:
                pkt_dict["payload_len"] = len(bytes(pkt[UDP].payload))
        elif pkt.haslayer(ICMP):
            pkt_dict["protocol"] = "ICMP"
            pkt_dict["icmp_type"] = pkt[ICMP].type
            pkt_dict["icmp_code"] = pkt[ICMP].code
            
        packets.append(pkt_dict)
        
    return packets

def _parse_classic_pcap(f, max_packets: int) -> List[Dict[str, Any]]:
    hdr_bytes = f.read(24)
    if len(hdr_bytes) < 24:
        raise ValueError("Corrupted PCAP file: Global header incomplete.")
    
    magic = hdr_bytes[:4]
    if magic == b'\xa1\xb2\xc3\xd4':
        endian = '>'
        nano = False
    elif magic == b'\xd4\xc3\xb2\xa1':
        endian = '<'
        nano = False
    elif magic == b'\xa1\xb2\x3c\x4d':
        endian = '>'
        nano = True
    elif magic == b'\x4d\x3c\xb2\xa1':
        endian = '<'
        nano = True
    else:
        raise ValueError("Invalid magic byte signature.")
        
    _, _, _, _, _, link_type = struct.unpack(f"{endian}HHIIII", hdr_bytes[4:])
    
    packets = []
    pkt_index = 0
    
    while pkt_index < max_packets:
        pkt_hdr = f.read(16)
        if not pkt_hdr or len(pkt_hdr) < 16:
            break
            
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
        data = f.read(incl_len)
        if len(data) < incl_len:
            break
            
        pkt_index += 1
        ts = ts_sec + (ts_usec / 1e9 if nano else ts_usec / 1e6)
        
        parsed = _decode_packet_bytes(data, link_type)
        parsed["index"] = pkt_index
        parsed["timestamp"] = ts
        parsed["length"] = orig_len if orig_len > 0 else incl_len
        packets.append(parsed)
        
    if not packets:
        raise ValueError("PCAP contains no valid packet records.")
        
    return packets

def _parse_pcapng(f, max_packets: int) -> List[Dict[str, Any]]:
    packets = []
    pkt_index = 0
    endian = '<'
    ts_resolutions = {}  # interface_id -> resolution multiplier
    link_types = {}      # interface_id -> link_type
    current_if_id = 0
    
    while pkt_index < max_packets:
        block_hdr = f.read(8)
        if not block_hdr or len(block_hdr) < 8:
            break
            
        block_type, block_len = struct.unpack(f"{endian}II", block_hdr)
        
        # Section Header Block (check endianness)
        if block_type == 0x0A0D0D0A:
            body = f.read(block_len - 8)
            if len(body) >= 4:
                bom = body[:4]
                if bom == b'\x1a\x2b\x3c\x4d':
                    endian = '>'
                else:
                    endian = '<'
            continue
            
        # Interface Description Block
        if block_type == 0x00000001:
            body = f.read(block_len - 8)
            if len(body) >= 4:
                link_type, _ = struct.unpack(f"{endian}HH", body[:4])
                link_types[current_if_id] = link_type
                ts_resolutions[current_if_id] = 1e6 # default 10^-6 microsecond
                
                # Check options for timestamp resolution (if_tsresol = 9)
                opt_offset = 8
                while opt_offset + 4 <= len(body) - 4:
                    opt_code, opt_len = struct.unpack(f"{endian}HH", body[opt_offset:opt_offset+4])
                    if opt_code == 0:
                        break
                    if opt_code == 9 and opt_len >= 1 and opt_offset + 4 + opt_len <= len(body):
                        res_val = body[opt_offset+4]
                        if res_val & 0x80:
                            # 2^-x
                            ts_resolutions[current_if_id] = 2.0 ** (res_val & 0x7F)
                        else:
                            # 10^-x
                            ts_resolutions[current_if_id] = 10.0 ** res_val
                    padding = (4 - (opt_len % 4)) % 4
                    opt_offset += 4 + opt_len + padding
                current_if_id += 1
            continue
            
        # Enhanced Packet Block
        if block_type == 0x00000006:
            body = f.read(block_len - 8)
            if len(body) >= 20:
                if_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(f"{endian}IIIII", body[:20])
                pkt_data = body[20:20 + cap_len]
                
                raw_ts = (ts_high << 32) | ts_low
                resol = ts_resolutions.get(if_id, 1e6)
                ts = raw_ts / resol
                
                l_type = link_types.get(if_id, LINKTYPE_ETHERNET)
                parsed = _decode_packet_bytes(pkt_data, l_type)
                
                pkt_index += 1
                parsed["index"] = pkt_index
                parsed["timestamp"] = ts
                parsed["length"] = orig_len if orig_len > 0 else cap_len
                packets.append(parsed)
            continue
            
        # Simple Packet Block
        if block_type == 0x00000003:
            body = f.read(block_len - 8)
            if len(body) >= 4:
                orig_len, = struct.unpack(f"{endian}I", body[:4])
                cap_len = min(orig_len, len(body) - 8)
                pkt_data = body[4:4 + cap_len]
                
                l_type = link_types.get(0, LINKTYPE_ETHERNET)
                parsed = _decode_packet_bytes(pkt_data, l_type)
                
                pkt_index += 1
                parsed["index"] = pkt_index
                parsed["timestamp"] = float(pkt_index)
                parsed["length"] = orig_len
                packets.append(parsed)
            continue
            
        # Any other block type: skip body
        f.seek(block_len - 8, os.SEEK_CUR)
        
    if not packets:
        raise ValueError("PCAPNG contains no valid packet records.")
        
    return packets

def _decode_packet_bytes(data: bytes, link_type: int) -> Dict[str, Any]:
    """
    Decodes packet layers from raw bytes.
    Handles Ethernet, Linux Cooked SLL/SLL2, Raw IP, IPv4, IPv6, TCP, UDP, ICMP.
    """
    res: Dict[str, Any] = {
        "protocol": "OTHER",
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "tcp_flags": {},
        "payload_len": 0,
        "icmp_type": None,
        "icmp_code": None
    }
    
    if not data:
        return res
        
    l3_data = b""
    ethertype = None
    
    # Layer 2 decoding
    if link_type == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return res
        ethertype, = struct.unpack("!H", data[12:14])
        l3_offset = 14
        
        # 802.1Q VLAN
        if ethertype == 0x8100 and len(data) >= 18:
            ethertype, = struct.unpack("!H", data[16:18])
            l3_offset = 18
            
        l3_data = data[l3_offset:]
        
    elif link_type in (LINKTYPE_RAW_IP, LINKTYPE_RAW_IP_ALT):
        l3_data = data
        if len(data) > 0:
            version = (data[0] >> 4) & 0x0F
            if version == 4:
                ethertype = 0x0800
            elif version == 6:
                ethertype = 0x86DD
                
    elif link_type == LINKTYPE_LINUX_SLL:
        if len(data) >= 16:
            ethertype, = struct.unpack("!H", data[14:16])
            l3_data = data[16:]
            
    elif link_type == LINKTYPE_LINUX_SLL2:
        if len(data) >= 20:
            ethertype, = struct.unpack("!H", data[0:2])
            l3_data = data[20:]
            
    elif link_type == LINKTYPE_NULL:
        if len(data) >= 4:
            family, = struct.unpack("=I", data[:4])
            if family == 2:  # AF_INET
                ethertype = 0x0800
            elif family in (24, 28, 30): # AF_INET6
                ethertype = 0x86DD
            l3_data = data[4:]
    else:
        # Try raw IP fallback
        if len(data) > 0:
            version = (data[0] >> 4) & 0x0F
            if version == 4:
                ethertype = 0x0800
                l3_data = data
            elif version == 6:
                ethertype = 0x86DD
                l3_data = data
                
    # Layer 3 decoding
    l4_proto = None
    l4_data = b""
    
    if ethertype == 0x0800 and len(l3_data) >= 20:
        # IPv4
        v_ihl = l3_data[0]
        ihl = (v_ihl & 0x0F) * 4
        if len(l3_data) >= ihl:
            l4_proto = l3_data[9]
            res["src_ip"] = socket.inet_ntoa(l3_data[12:16])
            res["dst_ip"] = socket.inet_ntoa(l3_data[16:20])
            l4_data = l3_data[ihl:]
            
    elif ethertype == 0x86DD and len(l3_data) >= 40:
        # IPv6
        l4_proto = l3_data[6]
        res["src_ip"] = socket.inet_ntop(socket.AF_INET6, l3_data[8:24])
        res["dst_ip"] = socket.inet_ntop(socket.AF_INET6, l3_data[24:40])
        l4_data = l3_data[40:]
        
    # Layer 4 decoding
    if l4_proto == 6 and len(l4_data) >= 20:
        # TCP
        res["protocol"] = "TCP"
        res["src_port"], res["dst_port"] = struct.unpack("!HH", l4_data[:4])
        data_offset = ((l4_data[12] >> 4) & 0x0F) * 4
        flags_byte = l4_data[13]
        res["tcp_flags"] = {
            "SYN": bool(flags_byte & 0x02),
            "ACK": bool(flags_byte & 0x10),
            "FIN": bool(flags_byte & 0x01),
            "RST": bool(flags_byte & 0x04),
            "PSH": bool(flags_byte & 0x08),
            "URG": bool(flags_byte & 0x20)
        }
        if len(l4_data) >= data_offset:
            res["payload_len"] = len(l4_data[data_offset:])
            
    elif l4_proto == 17 and len(l4_data) >= 8:
        # UDP
        res["protocol"] = "UDP"
        res["src_port"], res["dst_port"], udp_len = struct.unpack("!HHH", l4_data[:6])
        res["payload_len"] = max(0, len(l4_data) - 8)
        
    elif l4_proto == 1 and len(l4_data) >= 2:
        # ICMP
        res["protocol"] = "ICMP"
        res["icmp_type"] = l4_data[0]
        res["icmp_code"] = l4_data[1]
        res["payload_len"] = max(0, len(l4_data) - 8)
        
    elif l4_proto == 58 and len(l4_data) >= 2:
        # ICMPv6
        res["protocol"] = "ICMP"
        res["icmp_type"] = l4_data[0]
        res["icmp_code"] = l4_data[1]
        
    return res
