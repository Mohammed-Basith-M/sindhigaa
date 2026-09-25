"""
CyberShield Test PCAP Synthesizer
Generates real binary .pcap and .pcapng files representing different network traffic scenarios.
"""

import os
import struct
import socket

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'test_files'))
os.makedirs(OUTPUT_DIR, exist_ok=True)

def create_pcap_global_header(nano=False) -> bytes:
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    return struct.pack('>IHHiIII', magic, 2, 4, 0, 0, 65535, 1) # LinkType Ethernet (1)

def create_ethernet_ip_tcp_packet(
    src_ip: str, dst_ip: str, 
    src_port: int, dst_port: int, 
    flags: int = 0x02, # SYN default
    payload: bytes = b"",
    ts: float = 1727270000.0
) -> bytes:
    # 1. TCP Header
    # src_port, dst_port, seq, ack, offset_flags, window, checksum, urgent
    seq = 1000
    ack = 0
    data_offset = 5 # 20 bytes
    offset_flags = (data_offset << 12) | flags
    tcp_hdr = struct.pack('!HHIIHHHH', src_port, dst_port, seq, ack, offset_flags, 64240, 0, 0)
    
    # 2. IPv4 Header
    # v_ihl, dscp_ecn, total_length, id, flags_fragment, ttl, proto, checksum, src_ip, dst_ip
    v_ihl = (4 << 4) | 5
    proto = 6 # TCP
    total_len = 20 + 20 + len(payload)
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    ip_hdr = struct.pack('!BBHHHBBH4s4s', v_ihl, 0, total_len, 54321, 0x4000, 64, proto, 0, src_bytes, dst_bytes)
    
    # 3. Ethernet Header (14 bytes)
    # dst_mac (6), src_mac (6), ethertype (2: 0x0800 for IPv4)
    eth_hdr = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00'
    
    raw_packet = eth_hdr + ip_hdr + tcp_hdr + payload
    
    # PCAP record header: ts_sec, ts_usec, incl_len, orig_len
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1e6)
    incl_len = len(raw_packet)
    rec_hdr = struct.pack('>IIII', ts_sec, ts_usec, incl_len, incl_len)
    
    return rec_hdr + raw_packet

def generate_normal_traffic_pcap(path: str):
    """Generates standard HTTP, DNS, ICMP traffic."""
    with open(path, 'wb') as f:
        f.write(create_pcap_global_header())
        base_ts = 1727270000.0
        # Client 192.168.1.100 visiting web server 93.184.216.34 (example.com)
        # Proper 3-way handshake + HTTP GET + Response + FIN
        c_ip = "192.168.1.100"
        s_ip = "93.184.216.34"
        
        for i in range(15):
            t = base_ts + (i * 0.4)
            sport = 51000 + (i % 3)
            # SYN
            f.write(create_ethernet_ip_tcp_packet(c_ip, s_ip, sport, 80, flags=0x02, ts=t))
            # SYN-ACK
            f.write(create_ethernet_ip_tcp_packet(s_ip, c_ip, 80, sport, flags=0x12, ts=t + 0.02))
            # ACK + Data
            f.write(create_ethernet_ip_tcp_packet(c_ip, s_ip, sport, 80, flags=0x18, payload=b"GET / HTTP/1.1\r\n\r\n", ts=t + 0.03))
            # Server Response
            f.write(create_ethernet_ip_tcp_packet(s_ip, c_ip, 80, sport, flags=0x18, payload=b"HTTP/1.1 200 OK\r\n\r\n", ts=t + 0.05))

def generate_port_scan_pcap(path: str):
    """Generates horizontal port scan: single host probing 35 ports."""
    with open(path, 'wb') as f:
        f.write(create_pcap_global_header())
        base_ts = 1727271000.0
        attacker = "192.168.1.200"
        target = "10.0.0.1"
        for i in range(35):
            target_port = 20 + i
            f.write(create_ethernet_ip_tcp_packet(
                attacker, target, 45000 + i, target_port, flags=0x02, ts=base_ts + (i * 0.02)
            ))

def generate_dos_syn_flood_pcap(path: str):
    """Generates high velocity SYN flood: 120 packets to port 80 at > 100 pkt/sec."""
    with open(path, 'wb') as f:
        f.write(create_pcap_global_header())
        base_ts = 1727272000.0
        target = "10.0.0.50"
        for i in range(120):
            attacker = f"172.16.0.{10 + (i % 20)}"
            # 120 packets in ~0.35 seconds -> ~340 packets/second
            f.write(create_ethernet_ip_tcp_packet(
                attacker, target, 50000 + i, 80, flags=0x02, ts=base_ts + (i * 0.003)
            ))

def generate_ssh_brute_force_pcap(path: str):
    """Generates 18 rapid connection attempts to SSH port 22."""
    with open(path, 'wb') as f:
        f.write(create_pcap_global_header())
        base_ts = 1727273000.0
        attacker = "192.168.1.88"
        target = "10.0.0.22"
        for i in range(18):
            t = base_ts + (i * 0.1)
            # SYN
            f.write(create_ethernet_ip_tcp_packet(attacker, target, 41000 + i, 22, flags=0x02, ts=t))
            # SYN-ACK
            f.write(create_ethernet_ip_tcp_packet(target, attacker, 22, 41000 + i, flags=0x12, ts=t + 0.01))
            # RST (aborted authentication)
            f.write(create_ethernet_ip_tcp_packet(attacker, target, 41000 + i, 22, flags=0x04, ts=t + 0.02))

def generate_botnet_beacon_pcap(path: str):
    """Generates periodic beaconing every 1.0 second."""
    with open(path, 'wb') as f:
        f.write(create_pcap_global_header())
        base_ts = 1727274000.0
        infected = "192.168.1.150"
        c2_ip = "198.51.100.22"
        for i in range(10):
            # Exactly 1.0s interval
            t = base_ts + (i * 1.0)
            f.write(create_ethernet_ip_tcp_packet(infected, c2_ip, 55432, 8080, flags=0x18, payload=b"BEACON_ID=99", ts=t))
            f.write(create_ethernet_ip_tcp_packet(c2_ip, infected, 8080, 55432, flags=0x10, ts=t + 0.04))

def generate_insufficient_evidence_pcap(path: str):
    """Generates only 2 packets."""
    with open(path, 'wb') as f:
        f.write(create_pcap_global_header())
        f.write(create_ethernet_ip_tcp_packet("192.168.1.5", "8.8.8.8", 50000, 53, flags=0x02, ts=1727275000.0))
        f.write(create_ethernet_ip_tcp_packet("8.8.8.8", "192.168.1.5", 53, 50000, flags=0x12, ts=1727275000.05))

def generate_pcapng_file(path: str):
    """Generates a valid .pcapng file with Section Header and Enhanced Packet Blocks."""
    with open(path, 'wb') as f:
        # 1. Section Header Block (SHB) 0x0A0D0D0A
        # type(4), len(4), bom(4), major(2), minor(2), section_len(8), len(4)
        shb = struct.pack('<IIIHHqI', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
        f.write(shb)
        
        # 2. Interface Description Block (IDB) 0x00000001
        # type(4), len(4), link_type(2), reserved(2), snaplen(4), len(4)
        # Exact 20 bytes: 4 + 4 + 2 + 2 + 4 + 4 = 20
        idb_bytes = struct.pack('<IIHHII', 0x00000001, 20, 1, 0, 65535, 20)
        f.write(idb_bytes)
        
        # 3. Enhanced Packet Blocks (EPB) 0x00000006
        for i in range(25):
            raw_pkt = create_ethernet_ip_tcp_packet(
                "192.168.1.77", "10.0.0.8", 50000 + i, 80, flags=0x02, ts=1727276000.0 + i * 0.1
            )[16:] # Strip 16-byte PCAP header
            
            cap_len = len(raw_pkt)
            pad_len = (4 - (cap_len % 4)) % 4
            padded_pkt = raw_pkt + (b'\x00' * pad_len)
            
            block_len = 32 + len(padded_pkt)
            # if_id, ts_high, ts_low, cap_len, orig_len
            raw_ts = int((1727276000.0 + i * 0.1) * 1e6)
            ts_high = (raw_ts >> 32) & 0xFFFFFFFF
            ts_low = raw_ts & 0xFFFFFFFF
            
            epb_hdr = struct.pack('<IIIIIII', 0x00000006, block_len, 0, ts_high, ts_low, cap_len, cap_len)
            epb_tail = struct.pack('<I', block_len)
            f.write(epb_hdr + padded_pkt + epb_tail)

def main():
    print("[*] Generating CyberShield test PCAPs in:", OUTPUT_DIR)
    
    generate_normal_traffic_pcap(os.path.join(OUTPUT_DIR, 'normal_traffic.pcap'))
    generate_port_scan_pcap(os.path.join(OUTPUT_DIR, 'port_scan.pcap'))
    generate_dos_syn_flood_pcap(os.path.join(OUTPUT_DIR, 'dos_syn_flood.pcap'))
    generate_ssh_brute_force_pcap(os.path.join(OUTPUT_DIR, 'ssh_brute_force.pcap'))
    generate_botnet_beacon_pcap(os.path.join(OUTPUT_DIR, 'botnet_beacon.pcap'))
    generate_insufficient_evidence_pcap(os.path.join(OUTPUT_DIR, 'insufficient_evidence.pcap'))
    generate_pcapng_file(os.path.join(OUTPUT_DIR, 'valid_test.pcapng'))
    
    # Empty file
    open(os.path.join(OUTPUT_DIR, 'empty.pcap'), 'wb').close()
    
    # Corrupted header
    with open(os.path.join(OUTPUT_DIR, 'corrupted.pcap'), 'wb') as f:
        f.write(b'\xa1\xb2\xc3') # Truncated 3 bytes
        
    # Invalid text file
    with open(os.path.join(OUTPUT_DIR, 'invalid_text.txt'), 'w') as f:
        f.write("This is a plain text file, not a PCAP file.")
        
    print("[+] All 10 test files generated successfully.")

if __name__ == '__main__':
    main()
