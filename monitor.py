import socket
import struct
import textwrap
import time
import os

# Couleurs pour la console
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.ntohs(proto), data[14:]

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    # Décryptage manuel de l'en-tête TCP (Ports, Séquence, Flags)
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgement, data[offset:]

print(f"{YELLOW}[*] Démarrage du HFT Sniffer (Mode Raw Socket)...{RESET}")

# Création d'un socket brut (nécessite les droits root/privileged)
# ntohs(0x0003) signifie "capture tout le trafic Ethernet"
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

packet_count = 0
start_time = time.time()

try:
    while True:
        raw_data, addr = conn.recvfrom(65536)
        packet_count += 1
        
        # 1. Décoder Ethernet
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        # 2. Si c'est IP (Protocol 8)
        if eth_proto == 8:
            (ttl, proto, src, target, data) = ipv4_packet(data)

            # 3. Si c'est TCP (Protocol 6)
            if proto == 6:
                (src_port, dest_port, sequence, ack, data) = tcp_segment(data)
                
                # On ne regarde que le trafic MySQL (Port 3306)
                if src_port == 3306 or dest_port == 3306:
                    payload_size = len(data)
                    
                    # Détection Micro-Burst (Gros paquets)
                    if payload_size > 1400:
                        print(f"{RED}[BURST] Alert! Gros paquet détecté: {payload_size} bytes {src}:{src_port} -> {target}:{dest_port}{RESET}")
                    else:
                        # Affichage simple pour dire que ça vit
                        print(f"{GREEN}[TCP] {src}:{src_port} -> {target}:{dest_port} | Seq: {sequence} | Len: {payload_size}{RESET}")

        # Stats toutes les secondes
        if time.time() - start_time > 10:
            print(f"\n--- STATS ---")
            print(f"Paquets analysés : {packet_count}")
            packet_count = 0
            start_time = time.time()

except KeyboardInterrupt:
    print("\nArrêt.")