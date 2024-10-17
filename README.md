# network-packet-sniffer
Network packet sniffer using python (identifies the protocols, TCP and UDP), also retrieves source and destination ports,  and sequence numbers.

import socket
import struct

def get_mac_addr(bytes_addr):
    return ':'.join(format(b, '02x') for b in bytes_addr)

def get_ipv4_addr(addr):
    return '.'.join(map(str, addr))

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    proto = data[9]
    src, target = struct.unpack('! 12x 4s 4s', data[:20])
    return get_ipv4_addr(src), get_ipv4_addr(target), proto, data[header_length:]

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    return src_port, dest_port

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f"Ethernet Frame: {dest_mac} -> {src_mac}, Protocol: {eth_proto}")

        if eth_proto == 8:
            src_ip, dest_ip, proto, data = ipv4_packet(data)
            print(f"IPv4 Packet: {src_ip} -> {dest_ip}, Protocol: {proto}")

            if proto == 6:
                src_port, dest_port = tcp_segment(data)
                print(f"TCP Segment: Source Port: {src_port}, Destination Port: {dest_port}")

            elif proto == 17:
                src_port, dest_port = udp_segment(data)
                print(f"UDP Segment: Source Port: {src_port}, Destination Port: {dest_port}")

if __name__ == "__main__":
    main()
