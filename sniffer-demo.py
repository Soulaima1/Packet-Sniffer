import socket
import struct

packet_history = []

def main(callback, stop_callback):
    # Analyze the packet ethernet networks going through network interface card (NIC)
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while stop_callback():
        raw_data, addr = conn.recvfrom(65535)
        packet_info = {}

        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        packet_info["Source"] = src_mac
        packet_info["Destination"] = dest_mac
        packet_info["Protocol"] = eth_proto
        packet_info["Packet Type"] = "Ethernet"
        packet_info["Segment"] = "Data"
        packet_info["Info"] = data

        if eth_proto == 8:  # IPv4
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            packet_info["Source"] = src
            packet_info["Destination"] = target
            packet_info["Packet Type"] = "IPv4"

            if proto == 1:  # ICMP
                (icmp_type, code, checksum, data) = icmp_packet(data)
                packet_info["Segment"] = "ICMP"
                packet_info["Info"] = f"Type: {icmp_type}, Code: {code}, Checksum: {checksum}"

            elif proto == 6:  # TCP
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                packet_info["Segment"] = "TCP"
                
                # Determine primary flags (SYN, SYN-ACK, ACK)
                primary_flags = []
                if flag_syn and flag_ack:
                    primary_flags.append("[SYN,ACK]")
                elif flag_syn:
                    primary_flags.append("[SYN]")
                elif flag_ack:
                    primary_flags.append("[ACK]")

                # Collect all other flags with their values
                other_flags = {
                    "URG": flag_urg,
                    "ACK": flag_ack,
                    "PSH": flag_psh,
                    "RST": flag_rst,
                    "SYN": flag_syn,
                    "FIN": flag_fin
                }

                # Format other flags string
                other_flags_str = ", ".join(f"{flag}={value}" for flag, value in other_flags.items() if flag not in ['SYN', 'ACK'])

                # Combine primary and other flags into the info string
                primary_flags_str = " ".join(primary_flags)
                flags_str = f"Flags: {primary_flags_str}, {other_flags_str}"

                packet_info["Info"] = f"{flags_str}, Src Port: {src_port}, Dest Port: {dest_port}, Seq: {sequence}, Ack: {acknowledgment}"

                # If port 80 (HTTP)
                if src_port == 80 or dest_port == 80:
                    http_info = http_segment(data)
                    if http_info:
                        packet_info["Segment"] = "HTTP"
                        packet_info["Info"] = http_info

            elif proto == 17:  # UDP
                src_port, dest_port, length, data = udp_segment(data)
                packet_info["Segment"] = "UDP"
                packet_info["Info"] = f"Src Port: {src_port}, Dest Port: {dest_port}, Length: {length}"

        # Store packet_info in packet_history and invoke callback function with packet_info
        packet_history.append(packet_info)
        callback(packet_info)

# Function to unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    # Convert MAC addresses to a human-readable format
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Function to return properly formatted MAC address (e.g., AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()
# Unpack IPv4
def ipv4_packet(data):
    version_header_length = data[0]
    # Extract version
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    # Decompose the first 20 bytes of the IPv4 header
    """
    8x : Ignore the first 8 bytes.
    B : Retrieve the TTL (1 byte).
    B : Retrieve the protocol (1 byte).
    2x : Ignore the next 2 bytes.
    4s : Retrieve the source IP address (4 bytes).
    4s : Retrieve the destination IP address (4 bytes)."""
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Return properly formatted IPv4 address 127.0.0.1
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpacks ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpacks UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Unpacks HTTP segment
def http_segment(data):
    try:
        http_data = data.decode('utf-8')
        if "HTTP" in http_data or "GET" in http_data or "POST" in http_data:
            #extract  method and URL
            headers = http_data.split("\r\n")
            method = headers[0].split()[0]
            url = headers[0].split()[1]
            http_info = f"Method: {method}, URL: {url}"

            if method == "POST":
                #extract  Data passed

                body_index = http_data.find("\r\n\r\n")# the empty line
                if body_index != -1:
                    body = http_data[body_index + 4:]  # Get the body after headers
                    form_items = body.split('&') # form_items contains ["username=user", "password=pass123", "email=user@example.com"]
                    form_info = ", ".join(form_items)
                    http_info += f", Form Items: {form_info}"#Method: POST, URL: /submit_form, Form Items: username=user, password=pass123, email=user@example.com"

            return http_info
        return None
    except UnicodeDecodeError:
        return None
