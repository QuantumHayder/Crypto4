# CTF 1 - Packet Analysis
# 
# The flag is hidden inside a pcap file, split across TCP packets
# on port 4444 and base64-encoded.
#
# Steps:
# 1. Read the pcap file and go through each packet
# 2. Look for TCP packets going to/from port 4444
# 3. Pull out the data (payload) from those packets
# 4. Stick all the pieces together and base64-decode

import struct
import base64

TARGET_PORT = 4444

def solve(filepath):
    with open(filepath, "rb") as f:

        header = f.read(24)
        magic, major, minor, _, _, snaplen, link_type = struct.unpack("<IHHiIII", header)
        print(f"PCAP v{major}.{minor}, link type: {link_type}")

        sll2_size = 20

        found_payloads = []
        total_packets = 0

        while True:
            pkt_header = f.read(16)
            if len(pkt_header) < 16:
                break 

            ts_sec, ts_usec, captured_len, original_len = struct.unpack("<IIII", pkt_header)
            raw_packet = f.read(captured_len)
            if len(raw_packet) < captured_len:
                break
            total_packets += 1

            if len(raw_packet) < sll2_size:
                continue

            proto = struct.unpack(">H", raw_packet[0:2])[0]
            if proto != 0x0800:
                continue

            ip_offset = sll2_size
            if len(raw_packet) < ip_offset + 20:
                continue

            ip_header_len = (raw_packet[ip_offset] & 0x0F) * 4
            transport_proto = raw_packet[ip_offset + 9]
            if transport_proto != 6:
                continue

            tcp_offset = ip_offset + ip_header_len
            if len(raw_packet) < tcp_offset + 20:
                continue

            src_port, dst_port = struct.unpack(">HH", raw_packet[tcp_offset:tcp_offset + 4])

            tcp_header_len = ((raw_packet[tcp_offset + 12] >> 4) & 0xF) * 4
            payload = raw_packet[tcp_offset + tcp_header_len:]

            if (src_port == TARGET_PORT or dst_port == TARGET_PORT) and len(payload) > 0:
                found_payloads.append(payload)
                print(f"  Found data in packet #{total_packets}: "
                      f"{src_port} -> {dst_port}, content: {payload}")

        print(f"\nWent through {total_packets} packets total")
        print(f"Found {len(found_payloads)} packets with data on port {TARGET_PORT}")

        full_stream = b"".join(found_payloads)
        print(f"Full stream: {full_stream}")


        data = full_stream
        if data.startswith(b"MSG:"):
            data = data[4:]
        if data.endswith(b":EOF"):
            data = data[:-4]

        flag = base64.b64decode(data).decode()
        print(f"\nFlag: {flag}")
        return flag


if __name__ == "__main__":
    solve("./traffic.pcapng")