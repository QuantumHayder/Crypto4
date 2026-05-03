"""
CTF 1 — Packet Analysis Solver
================================
Challenge: A flag was split across multiple TCP packets on port 4444
and base64-encoded before transmission. We need to reassemble and decode.

Approach:
1. Parse the pcap file manually (no external libraries needed)
2. The file uses Linux Cooked Capture v2 (SLL2) link layer
3. Filter for TCP packets where src or dst port = 4444
4. Extract payload data from each matching packet
5. The stream is framed with MSG: ... :EOF markers
6. Concatenate the payload chunks (excluding markers)
7. Base64-decode to reveal the flag
"""
"""
4 → represents a (pc4p = pcap)
3 → represents e (hidd3n = hidden, l3gi = legi)
7 → represents t (legi7 = legit, 7r4ffic = traffic)
"""

import struct
import base64


def parse_pcap_and_solve(filepath):
    with open(filepath, "rb") as f:
        # ── Step 1: Read the global pcap header (24 bytes) ──
        ghdr = f.read(24)
        magic, ver_major, ver_minor, _, _, snaplen, network = struct.unpack(
            "<IHHiIII", ghdr
        )
        print(f"[*] PCAP version {ver_major}.{ver_minor}, link type {network}")

        # Link type 276 = Linux SLL2 (20-byte header)
        SLL2_HEADER_LEN = 20

        tcp_payloads = []
        pkt_count = 0

        # ── Step 2: Read packets one by one ──
        while True:
            # Each packet has a 16-byte header: timestamps + lengths
            phdr = f.read(16)
            if len(phdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", phdr)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break
            pkt_count += 1

            # ── Step 3: Parse SLL2 → IP → TCP ──
            if len(pkt_data) < SLL2_HEADER_LEN:
                continue
            ethertype = struct.unpack(">H", pkt_data[0:2])[0]
            if ethertype != 0x0800:  # Not IPv4
                continue

            ip_start = SLL2_HEADER_LEN
            if len(pkt_data) < ip_start + 20:
                continue

            ip_ihl = (pkt_data[ip_start] & 0x0F) * 4  # IP header length
            ip_proto = pkt_data[ip_start + 9]           # Protocol field
            if ip_proto != 6:  # Not TCP
                continue

            tcp_start = ip_start + ip_ihl
            if len(pkt_data) < tcp_start + 20:
                continue

            src_port, dst_port = struct.unpack(">HH", pkt_data[tcp_start:tcp_start + 4])
            tcp_hdr_len = ((pkt_data[tcp_start + 12] >> 4) & 0xF) * 4

            # ── Step 4: Filter for port 4444 with payload ──
            payload = pkt_data[tcp_start + tcp_hdr_len:]
            if (src_port == 4444 or dst_port == 4444) and len(payload) > 0:
                tcp_payloads.append(payload)
                print(f"    [+] Packet #{pkt_count}: port {src_port}->{dst_port}, "
                      f"payload: {payload}")

        print(f"\n[*] Scanned {pkt_count} packets, "
              f"found {len(tcp_payloads)} with data on port 4444")

        # ── Step 5: Reassemble the stream ──
        combined = b"".join(tcp_payloads)
        print(f"[*] Combined stream: {combined}")

        # ── Step 6: Strip MSG: / :EOF framing and decode ──
        stream = combined
        if stream.startswith(b"MSG:"):
            stream = stream[4:]
        if stream.endswith(b":EOF"):
            stream = stream[:-4]

        flag = base64.b64decode(stream).decode()
        print(f"\n[✓] FLAG: {flag}")
        return flag


if __name__ == "__main__":
    parse_pcap_and_solve("./traffic.pcapng")