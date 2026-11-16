"""Generates sample.pcap (no server / admin rights needed) so you can test
the dissector instantly in Wireshark.  Run: python make_pcap.py"""
import struct
import myp

def ip_checksum(h):
    s = sum(struct.unpack("!10H", h))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def frame(payload, src_port, dst_port, src_ip, dst_ip):
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
    total = 20 + udp_len
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0,
                     bytes(src_ip), bytes(dst_ip))
    ip = ip[:10] + struct.pack("!H", ip_checksum(ip)) + ip[12:]
    eth = bytes.fromhex("aabbccddee02") + bytes.fromhex("aabbccddee01") + b"\x08\x00"
    return eth + ip + udp

C, S = (192, 168, 1, 10), (192, 168, 1, 20)
pkts = [
    (myp.build(myp.LOGIN, 1, "shivanshi"),                         50000, 9999, C, S),
    (myp.build(myp.LOGIN_OK, 1, "Welcome shivanshi"),              9999, 50000, S, C),
    (myp.build(myp.PING, 2),                                       50000, 9999, C, S),
    (myp.build(myp.PONG, 2),                                       9999, 50000, S, C),
    (myp.build(myp.DATA, 3, "hello wireshark", myp.FLAG_ACK),      50000, 9999, C, S),
    (myp.build(myp.DATA, 4, "urgent!", myp.FLAG_ACK | myp.FLAG_URGENT), 50000, 9999, C, S),
    (myp.build(myp.DATA, 5, "bad length demo", length=99),         50000, 9999, C, S),  # malformed
    (myp.build(myp.BYE, 6),                                        50000, 9999, C, S),
]
with open("sample.pcap", "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, (pl, sp, dp, si, di) in enumerate(pkts):
        fr = frame(pl, sp, dp, si, di)
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)) + fr)
print("sample.pcap created with", len(pkts), "packets")
