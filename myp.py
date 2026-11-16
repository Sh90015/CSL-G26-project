"""Shared helpers for the MYP protocol (build / parse packets)."""
import struct

MAGIC = 0x4D50
VERSION = 1
PORT = 9999
HEADER = struct.Struct("!HBBBHH")   # magic, ver, type, flags, seq, length

LOGIN, LOGIN_OK, DATA, PING, PONG, BYE = 1, 2, 3, 4, 5, 6
NAMES = {1: "LOGIN", 2: "LOGIN_OK", 3: "DATA", 4: "PING", 5: "PONG", 6: "BYE"}
FLAG_ACK, FLAG_URGENT = 0x01, 0x02


def build(msg_type, seq, payload=b"", flags=0, length=None):
    if isinstance(payload, str):
        payload = payload.encode()
    if length is None:
        length = len(payload)
    return HEADER.pack(MAGIC, VERSION, msg_type, flags, seq, length) + payload


def parse(data):
    if len(data) < HEADER.size:
        raise ValueError("packet too short")
    magic, ver, mtype, flags, seq, length = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise ValueError("bad magic")
    return dict(version=ver, type=mtype, flags=flags, seq=seq,
                length=length, payload=data[HEADER.size:HEADER.size + length])
