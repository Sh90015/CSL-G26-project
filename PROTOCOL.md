# MYP – Protocol Design Document

## 1. Goal
A simple request/response protocol for login, ping/pong and data messages, designed to be decoded easily in Wireshark.

## 2. Design choices
| Decision | Choice | Reason |
|---|---|---|
| Transport | UDP, port 9999 | Simple, connectionless, implement karna aasan |
| Byte order | Big endian (network order) | Network protocols ki standard convention |
| Header | Fixed 9 bytes | Parse karna aur dissect karna easy |
| Payload | Variable length, text | Debug karte waqt Wireshark me readable |
| Identification | Magic `0x4D50` ("MP") | Dissector pehchan sake ki packet MYP hai |
| Reliability | `Sequence No.` + optional ACK flag | UDP par basic request/reply matching |

## 3. Packet format
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+---------------+---------------+
|        Magic (0x4D50)         |    Version    |   Msg Type    |
+---------------+---------------+---------------+---------------+
|     Flags     |        Sequence No.           | Payload Len ..|
+---------------+---------------+---------------+---------------+
| ..Len (cont.) |               Payload (0..N bytes)            |
+---------------+-----------------------------------------------+
```
| Field | Size | Meaning |
|---|---|---|
| Magic | 2 B | Hamesha `0x4D50` |
| Version | 1 B | Abhi `1` |
| Type | 1 B | 1 LOGIN, 2 LOGIN_OK, 3 DATA, 4 PING, 5 PONG, 6 BYE |
| Flags | 1 B | bit0 = ACK requested, bit1 = Urgent |
| Sequence | 2 B | Client har request par badhata hai, reply me wahi value |
| Length | 2 B | Payload ke bytes |
| Payload | N B | Text (username, message, etc.) |

## 4. Message flow
```
Client                         Server
  | --- LOGIN  (user) -------->  |
  | <-- LOGIN_OK (Welcome) ----  |
  | --- PING ----------------->  |
  | <-- PONG ------------------  |
  | --- DATA (flags=ACK) ----->  |
  | <-- PONG ("ack") ----------  |
  | --- BYE ------------------>  |
```

## 5. Error handling
- Magic galat ya header 9 bytes se chhota: server packet ignore karta hai, dissector use MYP nahi maanta.
- Length field actual payload se match na kare: Wireshark Expert Info me **Malformed** error.
- Version != 1: Wireshark me warning.

## 6. Deliverables mapping
| Outcome | File |
|---|---|
| Protocol design | `PROTOCOL.md` (ye file) |
| Client / Server | `client.py`, `server.py`, `myp.py` |
| Lua dissector | `myproto.lua` |
| Test traffic | `sample.pcap`, `make_pcap.py` |
