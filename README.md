# MYP – Wireshark Lua Dissector (Mini Project)

A small custom protocol **MYP** (UDP port 9999) and its Wireshark Lua dissector.

## Files
| File | Kaam |
|---|---|
| `PROTOCOL.md` | Protocol design document (format, flow, errors) |
| `myproto.lua` | Wireshark dissector (asli project) |
| `test_myp.py` | 11 unit tests (`python -m unittest -v`) |
| `myp.py` | Protocol build/parse helper |
| `server.py` / `client.py` | Live traffic generate karne ke liye |
| `make_pcap.py` | Ready `sample.pcap` banata hai (bina server ke test) |
| `sample.pcap` | 8 packets (ek malformed bhi) |

## Protocol format (9 byte header)
```
0-1  Magic 0x4D50 ("MP")     5-6  Sequence No.
2    Version (1)             7-8  Payload Length
3    Type 1=LOGIN 2=LOGIN_OK 3=DATA 4=PING 5=PONG 6=BYE
4    Flags bit0=ACK bit1=Urgent      9..  Payload (text)
```

## Run kaise karein

### Sabse easy: sample.pcap
1. Dissector copy karo Wireshark plugin folder me  
   - Windows: `%APPDATA%\Wireshark\plugins\`  
   - Linux/Mac: `~/.local/lib/wireshark/plugins/` (Mac: `~/.config/wireshark/plugins/`)  
   (Folder na ho to bana lo.) Ya seedha: `wireshark -X lua_script:myproto.lua sample.pcap`
2. `sample.pcap` Wireshark me open karo.
3. Protocol column me **MYP** dikhega, packet details me poora tree.
4. Display filters try karo: `myp`, `myp.type == 3`, `myp.flags.urgent == 1`
5. Packet 7 me Expert Info error dikhega (length mismatch).

### Live capture
1. Terminal 1: `python server.py`
2. Wireshark me loopback capture start karo (Linux/Mac: `lo`/`lo0`, Windows: Npcap Loopback Adapter), filter `udp.port == 9999`
3. Terminal 2: `python client.py`

Python 3 chahiye, koi extra library nahi.
