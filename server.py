"""Tiny MYP server (UDP 127.0.0.1:9999). Run: python server.py"""
import socket
import myp

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", myp.PORT))
print(f"MYP server listening on UDP {myp.PORT} ... (Ctrl+C to stop)")

while True:
    data, addr = sock.recvfrom(2048)
    try:
        p = myp.parse(data)
    except ValueError as e:
        print("bad packet:", e)
        continue
    name = myp.NAMES.get(p["type"], p["type"])
    print(f"<- {name} seq={p['seq']} payload={p['payload']!r}")
    if p["type"] == myp.LOGIN:
        user = p["payload"].decode(errors="replace")
        sock.sendto(myp.build(myp.LOGIN_OK, p["seq"], f"Welcome {user}"), addr)
    elif p["type"] == myp.PING:
        sock.sendto(myp.build(myp.PONG, p["seq"]), addr)
    elif p["type"] == myp.DATA and p["flags"] & myp.FLAG_ACK:
        sock.sendto(myp.build(myp.PONG, p["seq"], "ack"), addr)
