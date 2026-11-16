"""MYP test client. Run after starting the server: python client.py"""
import socket
import myp

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2)
dst = ("127.0.0.1", myp.PORT)

steps = [
    (myp.LOGIN, "shivanshi", 0),
    (myp.PING,  "",          0),
    (myp.DATA,  "hello wireshark", myp.FLAG_ACK),
    (myp.DATA,  "urgent message!",  myp.FLAG_ACK | myp.FLAG_URGENT),
    (myp.BYE,   "",          0),
]
for seq, (t, payload, flags) in enumerate(steps, start=1):
    sock.sendto(myp.build(t, seq, payload, flags), dst)
    print(f"-> {myp.NAMES[t]} seq={seq}")
    if t != myp.BYE:
        try:
            r = myp.parse(sock.recvfrom(2048)[0])
            print(f"<- {myp.NAMES[r['type']]} seq={r['seq']} {r['payload']!r}")
        except socket.timeout:
            print("<- (no reply)")
