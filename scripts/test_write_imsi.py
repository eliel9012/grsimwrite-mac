#!/usr/bin/env python3
"""Testa escrita autenticada no EF_IMSI com retries agressivos."""
from smartcard.System import readers
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import CardConnectionException
import time

ADM_KEY = "3838383838383838"  # "88888888"


def connect():
    c = readers()[0].createConnection()
    c.connect(protocol=CardConnection.T0_protocol)
    return c


c = connect()


def tx(h, n=6):
    global c
    for i in range(n):
        try:
            d, s1, s2 = c.transmit(list(bytes.fromhex(h)))
            return f"{s1:02X}{s2:02X}", bytes(d)
        except CardConnectionException:
            time.sleep(1.0)
            try:
                c.disconnect()
            except Exception:
                pass
            c = connect()
    raise RuntimeError(f"APDU {h} falhou apos {n} retries")


def auth():
    tx("A0A40000023F00")
    sw, _ = tx(f"A020000B08{ADM_KEY}")
    assert sw == "9000", f"AUTH falhou: {sw}"


print("SEL MF   :", tx("A0A40000023F00")[0])
print("AUTH     :", tx(f"A020000B08{ADM_KEY}")[0])
print("SEL 7F20 :", tx("A0A40000027F20")[0])
sw, fcp = tx("A0A40000026F07")
print("SEL 6F07 :", sw, fcp.hex())
if sw.startswith("9F"):
    print("GETRESP  :", tx(f"A0C00000{int(sw[2:],16):02X}")[0])

try:
    sw, _ = tx("A0D6000009" + "FF" * 18)
    print("UPD IMSI (FF):", sw)
except Exception as e:
    print("UPD IMSI (FF): falhou:", type(e).__name__)

# releitura em sessao nova
time.sleep(0.5)
try:
    c.disconnect()
except Exception:
    pass
c = connect()
auth()
tx("A0A40000027F20")
tx("A0A40000026F07")
sw, data = tx("A0B0000009")
print(f"IMSI lido: {sw} {data.hex()}")
