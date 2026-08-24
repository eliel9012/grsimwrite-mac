#!/usr/bin/env python3
"""Fase 2: grava Ki (MF/0001), OPc (MF/6002), MilenageParam (2FE5) e IMSI."""
import json, os, time
from smartcard.System import readers
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import CardConnectionException

ADM_KEY = "3838383838383838"
res = json.load(open(os.path.expanduser("~/grsimwrite-mac/research/card_result.json")))
KI = bytes.fromhex(res["ki"])
OPC = bytes.fromhex(res["opc"])
IMSI = res["imsi"]

def bcd(s):
    if len(s) % 2: s += "f"
    b = bytes.fromhex(s)
    return bytes(((x & 0xF) << 4) | (x >> 4) for x in b)

enc_imsi = bytes([0x08]) + bcd(IMSI)[:8]

class Sess:
    def __init__(self):
        self.connect()
    def connect(self):
        self.c = readers()[0].createConnection()
        self.c.connect(protocol=CardConnection.T0_protocol)
    def reconnect(self):
        time.sleep(1.2)
        try: self.c.disconnect()
        except Exception: pass
        self.connect()
    def tx(self, h, tries=6):
        for i in range(tries):
            try:
                d, s1, s2 = self.c.transmit(list(bytes.fromhex(h)))
                return f"{s1:02X}{s2:02X}", bytes(d)
            except CardConnectionException:
                if i == tries-1: raise
                self.reconnect()
    def auth(self):
        self.tx("A0A40000023F00")
        sw, _ = self.tx(f"A020000B08{ADM_KEY}")
        assert sw == "9000", sw
    def goto_mf(self):
        self.tx("A0A4000C023F00")
    def sel(self, fid, parent=True):
        """seleciona a partir do MF"""
        if parent:
            self.goto_mf()
        sw, _ = self.tx(f"A0A4000002{fid}")
        if sw.startswith(("9F","61")):
            sw, _ = self.tx(f"A0C00000{int(sw[2:],16):02X}")
        return sw
    def rb(self, n, off=0):
        return self.tx(f"A0B0{off:04X}{n:02X}")
    def wb(self, data, off=0):
        return self.tx(f"A0D6{off:04X}{len(data):02X}" + data.hex())

s = Sess()
s.auth()
print("[AUTH OK]")

def dump(label, fid):
    sw = s.sel(fid)
    if sw != "9000":
        print(f"{label:<16} sel={sw}")
        return None
    rsw, d = s.rb(32)
    print(f"{label:<16} {rsw} {d.hex()}")
    return d

print("\n== estado atual ==")
dump("MF/0001 (Ki?)", "0001")
dump("MF/6002 (OPc?)", "6002")
dump("MF/2FE5 (MilPar)", "2FE5")
dump("MF/2FE6", "2FE6")

print("\n== gravando ==")
# Ki
if s.sel("0001") == "9000":
    w = s.wb(KI)[0]
    vsw, vd = s.rb(16)
    ok = vsw == "9000" and vd == KI
    print(f"Ki  -> write={w} verify={'OK' if ok else 'FALHOU '+vd.hex()}")
else:
    print("Ki: 0001 inacessivel")

# OPc com prefixo 01
if s.sel("6002") == "9000":
    w = s.wb(b"\x01" + OPC)[0]
    vsw, vd = s.rb(17)
    ok = vsw == "9000" and vd == b"\x01" + OPC
    print(f"OPc -> write={w} verify={'OK' if ok else 'FALHOU '+vd.hex()}")
else:
    print("OPc: 6002 inacessivel")

# MilenageParameter
if s.sel("2FE5") == "9000":
    try:
        w = s.wb(bytes.fromhex("081C2A0001"))[0]
        vsw, vd = s.rb(5)
        print(f"MIL -> write={w} read={vd.hex()}")
    except Exception as e:
        print("MIL erro:", type(e).__name__)

# IMSI
if s.sel("7F20") == "9000" and s.sel("6F07", parent=False) == "9000":
    w = s.wb(enc_imsi)[0]
    vsw, vd = s.rb(9)
    ok = vsw == "9000" and vd == enc_imsi
    print(f"IMSI-> write={w} verify={'OK' if ok else 'FALHOU'} ({vd.hex()})")

print("\n== leitura final ==")
for label, fid, n in [("Ki(0001)","0001",16), ("OPc(6002)","6002",17),
                      ("ICCID(2FE2)","2FE2",10)]:
    if s.sel(fid) == "9000":
        _, d = s.rb(n)
        print(f"{label:<14}: {d.hex()}")

s.sel("7F20"); s.sel("6F07", parent=False)
_, d = s.rb(9)
print(f"{'IMSI(6F07)':<14}: {d.hex()}")
