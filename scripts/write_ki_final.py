#!/usr/bin/env python3
"""Gravacao final: Ki em MF/0001 e OPc em MF/6002 com navegacao correta."""
import json, os, time
from smartcard.System import readers
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import CardConnectionException

ADM = "3838383838383838"
res_path = os.path.expanduser("~/grsimwrite-mac/research/card_result.json")
res = json.load(open(res_path))
KI = bytes.fromhex(res["ki"])
OPC = bytes.fromhex(res["opc"])

class S:
    def __init__(self):
        self.connect()
    def connect(self):
        self.c = readers()[0].createConnection()
        self.c.connect(protocol=CardConnection.T0_protocol)
    def rec(self):
        time.sleep(1.0)
        try: self.c.disconnect()
        except Exception: pass
        self.connect()
    def tx(self, h, n=5):
        for i in range(n):
            try:
                d, s1, s2 = self.c.transmit(list(bytes.fromhex(h)))
                return f"{s1:02X}{s2:02X}", bytes(d)
            except CardConnectionException:
                if i == n-1: raise
                self.rec()
    def loud(self, fid):
        sw, _ = self.tx(f"A0A4000002{fid}")
        if sw.startswith(("9F","61")):
            sw, fcp = self.tx(f"A0C00000{int(sw[2:],16):02X}")
            return sw, fcp
        return sw, b""
    def auth(self):
        self.loud("3F00")
        sw, _ = self.tx(f"A020000B08{ADM}")
        assert sw == "9000", f"auth {sw}"

s = S()

def write_file(label, fid, data):
    s.auth()
    sw, fcp = s.loud(fid)
    if sw != "9000":
        print(f"{label}: sel={sw} - SKIP")
        return False
    wsw, _ = s.tx(f"A0D6000000{len(data):02X}" + data.hex())
    vsw, vd = s.tx(f"A0B00000{len(data):02X}")
    ok = vsw == "9000" and vd == data
    print(f"{label}: write={wsw} verify={'OK' if ok else 'FALHOU ' + vd.hex()}")
    return ok

print("== gravando ==")
ok_ki = write_file("Ki  (0001)", "0001", KI)
ok_opc = write_file("OPc (6002)", "6002", b"\x01" + OPC)

print("\n== leitura final de tudo ==")
final = {}
for label, fid, n in [("ICCID(2FE2)","2FE2",10), ("Ki(0001)","0001",16),
                      ("OPc(6002)","6002",17), ("ADM(0B00)","0B00",16),
                      ("MilPar(2FE5)","2FE5",5)]:
    s.auth()
    sw, _ = s.loud(fid)
    if sw == "9000":
        _, d = s.tx(f"A0B00000{n:02X}")
        final[label] = d.hex()
        print(f"{label:<14}: {d.hex()}")

s.auth()
s.loud("7F20")
sw, _ = s.loud("6F07")
if sw == "9000":
    _, d = s.tx("A0B0000009")
    final["IMSI(6F07)"] = d.hex()
    print(f"{'IMSI(6F07)':<14}: {d.hex()}")

res["final"] = final
res["ki_ok"] = ok_ki
res["opc_ok"] = ok_opc
with open(res_path, "w") as f:
    json.dump(res, f, indent=2)
print("\nJSON atualizado:", res_path)
