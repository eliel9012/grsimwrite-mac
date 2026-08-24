#!/usr/bin/env python3
"""Programa o cartão XC-SCM-01 (LY14) com credenciais próprias para YateBTS.

Fluxo descoberto na RE do GRSIMWrite 4.4.10 (ver research/iccapai-notas.md):
  - AUTH: VERIFY ADM q=0B com "88888888"
  - Ki em arquivo oculto 0001, OPc como 01+valor, MilenageParameter em 2FE5
  - IMSI em 7F20/6F07, ICCID em 3F00/2FE2 (BCD padrao GSM)
"""
import json, os, stat, time, secrets
from smartcard.System import readers
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import CardConnectionException

OUT_JSON = os.path.expanduser("~/grsimwrite-mac/research/card_result.json")
ADM_KEY = "3838383838383838"          # "88888888"

# ---------------- credenciais ----------------
def luhn(d19):
    s, alt = 0, True
    for ch in reversed(d19):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9: d -= 9
        s += d
        alt = not alt
    return str((10 - s % 10) % 10)

ki_hex = secrets.token_hex(16).upper()                    # 32 hex
opc_hex = secrets.token_hex(16).upper()                   # OPc direto (valido)
imsi = "001010123456789"                                  # PLMN teste 001-01
iccid19 = "8988210000000000001"
iccid = iccid19 + luhn(iccid19)

def bcd(s):
    if len(s) % 2: s += "f"
    b = bytes.fromhex(s)
    out = bytearray()
    for x in b:
        out.append((x & 0xF) << 4 | (x >> 4))
    return bytes(out)

def enc_iccid(iccid): return bcd(iccid)[:10]
def enc_imsi(imsi):
    hdr = bytes([0x08])                                   # 15 digitos, paridade impar
    body = bcd(imsi)[:8]
    return hdr + body

# ---------------- sessao ----------------
class Sess:
    def __init__(self):
        self.c = None
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
                if i == tries - 1:
                    raise
                self.reconnect()
        raise RuntimeError(h)

    def auth(self):
        self.tx("A0A40000023F00")
        sw, _ = self.tx(f"A020000B08{ADM_KEY}")
        if sw != "9000":
            sw, _ = self.tx(f"A058000008{'38'*8}")
        assert sw == "9000", f"AUTH falhou: {sw}"
        return sw

    def sel(self, fid, df=None):
        """SELECT passo-a-passo; retorna (sw, fcp)"""
        if df:
            sw, _ = self.tx(f"A0A4000002{df}")
            if not sw.startswith(("9F", "61")) and sw != "9000":
                return sw, b""
        sw, _ = self.tx(f"A0A4000002{fid}")
        fcp = b""
        if sw.startswith(("9F", "61")):
            n = int(sw[2:], 16)
            sw2, fcp = self.tx(f"A0C00000{n:02X}")
            sw = sw2
        return sw, fcp

    def rb(self, n, off=0):
        sw, d = self.tx(f"A0B0{off:04X}{n:02X}")
        return sw, d

    def wb(self, data, off=0):
        sw, _ = self.tx(f"A0D6{off:04X}{len(data):02X}" + data.hex())
        return sw

s = Sess()
print("conectado")
print("AUTH:", s.auth())

report = {"ki": ki_hex, "opc": opc_hex, "imsi": imsi, "iccid": iccid}

# ---------------- fase 1: recon ----------------
print("\n== recon ==")
found = {}
for df, ef in [(None,"0001"), (None,"0002"), (None,"0100"), (None,"0200"),
               (None,"0B00"), (None,"2FE5"), (None,"2FE6"),
               ("7FF0","0001"), ("7FF0","0002"), (None,"7FF0")]:
    key = f"{df or 'MF'}/{ef}"
    try:
        sw, fcp = s.sel(ef, df)
        ok = sw == "9000"
        found[key] = {"sel": sw, "fcp": fcp.hex()}
        if ok:
            sz = min(32, max(8, int.from_bytes(fcp[2:4], "big") if len(fcp) >= 4 else 16))
            rsw, data = s.rb(sz)
            found[key]["data"] = data.hex()
        print(f"{key:<10} {sw} {found[key].get('data','')[:24]}")
    except Exception as e:
        found[key] = {"erro": type(e).__name__}
        print(f"{key:<10} ERRO {type(e).__name__}")

# ---------------- fase 2: gravar Ki/OPc ----------------
def tenta_write(label, df, fid, data, off=0):
    try:
        sw, _ = s.sel(fid, df)
        if sw != "9000":
            print(f"{label}: arquivo nao acessivel ({sw}) - skip")
            return False
        # tamanho do arquivo pelo FCP (bytes 2-3)
        rsw, old = s.rb(max(len(data), 8), off)
        sw_w = s.wb(data, off)
        vsw, new = s.rb(max(len(data), 8), off)
        ok = sw_w == "9000" and new[off:off+len(data)] == data
        print(f"{label}: write={sw_w} verify={'OK' if ok else 'FALHOU'}")
        return ok
    except Exception as e:
        print(f"{label}: excecao {type(e).__name__}")
        return False

print("\n== gravando identidade ==")
kib = bytes.fromhex(ki_hex)
opcb = bytes.fromhex(opc_hex)

wrote_ki = False
for df, fid in [("7FF0","0001"), (None,"0001"), ("7FF0","0002")]:
    if tenta_write(f"Ki @{df or 'MF'}/{fid}", df, fid, kib):
        wrote_ki = True
        report["ki_local"] = f"{df or 'MF'}/{fid}"
        break

wrote_opc = False
for df, fid in [("7FF0","0002"), (None,"0002")]:
    if tenta_write(f"OPc @{df or 'MF'}/{fid}", df, fid, b"\x01" + opcb):
        wrote_opc = True
        report["opc_local"] = f"{df or 'MF'}/{fid}"
        break

if not wrote_ki:
    print("\n!!! Nao achei arquivo de Ki - vou mapear mais e reportar")

# ---------------- fase 3: IMSI e ICCID ----------------
print("\n== IMSI/ICCID ==")
try:
    sw, _ = s.sel("6F07", "7F20")
    if sw == "9000":
        print("IMSI write:", s.wb(enc_imsi(imsi)))
except Exception as e:
    print("IMSI erro:", type(e).__name__)

for attempt in range(2):
    try:
        sw, _ = s.sel("2FE2", "3F00")
        if sw == "9000":
            print("ICCID write:", s.wb(enc_iccid(iccid)))
        break
    except Exception as e:
        print("ICCID tentativa", attempt + 1, "-", type(e).__name__)
        s.reconnect()
        s.auth()

# ---------------- fase 4: leitura final ----------------
print("\n== leitura final ==")
final = {}
def rd(label, df, fid, n):
    try:
        sw, _ = s.sel(fid, df)
        if sw != "9000":
            final[label] = "(nao acessivel)"
            return
        rsw, d = s.rb(n)
        final[label] = d.hex()
        print(f"{label:<18}: {d.hex()}")
    except Exception as e:
        final[label] = f"(erro {type(e).__name__})"

rd("ICCID(2FE2)", None, "2FE2", 10)
rd("IMSI(6F07)", "7F20", "6F07", 9)

report["final"] = final
os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
with open(OUT_JSON, "w") as f:
    json.dump(report, f, indent=2)
os.chmod(OUT_JSON, stat.S_IRUSR | stat.S_IWUSR)
print(f"\nsalvo em {OUT_JSON}")
