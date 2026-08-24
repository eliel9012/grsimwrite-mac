#!/usr/bin/env python3
"""Leitor completo de SIM GSM para YateBTS - salva resultado em Markdown."""
from smartcard.System import readers
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import CardConnectionException, NoCardException
import binascii, time, datetime

MD_PATH = "/Users/eliel/sim-yatebts.md"
results = {}   # name -> dict(hex=..., dec=..., sw=...)
log = []

def connect(retries=4):
    for i in range(retries):
        try:
            r = readers()
            if not r:
                raise Exception("nenhum leitor")
            c = r[0].createConnection()
            c.connect(protocol=CardConnection.T0_protocol)
            return c
        except Exception as e:
            log.append(f"tentativa {i+1} falhou: {e}")
            time.sleep(2)
    raise Exception("nao consegui conectar apos varias tentativas")

conn = connect()
atr = "".join(f"{b:02x}" for b in conn.getATR())
print(f"[OK] Conectado. ATR={atr}")

def tx(h):
    return conn.transmit(list(bytes.fromhex(h)))

def apdu_raw(h):
    d, s1, s2 = tx(h)
    return bytes(d), (s1 << 8) | s2

def get_resp(n):
    return apdu_raw(f"A0C00000{n:02X}")

def sel(fid):
    """SELECT por ID (passo-a-passo). Retorna (fcp_bytes, sw)."""
    d, sw = apdu_raw(f"A0A4000002{fid}")
    if (sw >> 8) == 0x9F:
        d, sw = get_resp(sw & 0xFF)
    return d, sw

def rb(n, off=0):
    """READ BINARY com correcao de comprimento (SW 6Cxx)."""
    d, sw = apdu_raw(f"A0B0{off:04X}{n:02X}")
    if (sw >> 8) == 0x6C:
        d, sw = apdu_raw(f"A0B0{off:04X}{sw & 0xFF:02X}")
    return d, sw

def rr(rec, n=32):
    """READ RECORD absoluto."""
    d, sw = apdu_raw(f"A0B2{rec:02X}04{n:02X}")
    if (sw >> 8) == 0x67:
        d, sw = apdu_raw(f"A0B2{rec:02X}04{sw & 0xFF:02X}")
    return d, sw

def bcd(b, strip_f=True):
    s = "".join(f"{x & 0xF:x}{x >> 4:x}" for x in b)
    return s.rstrip("f") if strip_f else s

def dec_imsi(b):
    if not b: return ""
    n = b[0] & 0x0F
    digits = []
    for x in b[1:]:
        digits += [x & 0xF, x >> 4]
    return "".join(str(d) for d in digits if d <= 9)[:n]

def dec_plmn(two):
    s = bcd(two, strip_f=True)
    mcc, mnc = s[:3], s[3:]
    return mcc, mnc

def dec_lai(lai5):
    mcc, mnc = dec_plmn(lai5[:2] + bytes([lai5[2] & 0xF0]))
    lac = int.from_bytes(lai5[3:5], "big")
    return mcc, mnc, lac

# ---------- seleção do MF ----------
_, mf_sw = sel("3F00")
mf_ok = mf_sw in (0x9000,) or (mf_sw >> 8) == 0x9F
print(f"MF 3F00: SW={mf_sw:04X}")

def read_transp(group, name, df, fid, maxlen=255):
    d0, sw_df = sel(df)
    if not ((sw_df == 0x9000) or (sw_df >> 8) == 0x9F):
        results[name] = {"hex": "", "dec": f"DF {df} nao acessivel (SW={sw_df:04X})", "sw": sw_df}
        return
    d, sw = sel(fid)
    if (sw >> 8) == 0x94 or sw == 0x6A82 or (sw >> 8) == 0x98:
        results[name] = {"hex": "", "dec": "arquivo ausente ou acesso negado", "sw": sw}
        print(f"[-] {name}: SW={sw:04X}")
        return
    fcp = d
    size = maxlen
    # extrai tamanho do TLV 80/81 no FCP se presente
    i = 0
    while i < len(fcp) - 1:
        t, l = fcp[i], fcp[i+1]
        if t in (0x80, 0x81) and i + 2 + l <= len(fcp) and l <= 2:
            size = int.from_bytes(fcp[i+2:i+2+l], "big")
            break
        i += 2 + l
    size = min(size, maxlen)
    out = b""
    off = 0
    while off < size:
        chunk = min(size - off, 256)
        dd, ss = rb(chunk, off)
        if ss != 0x9000:
            break
        out += dd
        off += len(dd)
        if len(dd) < chunk:
            break
    results[name] = {"hex": binascii.hexlify(out).decode(), "dec": "", "sw": 0x9000}
    print(f"[+] {name} = {binascii.hexlify(out).decode()}")

# ---------- ICCID ----------
read_transp("MF", "ICCID", "3F00", "2FE2")

# ---------- EF_DIR (lista aplicacoes / AIDs USIM) ----------
read_transp("MF", "EF_DIR", "3F00", "2F00", maxlen=128)

# ---------- DF_GSM ----------
_, gsm_sw = sel("7F20")
print(f"DF_GSM 7F20: SW={gsm_sw:04X}")
if (gsm_sw == 0x9000) or (gsm_sw >> 8) == 0x9F:
    for name, fid in [("IMSI","6F07"), ("Kc","6F20"), ("PLMNsel","6F30"),
                      ("HPLMN","6F31"), ("ACMmax","6F37"), ("SST","6F38"),
                      ("SPN","6F41"), ("CBMI","6F45"), ("ECC","6F64"),
                      ("BCCH","6F74"), ("ACC","6F78"), ("LOCI","6F7E"),
                      ("AD","6FAD"), ("KCGPRS","6F53"), ("LOCIGPRS","6F54"),
                      ("GID1","6F3E"), ("GID2","6F3F"), ("PUCT","6F58")]:
        read_transp("GSM", name, "7F20", fid)
else:
    print("[!] DF_GSM nao acessivel - pode ser USIM puro; tentando AID depois")

# ---------- DF_TELECOM (registros) ----------
_, tel_sw = sel("7F10")
if (tel_sw == 0x9000) or (tel_sw >> 8) == 0x9F:
    for name, fid in [("MSISDN","6F40"), ("SMSP","6F42"), ("ADN","6F3A")]:
        d, sw = sel(fid)
        if (sw >> 8) == 0x9F:
            d, sw = get_resp(sw & 0xFF)
        if sw != 0x9000 and (sw >> 8) != 0x9F:
            results[name] = {"hex": "", "dec": "ausente/negado", "sw": sw}
            continue
        recs = []
        for rec in range(1, 4):
            dd, ss = rr(rec, 40)
            if ss == 0x9000 and any(x != 0xFF for x in dd):
                recs.append(binascii.hexlify(dd).decode())
            elif ss != 0x9000:
                break
        results[name] = {"hex": " | ".join(recs), "dec": "", "sw": 0x9000}

conn.disconnect()

# ================= DECODIFICACAO =================
iccid = bcd(bytes.fromhex(results.get("ICCID", {}).get("hex", "")))
imsi_hex = results.get("IMSI", {}).get("hex", "")
imsi = dec_imsi(bytes.fromhex(imsi_hex)) if imsi_hex else ""

mcc = mnc = spn_txt = lac = tmsi = ""
ad_hex = results.get("AD", {}).get("hex", "")
if ad_hex and len(ad_hex) >= 6:
    mcc, mnc = dec_plmn(bytes.fromhex(ad_hex[2:6]))

spn_hex = results.get("SPN", {}).get("hex", "")
if spn_hex:
    try:
        raw = bytes.fromhex(spn_hex)[1:]
        spn_txt = raw.replace(b"\xff", b"").decode("ascii", errors="replace").strip("\x00@")
    except Exception:
        pass

loci_hex = results.get("LOCI", {}).get("hex", "")
if loci_hex and len(loci_hex) >= 22:
    lb = bytes.fromhex(loci_hex)
    tmsi = binascii.hexlify(lb[0:4]).decode()
    try:
        _, _, lac = dec_lai(lb[4:9])
    except Exception:
        lac = ""

sst_hex = results.get("SST", {}).get("hex", "")

# ================= MARKDOWN =================
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
md = f"""# Dados do SIM — para YateBTS

Gerado em: {now}
Leitor: Generic EMV Smartcard Reader (Alcor AU9540, VID 0x058f PID 0x9540)

## Resumo

| Campo | Valor |
|---|---|
| ATR | `{atr}` |
| ICCID | `{iccid}` |
| IMSI | `{imsi}` |
| MCC | `{mcc}` |
| MNC | `{mnc}` |
| Operadora (SPN) | `{spn_txt}` |
| LAC (ultimo registro) | `{lac}` |
| TMSI | `{tmsi}` |

## Config YateBTS (subscriber.conf)

```ini
[subscriber]
imsi={imsi}
ki=COLOQUE_AQUI_A_KI   ; definida quando o cartao foi gravado (write-only, nao da pra ler de volta)
opc=                   ; se o cartao usar OPc, preencher; senao usar OP
```

> **Nota:** em cartoes programaveis a Ki e gravada uma vez e **nao pode ser lida de volta**
> (write-only por seguranca). Use o valor que voce definiu na gravacao ou o fornecido
> pelo fabricante/sysmoUSIM. Para escrever novos valores no cartao e necessaria a
> chave ADM do mesmo.

## Arquivos lidos (brutos)

| Arquivo | Conteudo (hex) |
|---|---|
"""
order = ["ICCID", "IMSI", "AD", "SPN", "SST", "LOCI", "LOCIGPRS", "Kc", "KCGPRS",
         "PLMNsel", "HPLMN", "ACMmax", "ACC", "BCCH", "CBMI", "ECC", "PUCT",
         "GID1", "GID2", "EF_DIR", "MSISDN", "SMSP", "ADN"]
for k in order:
    v = results.get(k)
    if v:
        md += f"| {k} | `{v['hex'] or '(vazio)'}` {v['dec']} |\n"

md += "\n## Log de conexao\n\n```\n" + "\n".join(log) + "\n```\n"

with open(MD_PATH, "w") as f:
    f.write(md)

print(f"\n=== RESUMO ===")
print(f"ICCID : {iccid}")
print(f"IMSI  : {imsi}")
print(f"MCC/MNC: {mcc}/{mnc}  SPN: {spn_txt}")
print(f"\nSalvo em {MD_PATH}")
