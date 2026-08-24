#!/usr/bin/env python3
"""Extrai os 42 Check Card profiles do GRSIMWrite.exe para JSON estruturado."""
import re, json

raw = open("/Users/eliel/grsimwrite-mac/research/vendor/GRSIMWrite.exe", "rb").read()

HEXRE = re.compile(rb'^[0-9A-F]{4,}$')
FIDRE = re.compile(rb'^[0-9A-F]{4}$')

def is_hex(s): return bool(HEXRE.match(s))
def printable_runs(seg):
    txt = re.sub(rb'[^\x20-\x7e]', b'\n', seg)
    return [l.decode() for l in txt.split(b"\n") if l.strip()]

hits = [m.start() for m in re.finditer(b"Check Card", raw)]
profiles = []

for n, off in enumerate(hits):
    # janela ate o proximo profile ou 2500 bytes
    nxt = hits[n+1] if n+1 < len(hits) else off + 2600
    lines = []
    for l in printable_runs(raw[off:min(nxt, off+2600)]):
        if l not in lines[-2:]:
            lines.append(l)
    prof = {
        "index": n,
        "exe_offset": hex(off),
        "title": lines[0] if lines else f"profile_{n}",
        "auth": [],
        "auth_expected_sw": [],
        "ops": [],
        "misc_hex": [],
        "labels_seen": [],
        "next_profile_hint": None,
    }
    i = 1
    cur_op = None
    while i < len(lines):
        L = lines[i]
        if L.startswith(("Check Card B", "Check Card F", "Check Card Type")):
            prof["next_profile_hint"] = L
            break
        # SWs esperados tipo "9000" ou "9000 9804"
        if re.fullmatch(r'([0-9A-F]{4})( [0-9A-F]{4})*', L) and len(L) >= 4 and ' ' in L:
            prof["auth_expected_sw"].append(L)
        # comando APDU completo em texto
        elif re.fullmatch(r'[0-9A-F]{8,}(\s[0-9A-F]{8,})?', L) or \
             re.fullmatch(r'[0-9A-F]{8}\[[A-Z_0-9]+\]', L.replace(" ", "")):
            flat = L.replace(" ", "")
            m = re.fullmatch(r'([0-9A-F]{8,})\[([A-Z_0-9]+)\]', flat)
            if m:
                prof["ops"].append({"cmd_template": m.group(1), "placeholder": m.group(2)})
            else:
                # pode ser auth ou cmd de operacao pendente
                if flat.startswith("A020") or flat.startswith("00FBFFFF") or \
                   flat.startswith("A0FBFFFF") or flat.startswith("002000") or \
                   flat.startswith("A0580000") or flat.startswith("A053"):
                    prof["auth"].append(flat)
                elif cur_op:
                    cur_op["extra_cmd"] = flat
                else:
                    prof["misc_hex"].append(flat)
        # data template com placeholder
        elif re.search(r'\[[A-Z_0-9]+\]', L):
            if cur_op and "data" not in cur_op:
                cur_op["data"] = L
            else:
                cur_op = {"label": None, "data": L}
                prof["ops"].append(cur_op)
        # FID alvo solto
        elif FIDRE.match(L.encode()) and len(L) == 4 and int(L, 16) >= 0x0100:
            if cur_op and "file" not in cur_op:
                cur_op["file"] = L
            else:
                cur_op = {"label": None, "file": L}
                prof["ops"].append(cur_op)
        # label textual (PIN1, ADM, GSM_KI...)
        else:
            prof["labels_seen"].append(L)
            if cur_op is None or ("data" in cur_op or "file" in cur_op):
                cur_op = {"label": L}
                prof["ops"].append(cur_op)
            else:
                cur_op["label"] = L
        i += 1
    profiles.append(prof)

out = "/Users/eliel/grsimwrite-mac/research/profiles.json"
with open(out, "w") as f:
    json.dump(profiles, f, indent=1)

# estatisticas
auth_styles = {}
for p in profiles:
    style = "desconhecida"
    for a in p["auth"]:
        if a.startswith("A0FBFFFF"): style = "FB-SADM"; break
        if a.startswith("00FBFFFF"): style = "FB00-SADM"; break
        if a.startswith("A058"): style = "INS58"; break
        if a.startswith("A053"): style = "INS53"; break
        if a.startswith(("A020","0020")):
            q = a[8:10]
            style = f"VERIFY-q{q}"
    auth_styles[style] = auth_styles.get(style, 0) + 1

print(f"{len(profiles)} perfis extraidos -> {out}")
print("\nEstilos de auth:")
for k, v in sorted(auth_styles.items()):
    print(f"  {k:<14}: {v} perfis")
print("\nAmostra perfil 38 (LY14):")
print(json.dumps(profiles[38], indent=1)[:1200])
