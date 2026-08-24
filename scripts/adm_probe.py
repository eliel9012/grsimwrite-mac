#!/usr/bin/env python3
"""Sonda de autenticacao ADM: VERIFY e EXTERNAL AUTHENTICATE com chaves candidatas.

Baseado na analise da ICCAPI.dll (ver docs/PLANO.md):
  - fluxo do tool = GET CHALLENGE -> DES(challenge, key) -> EXT AUTH
  - ADM default do grsp = "88888888" (hex 3838383838383838)
"""
import argparse, time
from smartcard.System import readers
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import CardConnectionException

try:
    from pyDes import des, ECB
except ImportError:
    raise SystemExit("pip install pydes")

KEYS = [b"88888888", b"44444444", b"00000000", b"12345678",
        b"11111111", b"66666666"]
QUALS = ["0A", "01", "02", "07", "0B"]


def fresh():
    c = readers()[0].createConnection()
    c.connect(protocol=CardConnection.T0_protocol)   # T0 obrigatorio neste reader
    return c


def tx(c, h):
    d, s1, s2 = c.transmit(list(bytes.fromhex(h)))
    return f"{s1:02X}{s2:02X}", bytes(d)


def des_ecb(key8, data8):
    return des(key8, ECB, padmode=None).encrypt(data8)


def probe(cla, select_path, keys=KEYS, quals=QUALS, test_write=False):
    for k in keys:
        for q in quals:
            time.sleep(0.15)
            c = fresh()
            try:
                for s in select_path:
                    sw, _ = tx(c, s)
                    if sw != "9000":
                        break
                else:
                    sw, rnd = tx(c, f"{cla}84000008")
                    if sw == "9000" and len(rnd) == 8:
                        crypto = des_ecb(k, rnd)
                        sw, _ = tx(c, f"{cla}8200{q}08{crypto.hex()}")
                        print(f"{cla} q={q} key={k.decode()}: challenge OK, extauth={sw}")
                        if sw == "9000":
                            print(f"\n*** AUTENTICADO com {k.decode()} q={q} ***")
                            if test_write:
                                tx(c, "A0A40000023F00")
                                tx(c, "A0A4000C022FE2")
                                sw2, _ = tx(c, "A0D600000AFFFFFFFFFFFF")
                                print(f"UPDATE ICCID teste: {sw2}")
                            return True
            except CardConnectionException:
                pass
            finally:
                c.disconnect()
    return False


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--cla", default="00", help="CLA a testar (00 ou A0)")
    p.add_argument("--write", action="store_true", help="testa UPDATE apos auth")
    args = p.parse_args()

    sel_mf = ["00A4000C023F00"] if args.cla == "00" else ["A0A40000023F00"]
    found = probe(args.cla.upper(), sel_mf, test_write=args.write)

    if not found and args.cla.upper() == "A0":
        sel2 = ["A0A40000023F00", "A0A40000027F20"]
        found = probe("A0", sel2, test_write=args.write)

    if not found:
        print("\nNenhuma combinacao funcionou — ver docs/PLANO.md estrategia A/B.")
