#!/usr/bin/env python3
"""KeyEngine - construcao das APDUs das macros Ax* do GRSIMWrite 4.4.10.

Standalone: nao depende de families/dispatch/format.

Evidencia RE (research/ax_macros.md):
  - FILE-BASED (LY14): SELECT "A0A4000002"+FID (SW 9000) seguido de
    UPDATE BINARY "A0D6"+P1P2(0000)+Lc+dados (SW 9000). Sem cifra, sem re-auth.
  - FB-DIRECT: "A0FB"+P1P2+Lc+MAGIC8+dados (sem select).
  - D4-DIRECT: "A0D4"+ADDR+"08"+dados8 (PIN/PUK/ADM diretos).

Placeholders viram bytes por substituicao textual hex (uppercase forcado);
[OPC] usa template "01[OPC]" (prefixo 0x01); PIN/PUK/ADM entram como
nibble-hex ASCII ("1234" -> bytes 12 34).
"""

MAGIC_FB = {
    "ki": "7FACB75076880506",
    "opc": "1034D5C56869820401",
    "pin": "5121239D2455370B",
}

D4_ADDR = {
    "pin1": "3A01", "pin2": "3A02", "puk1": "3B00", "puk2": "3B02",
    "adm": "3A05", "adm_alt": "3A6A",
}

FB_ADDR = {
    # perfil FB (profiles.json idx 4): addr, len total Lc inclui magic8
    "pin1": "0000", "pin2": "0015", "puk1": "0008", "puk2": "001D",
    "adm": "003F", "ki": "0000", "opc": "0010",
}

FILE_BASED_FIDS = {
    "pin1": "0100", "pin2": "0200", "adm": "0B00", "ki": "0001", "opc": "6002",
}

FILE_BASED_TEMPLATES = {
    "pin": "000000[PIN]8383[PUK]8A8A",
    "adm": "010000[ADM]8A8A",
    "ki": "[KI]",
    "opc": "01[OPC]",
}


def _norm_hex(value, label):
    v = "".join((value or "").split()).upper()
    if not v:
        raise ValueError("%s: valor vazio" % label)
    if len(v) % 2 != 0 or any(c not in "0123456789ABCDEF" for c in v):
        raise ValueError("%s: hex invalido: %r" % (label, value))
    return v


def _norm_digits(value, max_digits, label):
    v = (value or "").strip()
    if not v or not v.isdigit() or len(v) > max_digits:
        raise ValueError("%s: esperado numerico <=%d digitos" % (label, max_digits))
    if len(v) % 2 != 0:
        v = "0" + v
    return v.upper()


class KeyEngine(object):
    """Gera as APDUs equivalentes as macros Ax do GRSIMWrite."""

    def __init__(self, cla="A0"):
        self.cla = cla if cla in ("A0", "00") else "A0"

    # ------------------------------------------------------------------ #
    # helpers                                                             #
    # ------------------------------------------------------------------ #
    def _update_binary(self, data_hex):
        """UPDATE BINARY no offset 0000; chunka se >255 bytes (path B)."""
        lines = []
        n = len(data_hex) // 2
        if n <= 255:
            lines.append("%sD60000%02X%s" % (self.cla, n, data_hex))
        else:
            off = 0
            while off * 2 < len(data_hex):
                chunk = data_hex[off * 2:(off + 255) * 2]
                lines.append("%sD6%04X%02X%s"
                             % (self.cla, off, len(chunk) // 2, chunk))
                off += len(chunk) // 2
        return lines

    @staticmethod
    def _result(apdu, fid, style, notes, select=None):
        out = {"apdu": apdu, "file": fid, "style": style, "notes": notes}
        if select:
            out["select_apdu"] = select
        return out

    def _file_based(self, kind, data_hex, extra_note=""):
        fid = FILE_BASED_FIDS[kind]
        sel = self.cla + "A4000002" + fid
        writes = self._update_binary(data_hex)
        notes = ("SELECT %s antes do write (SW 9000); UPDATE BINARY D6 "
                 "offset 0000 (SW 9000); sem cifra/re-auth no motor de macros "
                 "(RE 0x4A4DD4). %srequer validacao em cartao real" %
                 (sel, extra_note))
        return self._result(writes[0], fid, "file-based", notes, select=sel)

    def _fb_direct(self, kind, data_hex):
        magic = MAGIC_FB["pin"] if kind in ("pin", "adm") else MAGIC_FB[kind]
        addr = FB_ADDR[kind]
        body = magic + data_hex
        lc = len(body) // 2
        apdu = "%sFB%s%02X%s" % (self.cla, addr, lc, body)
        notes = ("FB-DIRECT: %sFB<addr=%s><Lc=%02X><magic8><data>; sem select; "
                 "templates completos ja conhecidos (profiles.json)" %
                 (self.cla, addr, lc))
        return self._result(apdu, None, "fb-direct", notes)

    def _d4_direct(self, key, data_hex):
        addr = D4_ADDR[key]
        # templates D4 fixam Lc=08 (ex: "A0D43A0108[PIN1]"); completa com
        # nibble F ate 8 bytes (padding real incerto - validar no cartao)
        data = data_hex + "F" * max(0, 16 - len(data_hex))
        apdu = "%sD4%s08%s" % (self.cla, addr, data[:16])
        notes = ("D4-DIRECT: %sD4<addr=%s><Lc=08 fixo><data8>; padding F "
                 "requer validacao em cartao real; handlers por ATR podem "
                 "fazer VERIFY ADM antes (ex 0x4AAB70: A020000B08+ADM)" %
                 (self.cla, addr))
        return self._result(apdu, None, "d4-direct", notes)

    def _style_of(self, family):
        f = (family or "").strip().upper()
        if f.startswith("FB") or "SYSMO" in f:
            return "fb-direct"
        if f.startswith("D4") or "D4" in f.split("-"):
            return "d4-direct"
        return "file-based"

    def _build(self, family, kind, data_hex):
        style = self._style_of(family)
        if style == "fb-direct":
            return self._fb_direct(kind, data_hex)
        if style == "d4-direct":
            return self._d4_direct("adm" if kind == "adm" else kind, data_hex)
        return self._file_based(kind, data_hex)

    # ------------------------------------------------------------------ #
    # API                                                                 #
    # ------------------------------------------------------------------ #
    def build_chv_write(self, family, pin, puk):
        """Macro AxCHV(PINx),AxCHV(PUKx): template 000000[PIN]8383[PUK]8A8A."""
        pin_h = _norm_digits(pin, 8, "pin")
        puk_h = _norm_digits(puk, 8, "puk")
        style = self._style_of(family)
        if style == "file-based":
            data = "000000" + pin_h + "8383" + puk_h + "8A8A"
            return self._file_based("pin1", data)
        if style == "fb-direct":
            body = pin_h + puk_h
            return self._fb_direct("pin", body)
        return self._d4_direct("pin1", pin_h)

    def build_adm_write(self, family, adm_key):
        """Macro AxADM(ADM): template 010000[ADM]8A8A (file-based)."""
        adm_h = _norm_digits(adm_key, 16, "adm")
        style = self._style_of(family)
        if style == "file-based":
            data = "010000" + adm_h + "8A8A"
            return self._file_based("adm", data)
        if style == "fb-direct":
            return self._fb_direct("adm", adm_h)
        return self._d4_direct("adm", adm_h)

    def build_ki_write(self, family, ki_hex):
        """Macro Ax(KI): [KI] direto, 16 bytes (EF 0001 no file-based)."""
        ki = _norm_hex(ki_hex, "ki")
        if len(ki) != 32:
            raise ValueError("ki: esperado 16 bytes (32 hex), veio %d bytes" % (len(ki) // 2))
        return self._build(family, "ki", ki)

    def build_opc_write(self, family, opc_hex):
        """Macro Ax(OPC): template 01[OPC] -> prefixo 01 + OPc (EF 6002)."""
        opc = _norm_hex(opc_hex, "opc")
        if len(opc) != 32:
            raise ValueError("opc: esperado 16 bytes (32 hex), veio %d bytes" % (len(opc) // 2))
        return self._build(family, "opc", "01" + opc)


if __name__ == "__main__":
    k = KeyEngine()
    print(k.build_ki_write("LY14", "0123456789ABCDEF0123456789ABCDEF"))
