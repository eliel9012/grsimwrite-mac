"""Mapa de EFs GSM 11.11 e codecs BCD/Luhn (ICCID, IMSI).

Codificacoes validadas em cartao real:
- IMSI "001010123456789" -> 0800010121436587f9
- ICCID usa Luhn no 20o digito antes do empacotamento BCD (10 bytes).
"""

EF_MAP = {
    "ICCID":   {"fid": "2FE2", "df": None,   "size": 10, "tipo": "transparent"},
    "IMSI":    {"fid": "6F07", "df": "7F20", "size": 9,  "tipo": "transparent"},
    "AD":      {"fid": "6FAD", "df": "7F20", "size": 3,  "tipo": "transparent"},
    "SPN":     {"fid": "6F41", "df": "7F20", "size": 17, "tipo": "transparent"},
    "SST":     {"fid": "6F38", "df": "7F20", "size": 14, "tipo": "transparent"},
    "LOCI":    {"fid": "6F7E", "df": "7F20", "size": 11, "tipo": "transparent"},
    "Kc":      {"fid": "6F20", "df": "7F20", "size": 9,  "tipo": "transparent"},
    "PLMNsel": {"fid": "6F30", "df": "7F20", "size": 30, "tipo": "transparent"},
    "ACC":     {"fid": "6F78", "df": "7F20", "size": 2,  "tipo": "transparent"},
    "BCCH":    {"fid": "6F74", "df": "7F20", "size": 16, "tipo": "transparent"},
    "ECC":     {"fid": "6F64", "df": "7F20", "size": 3,  "tipo": "transparent"},
    "MSISDN":  {"fid": "6F40", "df": "7F10", "size": 14, "tipo": "record"},
    "SMSP":    {"fid": "6F42", "df": "7F10", "size": 14, "tipo": "record"},
    "ADN":     {"fid": "6F3A", "df": "7F10", "size": 14, "tipo": "record"},
}


def bcd_encode(s):
    """Empacota string de digitos em BCD com nibbles trocados; padding 'f' se impar.

    Mesma semantica do fluxo validado em cartao real (scripts/program_card.py):
    cada par vira um byte (s[i] alto, s[i+1] baixo) e os nibbles sao trocados.
    Ex.: "001010123456789" -> 00 01 01 21 43 65 87 f9
    """
    if any(c not in "0123456789" for c in s):
        raise ValueError(f"BCD aceita apenas digitos: {s!r}")
    if len(s) % 2:
        s += "f"
    raw = bytearray()
    for i in range(0, len(s), 2):
        raw.append((int(s[i], 16) << 4) | int(s[i + 1], 16))
    out = bytearray()
    for x in raw:
        out.append(((x & 0x0F) << 4) | (x >> 4))
    return bytes(out)


def bcd_decode(b):
    """Decodifica BCD trocado para string de digitos, removendo padding 'f'."""
    digits = []
    for x in b:
        digits.append(x & 0x0F)
        digits.append((x >> 4) & 0x0F)
    s = "".join(str(d) for d in digits if d <= 9)
    return s.rstrip("f")


def luhn_check_digit(d19):
    """Digito verificador Luhn para os 19 primeiros digitos do ICCID."""
    total, alt = 0, True
    for ch in reversed(d19):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return str((10 - total % 10) % 10)


def encode_iccid(iccid_str):
    """Codifica ICCID (19 digitos) em 10 bytes BCD, anexando o digito Luhn.

    Aceita tambem 20 digitos ja completos, validando o verificador.
    """
    iccid_str = iccid_str.strip()
    if len(iccid_str) == 19:
        iccid_str += luhn_check_digit(iccid_str)
    elif len(iccid_str) != 20:
        raise ValueError(f"ICCID deve ter 19 ou 20 digitos: {iccid_str!r}")
    else:
        expected = luhn_check_digit(iccid_str[:19])
        if iccid_str[19] != expected:
            raise ValueError(
                f"digito verificador ICCID invalido: {iccid_str[19]} (esperado {expected})"
            )
    return bcd_encode(iccid_str)[:10]


def decode_iccid(b):
    """Decodifica 10 bytes BCD em string ICCID de 20 digitos (com Luhn)."""
    return bcd_decode(bytes(b))[:20]


def encode_imsi(imsi_str):
    """Codifica IMSI em 9 bytes: b'\\x08' + BCD trocado (8 bytes).

    O byte 0x08 declara 15 digitos com paridade impar (TS 11.11).
    Vetor validado em cartao real:
      encode_imsi('001010123456789') == bytes.fromhex('0800010121436587f9')
    """
    imsi_str = imsi_str.strip()
    if not imsi_str.isdigit() or not (6 <= len(imsi_str) <= 15):
        raise ValueError(f"IMSI deve ter de 6 a 15 digitos: {imsi_str!r}")
    header = bytes([0x08])
    body = bcd_encode(imsi_str)[:8].ljust(8, b"\xff")
    return header + body


def decode_imsi(b):
    """Decodifica EF_IMSI (9 bytes) para string de digitos.

    Varre os nibbles (baixo->alto em cada byte) ate encontrar padding 'f';
    nao usa o primeiro octeto como contagem de digitos (ele e comprimento
    em bytes com bit de paridade, ex.: 08).
    """
    b = bytes(b)
    if not b:
        return ""
    digits = []
    for x in b[1:]:
        for nib in (x & 0x0F, (x >> 4) & 0x0F):
            if nib > 9:
                return "".join(str(d) for d in digits)
            digits.append(nib)
    return "".join(str(d) for d in digits)
