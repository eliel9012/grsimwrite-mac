"""Dispatch de familias de cartoes SIM (Fase 2) — parser dos 42 perfis
extraidos do GRSIMWrite.exe (research/profiles.json).

Cada perfil descreve uma familia de cartao: comando(s) de autenticacao
(VERIFY ADM, comandos proprietarios tipo INS 58/FB) e operacoes de escrita
(PIN/PUK, chave ADM, KI, OPC, parametros Milenage).

O extrator original (research/extract_profiles.py) e imperfeito: comandos de
autenticao as vezes caem na lista de ops com placeholder [SADM] —
normalize_profile() trata ops cujo template contem "[SADM]" como AUTH, nunca
como escrita. Headers de VERIFY soltos em labels (ex. "A020000408 ") tambem
sao resgatados.

Public API:
    load_profiles(path=None) -> [FamilyProfile]           # 42 perfis
    get_profile(index) -> FamilyProfile
    detect_family(atr_hex) -> FamilyProfile | None        # tabela exata ATR
    build_auth_apdus(profile, adm_key_ascii="88888888") -> [apdu_hex]
    build_write_ops(profile, dados, on_missing="raise") -> [{"file","data","op"}]

Semantica dos placeholders:
    [SADM]/[ADM]/[ADM1]/[ADM2]  chave ADM em hex-ASCII ("88888888" ->
                                "3838383838383838"); AMD e alias de ADM
    [PIN1]/[PIN2]/[PUK1]/[PUK2] digitos ASCII cruous ("1234" -> "31323334")
    [KI]/[GSM_KI]/[LTE_KI]      bytes.fromhex da chave (32 hex chars);
                                [LTE_KI] usa dados["lte_ki"] ou fallback ki
    [OPC]/[LTE_OPC]             bytes.fromhex com prefixo b"\\x01" quando o
                                template ainda nao traz o literal "01" antes
                                do placeholder (ex.: "01[OPC]" -> 01+opc)

Somente biblioteca padrao.
"""

from __future__ import annotations

import json
import os
import re

__all__ = [
    "FamilyProfile",
    "Operation",
    "MissingData",
    "load_profiles",
    "get_profile",
    "detect_family",
    "build_auth_apdus",
    "build_write_ops",
    "FACTORY_ADM_KEYS",
]

#: Chaves ADM de fabrica conhecidas nestas familias.
FACTORY_ADM_KEYS = ("88888888", "29083011", "0102030405060708")

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_PATHS = (
    os.path.join(_REPO_ROOT, "research", "profiles.json"),
    os.path.join(os.getcwd(), "research", "profiles.json"),
)

_PLACEHOLDER_RE = re.compile(r"\[([A-Z_0-9]+)\]")
_HEX_RE = re.compile(r"^[0-9A-F]*$")
_VERIFY_HEADER_RE = re.compile(r"^([0-9A-F]{2})(20)([0-9A-F]{6})$")


class MissingData(ValueError):
    """Placeholder sem valor correspondente em `dados`."""


# ---------------------------------------------------------------------------
# codificacao de placeholders
# ---------------------------------------------------------------------------

def _need(dados, key):
    if key not in dados or dados[key] in (None, ""):
        raise MissingData(f"dados[{key!r}] ausente")
    return dados[key]


def _enc_ascii_key(dados, key="adm"):
    v = str(_need(dados, key))
    return v.encode("ascii")


def _enc_digits(dados, key):
    v = str(_need(dados, key))
    if not v.isdigit():
        raise ValueError(f"{key} deve conter apenas digitos: {v!r}")
    return v.encode("ascii")


def _enc_ki(dados, key, fallback=None):
    v = dados.get(key) or (dados.get(fallback) if fallback else None)
    if not v:
        raise MissingData(f"dados[{key!r} (ou {fallback!r})] ausente")
    v = str(v).strip().upper()
    if len(v) != 32 or not _HEX_RE.match(v):
        raise ValueError(f"{key} deve ser 32 hex chars: {v!r}")
    return bytes.fromhex(v)


def _enc_opc(dados, key="opc"):
    return _enc_ki(dados, key)


# nome do placeholder -> (builder, tipo)
_PLACEHOLDERS = {
    "SADM":     (lambda d: _enc_ascii_key(d), "AUTH"),
    "ADM":      (lambda d: _enc_ascii_key(d), "ADM"),
    "AMD":      (lambda d: _enc_ascii_key(d), "ADM"),
    "ADM1":     (lambda d: _enc_ascii_key(d), "ADM"),
    "ADM2":     (lambda d: _enc_ascii_key(d, "adm2") if d.get("adm2") else _enc_ascii_key(d), "ADM"),
    "PIN1":     (lambda d: _enc_digits(d, "pin1"), "CHV1"),
    "PIN2":     (lambda d: _enc_digits(d, "pin2"), "CHV2"),
    "PUK1":     (lambda d: _enc_digits(d, "puk1"), "PUK1"),
    "PUK2":     (lambda d: _enc_digits(d, "puk2"), "PUK2"),
    "KI":       (lambda d: _enc_ki(d, "ki"), "KI"),
    "GSM_KI":   (lambda d: _enc_ki(d, "ki"), "KI"),
    "LTE_KI":   (lambda d: _enc_ki(d, "lte_ki", fallback="ki"), "KI_LTE"),
    "OPC":      (lambda d: _enc_opc(d, "opc"), "OPC"),
    "LTE_OPC":  (lambda d: _enc_opc(d, "opc"), "OPC"),
}

_TYPE_NAMES = {
    "PIN1": "CHV1", "PIN2": "CHV2", "PUK1": "PUK1", "PUK2": "PUK2",
    "ADM": "ADM", "ADM1": "ADM", "ADM2": "ADM", "AMD": "ADM",
    "KI": "KI", "GSM_KI": "KI", "LTE_KI": "KI_LTE",
    "OPC": "OPC", "LTE_OPC": "OPC",
}


def _clean_template(s):
    """Remove espacos/lixo de formato; retorna None se nao sobrar nada."""
    if not isinstance(s, str):
        return None
    t = re.sub(r"\s+", "", s)
    return t or None


def _split_template(tmpl):
    """Divide "01[OPC]" -> ("01", "[OPC]"). Segmentos fixos devem ser hex."""
    parts = _PLACEHOLDER_RE.split(tmpl)
    fixed = parts[0::2]
    for seg in fixed:
        if seg and not _HEX_RE.match(seg):
            raise ValueError(f"segmento nao-hex no template: {tmpl!r}")
    return tmpl


def _template_type(tmpl):
    """Nomeia a operacao pelo primeiro placeholder reconhecido do template."""
    names = []
    for m in _PLACEHOLDER_RE.finditer(tmpl):
        tok = m.group(1)
        name = _TYPE_NAMES.get(tok)
        if name and name not in names:
            names.append(name)
    return "+".join(names) if names else None


def _template_placeholders(tmpl):
    return [m.group(1) for m in _PLACEHOLDER_RE.finditer(tmpl)]


def _render_template(tmpl, dados):
    """Substitui placeholders e devolve os bytes finais.

    [OPC]/[LTE_OPC]: se o trecho imediatamente anterior ao placeholder nao for
    o literal "01", um prefixo b"\\x01" e acrescentado automaticamente.
    """
    out = bytearray()
    pos = 0
    for m in _PLACEHOLDER_RE.finditer(tmpl):
        head = tmpl[pos:m.start()]
        if head:
            out += bytes.fromhex(head)
        tok = m.group(1)
        if tok not in _PLACEHOLDERS:
            raise MissingData(f"placeholder nao suportado: [{tok}]")
        builder, _ = _PLACEHOLDERS[tok]
        chunk = builder(dados)
        if tok in ("OPC", "LTE_OPC") and not head.upper().endswith("01"):
            chunk = b"\x01" + chunk
        out += chunk
        pos = m.end()
    tail = tmpl[pos:]
    if tail:
        out += bytes.fromhex(tail)
    return bytes(out)


# ---------------------------------------------------------------------------
# FamilyProfile / Operation
# ---------------------------------------------------------------------------

class Operation:
    """Uma operacao de escrita da familia.

    data_builder(dados) -> bytes (levanta MissingData/ValueError se invalido).
    """

    __slots__ = ("op_type", "file_id", "template", "label")

    def __init__(self, op_type, file_id, template, label=None):
        self.op_type = op_type
        self.file_id = file_id          # FID hex ("0B00") ou None
        self.template = template        # ex.: "010000[ADM]8A8A"
        self.label = label

    def data_builder(self, dados):
        return _render_template(self.template, dados)

    def __repr__(self):
        return f"Operation({self.op_type!r}, file={self.file_id!r}, {self.template!r})"

    def __eq__(self, other):
        return (isinstance(other, Operation)
                and (self.op_type, self.file_id, self.template)
                == (other.op_type, other.file_id, other.template))

    def __hash__(self):
        return hash((self.op_type, self.file_id, self.template))


class FamilyProfile:
    """Perfil normalizado de uma familia de cartao."""

    __slots__ = ("index", "title", "exe_offset", "raw", "auth_templates",
                 "expected_sw", "operations", "auth_status", "dropped")

    def __init__(self, raw):
        self.raw = raw
        self.index = raw["index"]
        self.title = raw.get("title") or f"profile_{self.index}"
        self.exe_offset = raw.get("exe_offset")
        self.expected_sw = self._parse_expected_sw(raw.get("auth_expected_sw"))
        self.dropped = []
        self.auth_templates, self.auth_status = [], "missing"
        self.operations = []
        self._normalize()

    # -- normalizacao ------------------------------------------------------

    @staticmethod
    def _parse_expected_sw(entries):
        sws = []
        for e in entries or []:
            for tok in str(e).split():
                if re.fullmatch(r"[0-9A-Fa-f]{4}", tok):
                    sws.append(tok.upper())
        return sws

    def _add_dropped(self, why, detail=""):
        self.dropped.append(f"{why}: {detail}" if detail else why)

    def _normalize(self):
        auth = []
        seen = set()

        def add_auth(tmpl, origin):
            if tmpl and tmpl not in seen:
                seen.add(tmpl)
                auth.append(tmpl)
            elif not tmpl:
                self._add_dropped("auth-invalida", origin)

        # 1) campo "auth" do extrator
        for a in self.raw.get("auth") or []:
            t = _clean_template(a)
            if not t or not _HEX_RE.match(t):
                self._add_dropped("auth-invalida", repr(a))
                continue
            if "[" in t:                                   # ja vem com placeholder
                add_auth(t.replace("[SADM]", "[KEY]").replace("[ADM]", "[KEY]"), t)
            elif len(t) >= 24 and len(t) % 2 == 0:         # APDU completo c/ chave
                add_auth(t, t)
            elif 10 <= len(t) < 24:                        # header sem chave
                add_auth(t + "[KEY]", t)
            else:
                self._add_dropped("auth-curta", t)

        # 2) ops que sao auth disfarçadas ([SADM] ou VERIFY head+[ADM])
        auth_ops = set()               # ids das ops consumidas como AUTH
        for op in self.raw.get("ops") or []:
            t = _clean_template(op.get("data"))
            if not t:
                continue
            is_auth = False
            if "[SADM]" in t:
                add_auth(t.replace("[SADM]", "[KEY]"), t)
                is_auth = True
            else:
                m = re.fullmatch(r"([0-9A-F]+)\[ADM\]", t)
                if m and _VERIFY_HEADER_RE.match(m.group(1)):
                    add_auth(t.replace("[ADM]", "[KEY]"), t)
                    is_auth = True
            if is_auth:
                auth_ops.add(id(op))

        # 3) headers de VERIFY perdidos em labels (ex. "A020000408 ")
        for lab in self.raw.get("labels_seen") or []:
            t = _clean_template(lab)
            if t and _VERIFY_HEADER_RE.match(t) and len(t) == 10:
                add_auth(t + "[KEY]", t)

        self.auth_templates = auth
        self.auth_status = "explicit" if auth else "missing"

        # 4) operacoes de escrita
        writes = []
        wseen = set()
        for op in self.raw.get("ops") or []:
            if id(op) in auth_ops:     # ja consumida como AUTH no passo 2
                continue
            label = op.get("label")
            file_id = self._norm_fid(op.get("file"))
            tmpl = _clean_template(op.get("data"))

            # extra_cmd constante significativa (MilenageParameter -> 2FE5)
            extra = _clean_template(op.get("extra_cmd"))
            if not tmpl and extra and _HEX_RE.match(extra) \
                    and ((label and "milenage" in str(label).lower()) or file_id == "2FE5"):
                cand = Operation("MILENAGE", file_id, extra, label)
                if cand not in wseen:
                    wseen.add(cand)
                    writes.append(cand)
                continue

            if not tmpl:
                if file_id:
                    self._add_dropped("select-sem-data", str(file_id))
                continue

            try:
                _split_template(tmpl)
            except ValueError as exc:
                self._add_dropped("template-lixo", f"{tmpl!r} ({exc})")
                continue

            phs = _template_placeholders(tmpl)
            optype = _template_type(tmpl)
            if optype is None or any(p not in _PLACEHOLDERS for p in phs):
                bad = [p for p in phs if p not in _PLACEHOLDERS]
                self._add_dropped(
                    "placeholder-nao-suportado",
                    f"{tmpl!r} {bad or '(sem placeholder conhecido)'}")
                continue
            if optype == "AUTH":       # defensa extra: nunca escrever [SADM]
                continue

            cand = Operation(optype, file_id, tmpl, label if isinstance(label, str) else None)
            if cand in wseen:
                continue               # blocos repetidos pelo extrator
            wseen.add(cand)
            writes.append(cand)

        self.operations = writes

    @staticmethod
    def _norm_fid(fid):
        if not isinstance(fid, str):
            return None
        fid = fid.strip().upper()
        return fid if re.fullmatch(r"[0-9A-F]{4}", fid) else None

    # -- conveniencia --------------------------------------------------------

    @property
    def ambiguous(self):
        """True quando nenhuma autenticacao pôde ser derivada do perfil."""
        return self.auth_status == "missing"

    def auth_apdus(self, adm_key_ascii="88888888"):
        return build_auth_apdus(self, adm_key_ascii)

    def write_ops(self, dados, on_missing="raise"):
        return build_write_ops(self, dados, on_missing=on_missing)

    def __repr__(self):
        return (f"<FamilyProfile #{self.index} {self.title!r} "
                f"auth={self.auth_status} ops={len(self.operations)}>")


# ---------------------------------------------------------------------------
# carregamento
# ---------------------------------------------------------------------------

_CACHE = {}


def _resolve_path(path):
    if path:
        return path
    for cand in _DEFAULT_PATHS:
        if os.path.exists(cand):
            return cand
    raise FileNotFoundError(
        "profiles.json nao encontrado; informe o caminho explicitly")


def load_profiles(path=None):
    """Carrega os 42 perfis como lista de FamilyProfile (com cache por path)."""
    real = os.path.realpath(_resolve_path(path))
    if real in _CACHE:
        return _CACHE[real]
    with open(real, "r") as fh:
        raw_list = json.load(fh)
    profiles = [FamilyProfile(raw) for raw in raw_list]
    _CACHE[real] = profiles
    return profiles


def get_profile(index, path=None):
    return load_profiles(path)[index]


# ---------------------------------------------------------------------------
# deteccao por ATR
# ---------------------------------------------------------------------------

#: Tabela exata ATR -> indice do perfil. Familias sem ATR conhecido ficam fora
#: desta tabela (documentado aqui): os offsets do .exe guardam apenas os
#: scripts de personalizacao; so o LY14 (XC-SCM-01) tem ATR confirmado em
#: research/iccapai-notas.md / GRSIMWrite.grsp. Perfis 0-37 e 39-41 exigem
#: escolha manual por indice.
ATR_TABLE = {
    # LY14 / XC-SCM-01 "LTE Blank USIM" (perfil 38)
    "3B9F95801FC78031A073B6A10067CF3215CA9CD70920": 38,
}


def detect_family(atr_hex):
    """Detecta a familia pelo ATR. Retorna FamilyProfile ou None.

    Sem entrada na tabela (caso da maioria), retorna None — o chamador deve
    permitir escolha manual por indice (get_profile(i) / load_profiles()).
    """
    if not atr_hex:
        return None
    atr = re.sub(r"[^0-9A-Fa-f]", "", str(atr_hex)).upper()
    idx = ATR_TABLE.get(atr)
    if idx is None:
        return None
    return load_profiles()[idx]


# ---------------------------------------------------------------------------
# construção de APDUs / ops
# ---------------------------------------------------------------------------

def build_auth_apdus(profile, adm_key_ascii="88888888"):
    """APDUs de autenticacao prontos para transmitir.

    - Templates com [KEY]/[SADM]/[ADM] recebem a chave `adm_key_ascii`
      codificada em hex-ASCII ("88888888" -> "3838383838383838").
    - APDUs completos ja embutidos no perfil (chaves de fabrica alternativas,
      ex. perfis 0 e 3) sao mantidosverbatim: formam sequencias de sonda.
    - Duplicatas removidas preservando ordem.
    """
    if isinstance(profile, int):
        profile = load_profiles()[profile]
    key_hex = str(adm_key_ascii).encode("ascii").hex().upper()
    out, seen = [], set()
    for t in profile.auth_templates:
        apdu = t.replace("[KEY]", key_hex)
        if "[" in apdu:                      # segurança: nenhum placeholder vivo
            apdu = _PLACEHOLDER_RE.sub(key_hex, apdu)
        apdu = apdu.upper()
        if apdu not in seen:
            seen.add(apdu)
            out.append(apdu)
    return out


def build_write_ops(profile, dados, on_missing="raise"):
    """Lista ordenada de gravacoes {"file": fid, "data": bytes, "op": tipo}.

    on_missing="raise" (default) propaga MissingData/ValueError;
    on_missing="skip" omite operacoes cujos dados nao foram fornecidos.
    Operacoes sem FID resolvel no perfil tambem sao omitidas (nada a selecionar).
    """
    if isinstance(profile, int):
        profile = load_profiles()[profile]
    if on_missing not in ("raise", "skip"):
        raise ValueError("on_missing deve ser 'raise' ou 'skip'")
    out = []
    for op in profile.operations:
        try:
            data = op.data_builder(dados)
        except (MissingData, ValueError):
            if on_missing == "raise":
                raise
            continue
        if not op.file_id:
            continue                          # alvo perdido na extracao
        out.append({"file": op.file_id, "data": data, "op": op.op_type})
    return out
