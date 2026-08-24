#!/usr/bin/env python3
"""FormatEngine — filesystem formatting engine for SIM cards, reverse-engineered
from GRSIMWrite.exe (card_reader_UDisk 4.4.10 vendor tool).

The vendor binary stores its per-card-family personalization scripts as ASCII
hex APDU templates.  CREATE FILE commands (GSM 11.11, CLA=A0 INS=E0) appear as
runs like:

    A0E00000 11 00003F0001000000000009000206060000
    ^^^^^^^^ ^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    CLA INS  Lc payload (semi-structured)

Payload layout observed across the corpus (treat as semi-structured):

    [size:2B BE] [FID:2B] [descriptor/type byte] [access conds / record info]
    ... optionally a leaf-to-root selection path suffix such as
    "7FF0 3F00 7F10 5F3A 4F17" at the end.

Templates are physically grouped in the .exe by card family: each template
block ends ~32 bytes before the ASCII marker of the family's own profile
("Check Card", "Check Card B", ...), whose offset research/profiles.json
records in the ``exe_offset`` field.  Blocks sharing the same following
profile marker are merged into one family.

Public API:
    FormatEngine.from_catalog(json_path) -> FormatEngine
    FormatEngine.extract(exe_path, profiles_json=None) -> FormatEngine
    engine.list_families() -> [(family_id, num_create_commands)]
    engine.build_format_sequence(family_id) -> [step, ...]
    engine.parse_command(raw_hex) -> dict

Only the Python standard library is required.
"""

from __future__ import annotations

import json
import os
import re

__all__ = ["FormatEngine", "parse_command", "validate_raw", "validate_apdu",
           "build_catalog", "extract_templates"]

# ---------------------------------------------------------------------------
# low level parsing
# ---------------------------------------------------------------------------

_RAW_RUN_RE = re.compile(rb"A0E0[0-9A-Fa-f]{10,400}")
_APDU_RUN_RE = re.compile(rb"A0[0-9A-Fa-f]{10,400}")
_PROFILE_MARKER_RE = re.compile(rb"Check Card")

#: DF file identifiers that may appear inside a create-file payload either as
#: parent reference or as part of a leaf-to-root selection path suffix.
_DF_FIDS = {
    "3F00", "7F10", "7F20", "7F21", "7F22", "7FF0",
    "5F3A", "5F3B", "5F40", "5F50",
}

_TYPE_GUESS = {
    0x01: "df_or_mf",
    0x02: "df_or_linear_fixed_ef",
    0x04: "ef_transparent",
}

_INS_STEP = {0xE0: "create", 0xA4: "select", 0xD6: "init_data", 0xDC: "init_data"}

#: additional INSNs accepted inside family spans (verified/erased/rehab etc.)
_EXTRA_INS = {0x20, 0x52, 0x53, 0x58}

_CLUSTER_GAP = 1200


def validate_raw(raw_hex: str) -> bool:
    """Validate one extracted CREATE FILE template string."""
    if not isinstance(raw_hex, str):
        return False
    raw = raw_hex.strip().upper()
    if len(raw) < 12 or len(raw) % 2 != 0:
        return False
    if not raw.startswith("A0E00000"):
        return False
    if any(c not in "0123456789ABCDEF" for c in raw):
        return False
    try:
        lc = int(raw[8:10], 16)
    except ValueError:
        return False
    # payload must be fully present; trailing extra hex beyond Lc is tolerated
    return len(raw) >= 10 + 2 * lc


def parse_command(raw_hex: str, exe_offset=None):
    """Parse one CREATE FILE template into structured fields.

    Returns None when the raw string fails validation.
    """
    raw = raw_hex.strip().upper()
    if not validate_raw(raw):
        return None
    lc = int(raw[8:10], 16)
    payload = bytes.fromhex(raw[10:10 + 2 * lc])
    size_declared = int.from_bytes(payload[0:2], "big") if len(payload) >= 2 else None
    fid = payload[2:4].hex().upper() if len(payload) >= 4 else None

    type_guess = None
    if len(payload) >= 5:
        desc = payload[4]
        type_guess = _TYPE_GUESS.get(desc)
        if type_guess is None:
            if desc & 0x06:                      # linear-fixed style descriptors
                type_guess = "ef_linear_fixed"
            elif size_declared == 0:
                type_guess = "df_or_mf"
            else:
                type_guess = "unknown"

    # context DF / selection path: scan payload tail for known DF fids
    path_hint = []
    context_df = None
    body = payload[4:]
    for i in range(0, max(0, len(body) - 1)):
        w = body[i:i + 2].hex().upper()
        if w in _DF_FIDS and w != fid:
            path_hint.append(w)
            context_df = w

    cmd = {
        "raw_hex": raw,
        "lc": lc,
        "fid": fid,
        "size": size_declared,
        "type_guess": type_guess,
        "parent_df": context_df,
        "path_hint": path_hint,
    }
    if exe_offset is not None:
        cmd["exe_offset"] = exe_offset if isinstance(exe_offset, str) else hex(exe_offset)
    return cmd


def validate_apdu(raw: str) -> bool:
    """Loose validation for any A0-class APDU template run."""
    if not isinstance(raw, str):
        return False
    if len(raw) < 10 or len(raw) % 2 != 0:
        return False
    if any(c not in "0123456789ABCDEF" for c in raw):
        return False
    if not raw.startswith("A0"):
        return False
    try:
        ins = int(raw[2:4], 16)
        lc = int(raw[8:10], 16)
    except ValueError:
        return False
    if ins not in _INS_STEP and ins not in _EXTRA_INS:
        return False
    return len(raw) >= 10 + 2 * lc


# ---------------------------------------------------------------------------
# extraction from the vendor executable
# ---------------------------------------------------------------------------

def _read_binary(exe_path: str) -> bytes:
    with open(exe_path, "rb") as fh:
        return fh.read()


def extract_templates(exe_path: str):
    """Extract all CREATE FILE templates from an executable image.

    Returns ``(commands, clusters)`` where *commands* is a list of
    ``(offset:int, raw:str)`` in binary order (identical raw strings are kept
    when they occur at distinct positions — each occurrence is a distinct step
    of a family script; overlapping regex artifacts are deduplicated), and
    *clusters* groups their indices by proximity.
    """
    data = _read_binary(exe_path)

    matches = []
    seen_starts = set()
    for m in _RAW_RUN_RE.finditer(data):
        if m.start() in seen_starts:
            continue
        seen_starts.add(m.start())
        matches.append((m.start(), m.group().decode("ascii").upper()))
    matches.sort(key=lambda t: t[0])

    # proximity clustering: split whenever the gap between consecutive
    # templates exceeds _CLUSTER_GAP bytes (intra-family gaps hold UPDATE
    # BINARY data blobs; inter-family gaps hold profile metadata text).
    clusters = []
    current_idx = []
    for i, (off, raw) in enumerate(matches):
        if i and off - (matches[i - 1][0] + len(matches[i - 1][1])) > _CLUSTER_GAP:
            clusters.append(current_idx)
            current_idx = []
        current_idx.append(i)
    if current_idx:
        clusters.append(current_idx)

    return matches, clusters


def _profile_markers(data: bytes):
    """Offsets of the 'Check Card' family title markers inside the binary."""
    return sorted(m.start() for m in _PROFILE_MARKER_RE.finditer(data))


def _span_apdu_events(data: bytes, lo: int, hi: int):
    """Companion non-create APDU runs (SELECT / UPDATE BINARY) in [lo, hi).

    Returned as compact catalog entries: {"o": offset, "i": "A4", "r": raw}.
    """
    events = []
    for m in _APDU_RUN_RE.finditer(data, lo, hi):
        raw = m.group().decode("ascii").upper()
        if not validate_apdu(raw):
            continue
        ins = int(raw[2:4], 16)
        if ins == 0xE0:
            continue  # creates live in the commands list already
        if ins not in _INS_STEP:
            continue
        events.append({"o": hex(lo + m.start()), "i": "%02X" % ins, "r": raw})
    return events


def build_catalog(exe_path: str, profiles_json: str = None) -> dict:
    """Full pipeline: regex extraction -> clustering -> family attribution.

    Family attribution rule (empirically validated against the vendor data
    layout): a template cluster belongs to the family whose profile marker
    ("Check Card" text, i.e. profiles.json ``exe_offset``) immediately follows
    the end of the cluster (typically 32 bytes later).  Clusters sharing the
    same owner marker are merged into one family, keeping global binary order.
    """
    matches, clusters = extract_templates(exe_path)
    data = _read_binary(exe_path)
    markers = _profile_markers(data)

    profile_titles = {}
    if profiles_json and os.path.exists(profiles_json):
        try:
            with open(profiles_json, "r") as fh:
                profs = json.load(fh)
            for p in profs:
                profile_titles[int(p["exe_offset"], 16)] = p.get("title")
        except Exception:
            profile_titles = {}

    fam_members = {}  # owner_marker_offset -> [parsed commands] (binary order)
    for idx_group in clusters:
        group_cmds = [(matches[i][0], matches[i][1]) for i in idx_group]
        cl_end = group_cmds[-1][0] + len(group_cmds[-1][1])
        owner = next((mk for mk in markers if mk >= cl_end),
                     markers[-1] if markers else cl_end)
        bucket = fam_members.setdefault(owner, [])
        for off, raw in group_cmds:
            parsed = parse_command(raw, exe_offset=off)
            if parsed is not None:
                bucket.append(parsed)

    families = []
    for owner in sorted(fam_members):
        cmds = fam_members[owner]
        offsets = [int(c["exe_offset"], 16) for c in cmds]
        lo = min(offsets)
        hi = max(int(c["exe_offset"], 16) + len(c["raw_hex"]) // 2 for c in cmds)
        families.append({
            "family": "family_%x" % owner,
            "exe_offset_range": {"start": hex(min(offsets)), "end": hex(max(offsets))},
            "profile_marker": hex(owner),
            "profile_title": profile_titles.get(owner, "Check Card"),
            "count": len(cmds),
            "commands": cmds,
            # companion SELECT/UPDATE-BINARY template runs inside the family
            # span, so sequences can be replayed from the JSON alone.
            "events": _span_apdu_events(data, lo, hi),
        })

    families.sort(key=lambda f: int(f["exe_offset_range"]["start"], 16))
    return {
        "source_exe": os.path.basename(exe_path),
        "total_commands": sum(f["count"] for f in families),
        "num_families": len(families),
        "cluster_gap_threshold": _CLUSTER_GAP,
        "attribution_rule": "cluster belongs to the following 'Check Card' profile marker",
        "families": families,
    }


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------

class FormatEngine:
    """Replayable SIM filesystem formatting sequences per card family."""

    def __init__(self, catalog, _exe_path=None):
        self.catalog = self._normalize(catalog)
        self._exe_path = _exe_path
        self._current_family = None

    # -- loading ----------------------------------------------------------

    @staticmethod
    def _normalize(catalog):
        if isinstance(catalog, list):  # bare list of family objects
            catalog = {"families": catalog}
        fams = {}
        for fam in catalog.get("families", []):
            fams[fam["family"]] = fam
        if not fams:
            raise ValueError("catalog contains no families")
        catalog["families"] = sorted(fams.values(),
                                     key=lambda f: int(f["exe_offset_range"]["start"], 16))
        return catalog

    @classmethod
    def from_catalog(cls, json_path: str) -> "FormatEngine":
        with open(json_path, "r") as fh:
            return cls(json.load(fh))

    @classmethod
    def extract(cls, exe_path: str, profiles_json: str = None) -> "FormatEngine":
        """Fallback: extract templates straight from the vendor binary."""
        if profiles_json is None:
            guess = os.path.normpath(os.path.join(
                os.path.dirname(os.path.abspath(exe_path)), os.pardir, "profiles.json"))
            if os.path.exists(guess):
                profiles_json = guess
        return cls(build_catalog(exe_path, profiles_json), _exe_path=exe_path)

    @classmethod
    def auto(cls, base_dir: str) -> "FormatEngine":
        """Load catalog JSON if present, else extract from the vendored exe."""
        cat = os.path.join(base_dir, "research", "format_templates.json")
        if os.path.exists(cat):
            return cls.from_catalog(cat)
        exe = os.path.join(base_dir, "research", "vendor", "GRSIMWrite.exe")
        return cls.extract(exe)

    # -- introspection ----------------------------------------------------

    def list_families(self):
        """[(family_id, num_create_commands)] ordered by binary position."""
        return [(f["family"], f["count"]) for f in self.catalog["families"]]

    def family(self, family_id: str):
        for fam in self.catalog["families"]:
            if fam["family"] == family_id:
                return fam
        known = [f["family"] for f in self.catalog["families"]]
        raise KeyError("unknown family %r (known: %s)" % (family_id, known))

    @property
    def total_commands(self) -> int:
        return sum(f["count"] for f in self.catalog["families"])

    # -- sequence building -------------------------------------------------

    def build_format_sequence(self, family_id: str):
        """Ordered format steps for one card family.

        Returns steps preserving the original binary order (MF first, then
        DFs, then EFs, interleaved with their init data):

            [{"select": ["3F00"]},
             {"create": "A0E000001100003F00..."},
             {"init_data": {"fid": "2FE2", "data_hex": "..."}}, ...]
        """
        fam = self.family(family_id)
        cmds = fam["commands"]
        lo = min(int(c["exe_offset"], 16) for c in cmds)
        hi = max(int(c["exe_offset"], 16) + len(c["raw_hex"]) // 2 for c in cmds)

        # Replay every APDU-ish run inside the family span so init_data
        # (UPDATE BINARY) writes land between their creates, as authored.
        # Companion events carry their binary offset; creates are merged in
        # by offset so the stream reproduces the original script order.
        self._current_family = fam
        try:
            companion = self._span_events(lo, hi)   # [(off, ins, raw)]
        finally:
            self._current_family = None
        # disambiguate ordering when an event shares a create's offset
        stream = sorted(
            [(int(c["exe_offset"], 16), 0, 0xE0, c["raw_hex"]) for c in cmds]
            + [(o if o is not None else hi, 1, ins, raw) for o, ins, raw in companion],
            key=lambda t: (t[0], t[1]),
        )

        steps = []
        current_path = []
        selected = None          # last explicitly SELECTed fid
        created = None           # last CREATEd fid (no select since)
        saw_mf_step = False
        for _off, _tie, ins, raw in stream:
            kind = _INS_STEP.get(ins)
            if kind == "create":
                cmd = parse_command(raw)
                if cmd is None:
                    continue
                steps.append({"create": raw})
                created = cmd["fid"]
                if cmd["fid"] == "3F00":
                    saw_mf_step = True
                    current_path = ["3F00"]
            elif kind == "select":
                fid = raw[-4:].upper()
                current_path = self._extend_path(current_path, fid)
                selected = fid
                steps.append({"select": list(current_path)})
                if fid == "3F00":
                    saw_mf_step = True
            elif kind == "init_data":
                lc = int(raw[8:10], 16)
                target = selected or created or (current_path[-1] if current_path else None)
                steps.append({"init_data": {"fid": target,
                                            "data_hex": raw[10:10 + 2 * lc].upper()}})
        if steps and not saw_mf_step:
            # every card session starts anchored at the MF (card reset state);
            # make that explicit when the vendor script omits it.
            steps.insert(0, {"select": ["3F00"]})
        return steps

    @staticmethod
    def _extend_path(current_path, fid):
        fid = fid.upper()
        if fid == "3F00":
            return ["3F00"]
        if fid.startswith("7F"):                    # dedicated file under MF
            return ["3F00", fid]
        if fid.startswith("5F"):                    # sub-DF under current DF
            base = current_path[:2] if current_path else ["3F00"]
            return (base + [fid]) if base[-1].startswith("7F") else ["3F00", fid]
        if fid.startswith(("6F", "2F", "4F")):      # elementary files
            if current_path:
                return current_path + [fid]
            return ["3F00", fid]
        if current_path:
            return current_path + [fid]
        return ["3F00", fid]

    # -- event replay -------------------------------------------------------

    def _span_events(self, lo: int, hi: int):
        """Ordered (offset|None, INS, raw) triples of A0-APDU runs in [lo, hi).

        CREATE templates are not included (they live in ``commands``); the
        result covers SELECT / UPDATE BINARY companion runs.
        """
        # 1) events baked into the catalog (self-contained JSON)
        fam = self._current_family
        if fam is not None and fam.get("events"):
            out = []
            for ev in fam["events"]:
                raw = ev["r"].upper()
                if validate_apdu(raw):
                    out.append((int(ev["o"], 16), int(raw[2:4], 16), raw))
            out.sort(key=lambda t: t[0])
            return out
        # 2) live scan of the vendor binary when available
        if self._exe_path and os.path.exists(self._exe_path):
            with open(self._exe_path, "rb") as fh:
                fh.seek(lo)
                seg = fh.read(hi - lo)
            out = []
            for m in _APDU_RUN_RE.finditer(seg):
                raw = m.group().decode("ascii").upper()
                if not validate_apdu(raw):
                    continue
                ins = int(raw[2:4], 16)
                if ins == 0xE0 or ins not in _INS_STEP:
                    continue
                out.append((lo + int(m.start()), ins, raw))
            out.sort(key=lambda t: t[0])
            return out
        # 3) catalog-only fallback: no companion runs available
        return []


if __name__ == "__main__":  # pragma: no cover - regeneration helper
    import argparse

    ap = argparse.ArgumentParser(description="Regenerate the format template catalog")
    ap.add_argument("--exe", default="research/vendor/GRSIMWrite.exe")
    ap.add_argument("--profiles", default="research/profiles.json")
    ap.add_argument("--out", default="research/format_templates.json")
    args = ap.parse_args()
    cat = build_catalog(args.exe, args.profiles)
    with open(args.out, "w") as fh:
        json.dump(cat, fh, indent=1)
    print("families:", cat["num_families"], "commands:", cat["total_commands"],
          "->", args.out)
