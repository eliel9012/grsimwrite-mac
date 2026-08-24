# grsimwrite-mac

[🇧🇷 Português](README.md) · [🇺🇸 English](README.en.md)

Native macOS port (Python) of **GRSIMWrite 4.4.10** — a Windows tool for
writing GSM/USIM SIM cards over PC/SC — with support for all **42 card
families** of the original, rebuilt through reverse engineering. No Windows,
no VM required.

## Install

```bash
git clone https://github.com/eliel9012/grsimwrite-mac.git
cd grsimwrite-mac
pip3 install -r requirements.txt   # pyscard, pydes
```

## Usage (CLI)

```bash
python3 -m simwriter identify                        # reader + ATR
python3 -m simwriter read                            # read all EFs
python3 -m simwriter read --ef ICCID IMSI           # specific EFs
python3 -m simwriter write --iccid 898821... --imsi 001010123456789
```

## Usage (Python API)

```python
from simwriter.session import CardSession
from simwriter.families import detect_family, load_profiles
from simwriter.dispatch import write_card
from simwriter.format import FormatEngine
from simwriter.keyengine import KeyEngine

s = CardSession()                          # forces T=0 (macOS quirk)
profile = detect_family(s.get_atr())       # ATR → 1 of 42 families

# full personalization with read-back verification
report = write_card(s, profile, {
    "iccid": "89882100000000000012",
    "imsi":  "001010123456789",
    "ki":    "0123456789ABCDEF0123456789ABCDEF",   # use YOUR Ki
    "opc":   "FEDCBA9876543210FEDCBA9876543210",   # use YOUR OPc
})

# format a blank card (rebuilds the whole filesystem)
fe = FormatEngine.from_catalog("research/format_templates.json")
seq = fe.build_format_sequence("family_1197c0")    # LY14: 321 steps

# exact key-write APDUs as produced by the original tool
ke = KeyEngine()
apdu = ke.build_ki_write("LY14", ki_hex)
```

## Architecture

| Phase | Module | Responsibility |
|---|---|---|
| 0 | `research/` | Reverse engineering of the original: 42 Check Card profiles, DLLs, `Ax()` macros |
| 1 | `session.py`, `files.py`, `cli.py` | `CardSession` (PC/SC T=0), GSM EF map, BCD/Luhn codecs |
| 2 | `families.py`, `dispatch.py` | 42-family dispatch: auth + write sequences |
| 3 | `keyengine.py` | Key writes in the tool's 3 styles (file-based, FB-direct, D4-direct) |
| 4 | `format.py` | Blank-card formatting: 2245 CREATE FILE commands / 14 clusters |
| 5 | `tests/` | 41 unit tests — fully offline (mocked, no hardware) |

```bash
python3 -m pytest tests/ -q     # 41 passed
```

## Key reverse-engineering finding

The original tool writes keys with **plain UPDATE BINARY after SELECT** — no
cipher, no re-authentication, no proprietary INS (`AddWriteMacro @0x4A4DD4`):

```
> A020000B08 3838383838383838        ← VERIFY ADM "88888888" (factory)
> A0A40000020001                     ← select Ki slot
> A0D6000010 <32-hex-char Ki>        ← write
```

Full RE documentation: [`research/ax_macros.md`](research/ax_macros.md) and
[`docs/PLANO.md`](docs/PLANO.md).

## macOS / hardware quirks

- Always connect with **T=0 only** (`T0|T1` together → "card unresponsive")
- Never run Homebrew's `pcscd` alongside Apple's native stack (conflict);
  if present: `sudo pkill -x pcscd`
- Use **loud** SELECT (P2=00 + GET RESPONSE) before sensitive operations;
  silent select (P2=0C) poisons the state of some COSes
- After a `CardConnectionException`, wait ≥1 s before reconnecting
- GreenCardCOS2014 firmware wedges the reader instead of returning an error SW
  on certain denials — `CardSession` retries work around this

## Legal / ethical notice

Tool intended for security research and private lab networks (e.g.
YateBTS/NIB). Use only with cards you own. Cloning third-party identities is
illegal.

## License

Educational/research use. No warranty of any kind.
