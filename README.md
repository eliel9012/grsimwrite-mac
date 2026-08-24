# grsimwrite-mac

[🇧🇷 Português](README.md) · [🇺🇸 English](README.en.md)

Port macOS nativo (Python) do **GRSIMWrite 4.4.10** — ferramenta Windows de
gravação de SIM GSM/USIM via PC/SC — com suporte às **42 famílias de cartão**
do tool original, reconstruídas por engenharia reversa. Sem Windows, sem VM.

## Instalação

```bash
git clone https://github.com/eliel9012/grsimwrite-mac.git
cd grsimwrite-mac
pip3 install -r requirements.txt   # pyscard, pydes
```

## Uso (CLI)

```bash
python3 -m simwriter identify                        # leitor + ATR
python3 -m simwriter read                            # lê todos os EFs
python3 -m simwriter read --ef ICCID IMSI           # EFs específicos
python3 -m simwriter write --iccid 898821... --imsi 001010123456789
```

## Uso (API Python)

```python
from simwriter.session import CardSession
from simwriter.families import detect_family, load_profiles
from simwriter.dispatch import write_card
from simwriter.format import FormatEngine
from simwriter.keyengine import KeyEngine

s = CardSession()                          # força T=0 (quirk macOS)
profile = detect_family(s.get_atr())       # ATR → 1 de 42 famílias

# personalização completa com verificação read-back
report = write_card(s, profile, {
    "iccid": "89882100000000000012",
    "imsi":  "001010123456789",
    "ki":    "0123456789ABCDEF0123456789ABCDEF",   # use SUA Ki
    "opc":   "FEDCBA9876543210FEDCBA9876543210",   # use SEU OPc
})

# formatação de cartão virgem (recria o filesystem inteiro)
fe = FormatEngine.from_catalog("research/format_templates.json")
seq = fe.build_format_sequence("family_1197c0")    # LY14: 321 passos

# construção exata dos APDUs de chave conforme o tool original
ke = KeyEngine()
apdu = ke.build_ki_write("LY14", ki_hex)
```

## Arquitetura

| Fase | Módulo | Responsabilidade |
|---|---|---|
| 0 | `research/` | Engenharia reversa do original: 42 perfis Check Card, DLLs, macros `Ax()` |
| 1 | `session.py`, `files.py`, `cli.py` | `CardSession` (PC/SC T=0), mapa de EFs GSM, codecs BCD/Luhn |
| 2 | `families.py`, `dispatch.py` | Dispatch das 42 famílias: auth + sequências de escrita |
| 3 | `keyengine.py` | Escrita de chaves nos 3 estilos do tool (file-based, FB-direct, D4-direct) |
| 4 | `format.py` | Formatação de virgem: 2245 comandos CREATE FILE / 14 clusters |
| 5 | `tests/` | 41 testes unitários — 100% offline (mocks, sem hardware) |

```bash
python3 -m pytest tests/ -q     # 41 passed
```

## Descoberta-chave da engenharia reversa

O tool original grava as chaves com **UPDATE BINARY puro após SELECT** — sem
cifra, sem re-autenticação, sem INS proprietário (`AddWriteMacro @0x4A4DD4`):

```
> A020000B08 3838383838383838        ← VERIFY ADM "88888888" (fábrica)
> A0A40000020001                     ← select do slot da Ki
> A0D6000010 <Ki em 32 hex>          ← gravação
```

Documentação completa da RE: [`research/ax_macros.md`](research/ax_macros.md) e
[`docs/PLANO.md`](docs/PLANO.md).

## Quirks macOS / hardware

- Conecte **sempre forçando T=0** (`T0|T1` juntos → "card unresponsive")
- Não rode o `pcscd` do Homebrew junto com o stack nativo Apple (conflito);
  se existir: `sudo pkill -x pcscd`
- Use SELECT **loud** (P2=00 + GET RESPONSE) antes de operações sensíveis;
  select silencioso (P2=0C) envenena o estado de alguns COS
- Após `CardConnectionException`, aguarde ≥1 s antes de reconectar
- Firmware GreenCardCOS2014 trava o leitor em vez de retornar SW de erro em
  certas negações — os retries da `CardSession` contornam isso

## Aviso legal / ético

Ferramenta para pesquisa de segurança e redes privadas de laboratório
(ex.: YateBTS/NIB). Use apenas com cartões seus. Clonar identidades de
terceiros é ilegal.

## Licença

Uso educacional/pesquisa. Sem garantia alguma.
