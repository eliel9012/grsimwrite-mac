# grsimwrite-mac

Port macOS nativo (Python) do GRSIMWrite 4.4.10 — gravação de SIM GSM/USIM via
PC/SC, com suporte às **42 famílias** de cartão do tool original. Sem Windows.

## Instalação

```bash
pip install -r requirements.txt   # pyscard, pydes
```

## Uso

```bash
python3 -m simwriter identify                 # leitor + ATR
python3 -m simwriter read                     # lê todos os EFs
python3 -m simwriter read --ef ICCID IMSI    # EFs específicos
python3 -m simwriter write --iccid 898821... --imsi 001010123456789
```

### API Python

```python
from simwriter.session import CardSession
from simwriter.families import load_profiles, detect_family
from simwriter.dispatch import write_card
from simwriter.format import FormatEngine
from simwriter.keyengine import KeyEngine

s = CardSession()                     # T=0 forçado (quirk macOS)
atr = s.get_atr()

profile = detect_family(atr)          # ATR → 1 das 42 famílias (ou índice manual)
report = write_card(s, profile, {
    "iccid": "89882100000000000012",
    "imsi":  "001010123456789",
    "ki":    "0123456789ABCDEF0123456789ABCDEF",
    "opc":   "FEDCBA9876543210FEDCBA9876543210",
})                                    # auth → writes → verificação read-back

fe = FormatEngine.from_catalog("research/format_templates.json")
seq = fe.build_format_sequence("family_1197c0")   # formata cartão virgem (321 steps p/ LY14)

ke = KeyEngine()
apdu = ke.build_ki_write("LY14", ki_hex)          # select+D6 exatos conforme RE do tool
```

## Arquitetura (fases)

| Fase | Módulo | O que faz |
|---|---|---|
| 0 | `research/` | Engenharia reversa completa do original (42 perfis, DLLs, macros) |
| 1 | `session.py`, `files.py`, `cli.py` | CardSession T=0 + mapa de EFs + CLI |
| 2 | `families.py`, `dispatch.py` | Dispatch das 42 famílias: auth e sequências de escrita |
| 3 | `keyengine.py` | Escrita de chaves (Ki/OPc/ADM/PIN) nos 3 estilos do tool |
| 4 | `format.py` | Formatação de cartão virgem (2245 CREATE FILE / 14 clusters) |
| 5 | `tests/` | 41 testes unitários (mock, sem hardware) |

## Descoberta-chave da RE

O tool original grava as chaves com **UPDATE BINARY puro após SELECT** — sem cifra,
sem re-auth, sem INS proprietário (`AddWriteMacro @0x4A4DD4`):

```
> A0A40000020001                                 → 9000
> A0D6000010<sua_ki_32_hex>      → 9000
```

Autenticação ADM da família principal: `A020000B08 <chave em ASCII-hex>`
(fábrica: `88888888`). Documentação completa: `research/ax_macros.md`.

## Quirks macOS/hardware (importante!)

- Conectar **sempre forçando T=0** (`T0|T1` juntos → "card unresponsive")
- Não rodar `pcscd` do Homebrew junto com o stack nativo Apple (conflito);
  se existir: `sudo pkill -x pcscd`
- SELECT **loud** (P2=00 + GET RESPONSE) antes de operações sensíveis;
  select silencioso envenena o estado de alguns COS
- Após `CardConnectionException`, aguardar ≥1s antes de reconectar
- Firmware GreenCardCOS2014 trava o leitor em vez de retornar SW de erro em
  certas condições negadas — os retries da `CardSession` contornam isso

## Status

- ✅ Leitura/escrita de EFs normais validada em cartão real (ICCID/IMSI/MilPar)
- ✅ 42 famílias mapeadas; 29 com auth parseada limpa (13 ambíguas documentadas)
- ⚠️ Escrita de Ki/OPc requer cartão saudável — o cartão de teste teve o canal
  ADM bloqueado pelo firmware durante o desenvolvimento (ver `~/sim-yatebts.md`)
- Testes: `python3 -m pytest tests/` → 41 passed
