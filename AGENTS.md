# AGENTS.md

Guia para agentes de IA (e humanos) trabalhando neste repositório.

## Visão geral

Port macOS em Python do GRSIMWrite 4.4.10 (tool Windows de gravação de SIM
GSM/USIM via PC/SC). Suporta as 42 famílias de cartão mapeadas por engenharia
reversa do binário original. CLI-first (`python3 -m simwriter`).

## Comandos essenciais

```bash
pip3 install -r requirements.txt      # pyscard, pydes
python3 -m pytest tests/ -q           # 41+ testes, 100% offline (mocks)
python3 -m compileall simwriter/      # checagem sintática rápida
python3 -m simwriter --help           # smoke da CLI (não precisa de hardware)
```

## Estrutura

| Caminho | Conteúdo |
|---|---|
| `simwriter/session.py` | `CardSession`: PC/SC T=0 forçado, retries com reconexão, selects loud/silent |
| `simwriter/files.py` | Mapa de EFs GSM (14) + codecs BCD/Luhn/IMSI/ICCID |
| `simwriter/families.py` | Parse dos 42 perfis (`research/profiles.json`), normalização de placeholders |
| `simwriter/dispatch.py` | `write_card()` end-to-end: auth → writes → verificação read-back |
| `simwriter/keyengine.py` | Escrita de chaves nos 3 estilos: file-based / FB-direct / D4-direct |
| `simwriter/format.py` | Engine CREATE FILE: 2245 templates / 14 clusters por família |
| `tests/` | pytest puro com mocks — hardware nunca é requisito |
| `research/` | Dados de RE (profiles.json, format_templates.json, ax_macros.md) |
| `research/vendor/` | **GITIGNORED** — binários originais do tool (não versionar!) |
| `docs/PLANO.md` | Plano original em fases |

## Regras críticas do domínio (não quebre!)

1. Conectar SEMPRE com protocolo T=0 isolado — pedir `T0|T1` juntos faz o
   leitor retornar "card unresponsive"
2. SELECT **loud** (P2=00 + GET RESPONSE quando SW 9Fxx/61xx) antes de
   operações sensíveis; select silencioso (P2=0C) envenena o estado de alguns COS
3. UPDATE BINARY em blocos ≤ 150 bytes (0x96)
4. Após `CardConnectionException`, aguardar ≥ 1 s antes de reconectar
5. Escrita de chave = SELECT → D6 puro. Sem cifra, sem re-auth, sem INS
   proprietário — evidências em `research/ax_macros.md` (AddWriteMacro @0x4A4DD4)
6. Auth ADM da família principal: `A020000B08 <chave em ASCII-hex>`
   (fábrica `88888888`; outras conhecidas: `29083011`, `0102030405060708`)
7. Placeholders dos perfis: `[SADM]` em op = comando de AUTH, nunca escrita;
   `[OPC]` ganha prefixo `\x01`; KI entra como bytes.fromhex; PIN/PUK como ASCII

## Políticas do repositório

- **NUNCA** commitar credenciais reais de cartão (Ki/OPc de usuários). Use os
  vetores fake canônicos. O histórico já foi purgado uma vez por isso.
- **NUNCA** commitar binários vendor (`*.exe`, `*.dll` gitignored).
- Testes devem permanecer 100% offline; hardware é opcional para dev.
- Commits no estilo conventional, um tema por commit.

## Vetores de teste canônicos

| Campo | Valor | Observação |
|---|---|---|
| IMSI | `001010123456789` | encode esperado: `0800010121436587f9` (validado em cartão real) |
| ICCID | `89882100000000000012` | Luhn válido |
| Ki fake | `0123456789ABCDEF0123456789ABCDEF` | placeholder documentação |
| OPc fake | `FEDCBA9876543210FEDCBA9876543210` | placeholder documentação |
| ATR LY14 | `3b9f95801fc78031a073b6a10067cf3215ca9cd70920` | perfil índice 38 |

## Pontos abertos conhecidos

- 13 perfis com auth ambígua na extração (índices 8–16, 20–22, 41) — ver
  `simwriter/families.py`
- `detect_family()` só tem ATR exato para o perfil 38 (LY14); demais exigem
  seleção manual por índice
- Escrita file-based de chaves foi validada apenas até o nível de APDU; validação
  em cartão físico pendente (cartão de teste teve canal ADM bloqueado pelo firmware)
