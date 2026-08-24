# grsimwrite-mac

Portagem do fluxo de gravação do GRSIMWrite 4.4.10 (cartão XC-SCM-01 "LTE Blank
USIM") para macOS — sem Windows — com integração YateBTS.

## Status

🔬 Engenharia reversa em andamento. Ver **[docs/PLANO.md](docs/PLANO.md)**.

## Estrutura

```
docs/PLANO.md          plano + achados da RE
scripts/sim_dump.py    leitor/dumper completo do SIM via APDU T=0
scripts/adm_probe.py   varredura VERIFY / EXT AUTH por chaves candidatas
research/              notas de análise dos binários
```

## Uso rápido (leitura)

```bash
python3 scripts/sim_dump.py        # lê todos os EF e gera resumo
```

Requisitos: `pip install pyscard pydes pefile capstone pypdf`

## Notas macOS

- Conectar forçando protocolo T=0 apenas
- Não rodar `pcscd` do Homebrew junto (conflita com CryptoTokenKit)
