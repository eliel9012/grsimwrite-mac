# Plano: Portagem do GRSIMWrite (card writer) para macOS

> Objetivo: gravar o cartão **XC-SCM-01 "LTE Blank USIM"** (Anordsem / XCRFID Store)
> nativamente no macOS, sem Windows, e integrar com YateBTS.

## 1. Estado atual da engenharia reversa

### O que já sabemos

| Item | Descoberta |
|---|---|
| Cartão | XC-SCM-01, perfil `LY14`, COS instalado, ATR `3B9F95801FC78031A073B6A10067CF3215CA9CD70920` |
| AID USIM | `A0000000871002FF86FF0389FFFFFFFF` |
| Estado | Virgem (ICCID/IMSI = `FF`) |
| Escrita DF_TELECOM (ADN) | ✅ livre, sem autenticação |
| Escrita DF_GSM (IMSI/ICCID/SPN) | ❌ bloqueada (`9804`) |
| VERIFY ADM (A0, q=0A) | `9840` — chave errada OU mecanismo errado |
| VERIFY (CLA=00) | `6983` — referência bloqueada/não é esse caminho |
| EXT AUTH (CLA=00, INS=82) | `6D00` — INS não suportado nesse contexto |
| Config `GRSIMWrite.grsp` | ADM default `3838383838383838` ("88888888"), PIN1 `1234`, PUK `88888888` |

### Mecanismo de autenticação descoberto na ICCAPI.dll

```
ICC_ExternalAuthByKey @ RVA 0x1dd0:
  1. GET CHALLENGE   → template em 0x10012414 ("00 84 00 00 08")
  2. chave: se string de diversificação presente → DiversifyKey_3
             senão → usa os 16 bytes crus passados pelo chamador (.exe)
  3. criptograma = DES(challenge, chave)      [rotina @ 0x4790]
  4. EXTERNAL AUTHENTICATE → template em 0x1001240c

ICC_BinaryFileWrite @ RVA 0x2470:
  - pré-chamada a 0x1c80 que PRECISA retornar SW 9000 (auth/select?)
  - escrita em blocos ≤150 bytes (0x96), template de APDU em 0x10012440

DiversifyKey_1/@0x4da0 e _3/@0x4e40:
  - DES duplo com inversão (~k) entre as passadas
MIDLL.dll exporta RijndaelKeySchedule (AES) — usado em perfis novos?
```

### Por que o sweep de EXT AUTH falhou (6D00)

O `6D00` (INS não suportado) com CLA=00 indica que montamos o comando no
contexto errado. Os templates reais estão em `.data @ 0x1240C–0x12460` —
**dumpar essa região resolve todas as dúvidas de CLA/P1/P2 de uma vez**.

## 2. Estratégias (em ordem de esforço)

### Estratégia A — Dump dos templates estáticos (horas)

1. Extrair `.data` da ICCAPI.dll nos RVAs `0x123F0–0x12480`
2. Reconstruir os APDUs exatos: GET CHALLENGE, EXT AUTH, UPDATE BINARY,
   SELECT usados pelo tool
3. Repetir o fluxo em Python (`pyscard` + `pyDes`) com chave "88888888"
4. Se diversificação estiver ativa, desmontar `DiversifyKey_*` e replicar

**Critério de sucesso:** sequência Python recebe `9000` no EXT AUTH.

### Estratégia B — Sniff do tráfego PC/SC sob Wine (meio dia)

Mata toda a incerteza: capturar o que o tool REALMENTE envia.

1. Instalar Wine (brew `--cask wine-stable` ou CrossOver)
2. Rodar `GRSIMWrite.exe` + leitor AU9540 (CCID funciona via pcscd do Wine? 
   alternativa: usar wrapper winscard.dll próprio)
3. **Shim winscard.dll**: DLL fake que loga `SCardTransmit`/`SCardStatus`
   e repassa pra real → dump completo dos APDUs autenticados
4. Replay nativo dos APDUs capturados

Alternativa mais simples ainda: rodar num Windows virtual (UTM) com um
proxy PC/SC (ex.: `pcsc-relay` / vitualreader) e logar tudo.

### Estratégia C — Desmontar o chamador no .exe (dias)

1. Achar onde GRSIMWrite.exe monta a struct de chave (Delphi, strings
   length-prefixed) e o valor default de ADM usado quando o usuário não digita
2. Entender `CardInfo.ChangeADM=0` vs `1` (talvez o fluxo mude)
3. Extrair constante mestre da diversificação se houver

### Estratégia D — Pedir ao vendedor (paralelo, custo zero)

Chat da XCRFID Store pedindo "ADM key" ou o software. Não depende de RE.

## 3. Roadmap de implementação nativa (pós-auth resolvido)

- [ ] `simwriter/auth.py` — GET CHALLENGE + DES + EXT AUTH (portagem do fluxo)
- [ ] `simwriter/write.py` — UPDATE BINARY/RECORD com blocos ≤150B
- [ ] `simwriter/files.py` — mapa EF (ICCID, IMSI, AD, SPN, SST, LOCI…)
- [ ] CLI: `write-card --iccid --imsi --ki --opc --pin --adm`
- [ ] Verificação pós-gravação (read-back de todos os campos)
- [ ] Gerador de credenciais (Ki/OPc aleatórios seguros, IMSI PLMN 001-01)
- [ ] Export direto pro `subscribers.conf` do YateBTS
- [ ] Testes com cartão real + documentação do processo completo

## 4. Riscos e observações

- Firmware do cartão tem bug: UPDATE BINARY no ICCID sem auth **trava o
  leitor** (NOT_TRANSACTED) em vez de retornar SW — sempre autenticar antes
- No macOS, conectar forçando **T=0 apenas** (`T0|T1` juntos dá unresponsive);
  matar `pcscd` do Homebrew se existir (conflito com CryptoTokenKit)
- Chaves ADM têm contadores possíveis: limitar tentativas por sessão
- Uso restrito a cartões próprios / rede privada de laboratório

## 5. Referências do material analisado

- Pacote: `card_reader_UDisk_4.4.10.rar` (não versionado neste repo)
  - `GRSIMWrite.exe` (PE32 Delphi), `ICCAPI.dll`, `GRCOSEN.dll`, `GRRGST.dll`,
    `MIDLL.dll`, `GRSIMWrite.grsp` (config texto), manual PDF
- Manual aponta suporte: info@gialer.com / smacarte.com
- Avaliação pública confirma: "escrito pelo GRSIMWrite 4.4.10"
