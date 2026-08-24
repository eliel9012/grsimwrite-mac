# Notas de análise — ICCAPI.dll / GRSIMWrite 4.4.10

Análise feita com pefile + capstone em macOS (sem execução do binário).

## ICCAPI.dll — exports relevantes

```
DiversifyKey_1 @ RVA 0x4da0     DES duplo com inversão entre passadas (rotina @0x4560)
DiversifyKey_3 @ RVA 0x4e40     idem, rotina DES @0x4790
ICC_ExternalAuthByKey @ 0x1dd0  GET CHALLENGE -> diversifica/usa chave ->
                                DES(challenge,key) -> EXT AUTH via templates .data
ICC_BinaryFileWrite @ 0x2470    pre-chamada 0x1c80 (precisa SW 9000) + blocos <=150B,
                                template APDU word em 0x10012440
ICC_VerifyPin @ 0x2190          monta APDU com tamanho = len(pin)+5 e envia
WriteBinFile @ 0x2900           usa 0x8101/0x180 — caminho "UDisk", nao cartao
```

## Templates APDU em .data (confirmar com dump 0x123F0–0x12480)

| Endereço global | Conteúdo provável |
|---|---|
| `0x10012414` (+byte `0x10012418`) | GET CHALLENGE `00 84 00 00` + Le `08` |
| `0x1001240c` (+byte `0x10012410`) | EXTERNAL AUTHENTICATE (INS 82) |
| `0x10012440` (word) | UPDATE BINARY (CLA+INS?) |

Padrões encontrados no raw: GETCHAL em file offset 0x12414; hits de `0082`
em 0xd7, 0x10db3, 0x1240c, 0x12a3f, 0x12eab.

## GRSIMWrite.grsp — perfil do cartão (texto)

- `CardInfo.Code=LY14`, `Name=LTE`, `Func=LTE+GSM`
- `ATR=3B9F95801FC78031A073B6A10067CF3215CA9CD70920` ← bate com nosso cartão
- `AID_USIM=A0000000871002FF86FF0389FFFFFFFF`
- `EditADM Value=3838383838383838` ("88888888" ASCII)
- PIN1/PUK default `1234`/`88888888`
- `CardInfo.ChangeADM=0`
- Algoritmos: `MLG=-1` habilitado; COMP128 desligados → Milenage/XOR interno?

## Status words observados no cartão real

| Comando | SW | Interpretação |
|---|---|---|
| VERIFY A0 q=0A chave errada | `9840` | auth falhou (sem contador visível) |
| VERIFY CLA=00 | `6983` | referência bloqueada nesse contexto |
| EXT AUTH CLA=00 INS=82 | `6D00` | INS não suportado no contexto testado |
| UPDATE BINARY ICCID sem auth | crash leitor | bug firmware (NOT_TRANSACTED) |
| UPDATE BINARY SPN/HPLMN/GID1 sem auth | `9804` | acesso negado limpo |
| UPDATE RECORD ADN | `9000` | escrita livre funciona |
