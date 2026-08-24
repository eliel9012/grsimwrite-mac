# RE: construção das APDUs das macros Ax(KI), Ax(OPC), AxADM(ADM), AxCHV(PIN/PUK) no GRSIMWrite.exe

Binário: `research/vendor/GRSIMWrite.exe` — PE32 Delphi, ImageBase **0x400000**.
Seções: `.text` RVA 0x1000 (raw 0x400), `.data` RVA 0x17000 (raw 0x16E600).
Conversão: **VA = 0x400000 + RVA**, e para `.text`: **VA = file_offset + 0x400C00**.

> Correção de premissa da Fase 2: as tabelas de texto NÃO estão em `.data`
> (`.data` tem só 0x3580 bytes). Estão em `.text`, como blocos repetidos por
> perfil (file offsets ~0xA8ACC–0x11A954 confirmados). Os cabeçalhos Delphi
> (`FFFFFFFF` refcount + length) precedem cada string.

---

## 1. Endereços-chave descobertos

### Camada de registro de macros (perfil → nós)

| VA | Papel | Assinatura (convenção Borland register) |
|---|---|---|
| **0x51xxxx região 0x511DDA–0x511F85** | init do perfil LY14: registra todos os nós na ordem fixa | inline |
| **0x4A43E8** | `AddNode(obj, edx=cmdline, ecx=expected_sw, stack:(p1,p2,name))` | nó genérico da árvore |
| **0x4A4A0C** | `AddSelectNode(obj, edx=FID, ecx=name)` | gera linha `SELECT` |
| **0x4A4DD4** | `AddWriteMacro(obj, edx=FID, ecx=template, stack:(type,value,name))` | gera SELECT + UPDATE(s) |
| 0x49442C / 0x40EB2C | split por delimitador / strip de espaços | helpers |
| 0x495100 | `IntToHex(value, digits)` (global^, val, dig, out) | helper |
| 0x409784 | **UPPERCASE SWAR** (magic 0x7b7b7b7b / 0x66666666) | força hex maiúsculo |
| 0x4054E8 / 0x40546C / 0x41944C / 0x414894 | concat/acumulação de strings | helpers |

Constantes de formato (em `.text`, próximas a 0x4A53xx):

| VA | String |
|---|---|
| 0x4A5330 | `"A0"` |
| 0x4A533C | `"00"` |
| 0x4A5348 | `"D60000"` (UPDATE BINARY offset 0, caminho single-shot) |
| 0x4A5378 | `"D6"` (caminho chunked) |
| 0x4A5368 / 0x512120 | `"9000"` (SW esperada de write e de select) |
| 0x4A5358 | `"Write "` (label UI) |
| 0x4A4BEC | `"00A4000C02 "` (SELECT quando perfil “modo 100”) |
| 0x4A4C10 | `"A0A4000002 "` (SELECT padrão) |
| 0x498658 | `"A020"` (prefixo VERIFY detectado em SendCommand) |
| 0x498678 | `"9000 9802 9808"` (SWs aceitas p/ VERIFY) |

### Substituição de placeholders — `0x495CCC`

```
Substitute(formObj^, edx=TEMPLATE, ecx=VALUE_STRING, out):
  parts   = SplitRegEx(VALUE_STRING, ';')        # 0x49442C, delim ';' @0x495E28
  s       = TEMPLATE
  i       = 0
  while '[' (@0x495E34) occurs in s:
      pre   = s[:pos('[')]
      token = s[pos('[')+1 : pos(']')]           # ']' @0x495E40
      suf   = s[pos(']')+1:]
      s     = pre + ' ' + TRIM(parts[i]) + ' ' + suf   # espaços inseridos!
      i += 1
  out = TRIM_ALL_SPACES(s)                        # 0x40EB2C remove TODOS os espaços
```

Ou seja: o valor chega como lista separada por `;` e os tokens `[XXX]` são
substituídos **em ordem** (é por isso que o init concatena `PIN1;PUK1` num
valor só para o macro `AxCHV(PIN1),AxCHV(PUK1)`). Depois todos os espaços são
removidos. **Hex direto, sem BCD, sem inversão, sem cifra.**

### Construção da linha de UPDATE — `AddWriteMacro` 0x4A4DD4

```
payload  = StripSpaces(Substitute(template, value))       # ex: "[KI]" -> "BEDF...3B"
nbytes   = len(payload) div 2                             # sar esi,1
if nbytes <= 0xFF:                                        # caminho único (path A)
    line = CLA + "D60000" + IntToHex(nbytes,2) + " " + Uppercase(payload)
else:                                                     # loop chunks ≤255 (path B)
    off = 0
    while remaining > 0:
        n    = min(remaining, 255)
        line = CLA + "D6" + IntToHex(off,4) + IntToHex(n,2) + " " + Uppercase(copy(payload, 2*off+1, 2*n))
        off += n
AddNode(obj, line, "9000", ...)                           # nó com SW esperada 9000
```

`CLA` é escolhido por `0x49478C(global^, flag=(profile.field_1C==100), "00", acc, "A0")`:
- perfil normal → **`A0`**
- `profile.field_1C == 0x64` (100) → **`00`** (mesma regra usada nos SELECTs `00A4000C02` vs `A0A4000002`).

### SELECT — `AddSelectNode` 0x4A4A0C

```
normal:            AddNode(obj, "A0A4000002 " + FID, "9000", ...)
perfil modo 100:   AddNode(obj, "00A4000C02 " + FID, "9000", ...)
```

### Camada de envio

| VA | Papel |
|---|---|
| **0x497898** | `SendCommand(self, edx=line, arg, outSW)` — remove espaço final; se linha começa com `A020`/`0020` usa conjunto de SWs `9000 9802 9808`; caso normal converte hex→bytes (0x493D8C) e chama SCardTransmit |
| 0x497974 | variante T=0 (buffers de 300 bytes) dentro do SendCommand |
| **0x498A60** | `RunCommand` — trata GET RESPONSE/wrap `00A4040C` e comandos curtos (=FIDs) gerando SELECT |
| **0x498910** | primitiva de SELECT: cmd começando com `'A'` → `00A40404<len/2,02><cmd>` (select por AID); senão `A0A4000002<cmd>` (ou `00A4000402` no modo 100) |
| 0x496558 | thunk `jmp dword ptr [0x5DC060]` = **SCardTransmit** (import estático de Winscard.dll; thunks em 0x496538–0x496560) |
| **0x51D188** | dispatcher principal por **ATR** do cartão → handler dedicado por modelo |

Struct global de dados do cartão: ponteiro em **0x5731C4**;
offsets `+0x10`=PIN1, `+0x14`=PIN2, `+0x18`=PUK1, `+0x1C`=PUK2, `+0x20`=ADM,
`+0x74`=KI, `+0x78`=OPc.

---

## 2. Respostas diretas

### (a) Qual INS grava nos arquivos de chave na família FILE-BASED?

**INS = 0xD6 (UPDATE BINARY) padrão ISO.** Não há INS proprietário nem cifra.
A linha registrada é:

```
A0 D6 <P1P2=offset 2B> <Lc> <dados>          (SW esperada: 9000)
```

precedida de um nó SELECT próprio do arquivo:

```
A0 A4 00 00 02 <FID 2B>                      (SW esperada: 9000)
```

**Não há re-autenticação antes de cada write no motor de macros** — nenhum
VERIFY/AUTHENTICATE é injetado por `AddWriteMacro` (0x4A4DD4). Autenticação só
aparece: (i) como nó explícito do perfil ("Check Card" = `A058000008[SADM]`),
(ii) nos handlers dedicados por ATR (ex.: 0x4AAB70 faz
`A020000B08<ADM>` antes dos writes D4). Se um UPDATE trava o leitor no cartão
real, a causa está nas condições de acesso do cartão, não em mecanismo oculto
do tool — o tool envia o D6 "cru". *(validar em cartão real)*

### (b) Como o placeholder vira bytes?

- `[KI]` → substituição **textual direta** do hex digitado (uppercase
  forçado por 0x409784). Sem BCD, sem swap.
- `[OPC]` → template `01[OPC]`: byte prefixo **0x01** + OPc (17 bytes totais),
  arquivo EF 6002.
- `[PIN]/[PUK]/[ADM]` → dígitos tratados como **nibble-hex**: PIN `1234` vira
  bytes `12 34`. O template `000000[PIN1]8383[PUK1]8A8A` produz
  13 bytes (3 + 2 + 1 + 1 + 4 + 1 + 1).
- Valores múltiplos chegam separados por `;` e preenchem os tokens em ordem.

### (c) Cifragem?

**Nenhuma no caminho de escrita.** Pipeline: texto → strip de espaços →
hex→bytes (0x493D8C) → buffer plano direto no `SCardTransmit`. As rotinas DES
(`DES_3_encrypt`, `DiversifyKey_1/_3` em ICCAPI/GRCOSEN) não são referenciadas
por `SendCommand`/`AddWriteMacro`/handlers de write analisados.

### (d) Ordem exata

Nós registrados pelo perfil FILE-BASED/LY14 (init 0x511DDA–0x511F85), executados
nessa ordem; **cada item = SELECT + WRITE(S)**, exceto o Check Card:

```
1. Check Card         : A058000008[SADM]                    (sem select)
2. PIN1_PUK1          : sel 0100 → A0D600000D <000000[PIN1]8383[PUK1]8A8A>
3. PIN2_PUK2          : sel 0200 → A0D600000D <010000[PIN2]8383[PUK2]8A8A>
4. AxADM(ADM)         : sel 0B00 → A0D6000009 <010000[ADM]8A8A>
5. Ax(KI)             : sel 0001 → A0D6000010 <KI 32 hex>
6. Ax(OPC)            : sel 6002 → A0D6000011 <01[OPC]>
7. MilenageParameter  : sel 2FE5 → A0D6000005081C2A0001
8. RC                 : sel 2FE6
```

Para outros estilos: **FB-DIRECT** (`A0FB<P1P2><Lc> <magic8><dados>`) e
**D4-DIRECT** (`A0D4<addr><Lc=08><dados>`) não usam select de arquivo; handlers
por ATR podem fazer VERIFY ADM primeiro (ex. 0x4AAB70:
`A020000B08<ADM-hex>` aceitando SW `9000`/`9804`, depois SELECT `3F00`,
depois os D4).

---

## 3. Exemplos concretos (LY14, FILE-BASED, CLA=A0)

Dados: `Ki=0123456789ABCDEF0123456789ABCDEF`,
`OPc=FEDCBA9876543210FEDCBA9876543210`, `ADM=88888888`, `PIN1=1234`,
`PUK1=88888888`.

```
# Ax(KI) — EF 0001
> A0A40000020001                                  [+SW 9000]
> A0D60000100123456789ABCDEF0123456789ABCDEF      [+SW 9000]

# Ax(OPC) — EF 6002 (prefixo 01)
> A0A40000026002                                  [+SW 9000]
> A0D600001101FEDCBA9876543210FEDCBA9876543210    [+SW 9000]

# AxADM(ADM) — EF 0B00, template 010000[ADM]8A8A
> A0A40000020B00                                  [+SW 9000]
> A0D6000009010000888888888A8A                    [+SW 9000]

# AxCHV(PIN1),AxCHV(PUK1) — EF 0100, valor "1234;88888888"
> A0A40000020100                                  [+SW 9000]
> A0D600000D00000012348383888888888A8A            [+SW 9000]
```

Nota: a linha interna do tool mantém UM espaço antes dos dados
(`A0D6000010 BEDF…`) apenas para exibição; o SendCommand remove todos os
espaços antes de transmitir.

---

## 4. Evidência resumida (endereços → trechos)

- `push 0x51A520 ("Ax(KI)") / mov ecx,0x51A530 ("[KI]") / mov edx,0x51A540
  ("0001") / call 0x4A4DD4` @ **0x511F0C–0x511F2B** → registro Ax(KI).
- `mov edx,0x51A55C ("Ax(OPC)") … ecx,0x51A56C ("01[OPC]") … edx,0x51A57C
  ("6002")` @ **0x511F3B–0x511F5A** → registro Ax(OPC).
- `push 0x51A4CC ("ADM") / push [cfg+0x20] / push 0x51A4D8 / ecx,0x51A4EC
  ("010000[ADM]8A8A") / edx,0x51A504 ("0B00") / call 0x4A4DD4` @
  **0x511ED6–0x511EF5**.
- `cmp esi,0x100 / jge chunked` e constantes `"D60000"`/`"D6"` dentro de
  0x4A4DD4 (path A @0x4A4E93+, path B @0x4A5007–0x4A5223).
- `call 0x496558 (SCardTransmit)` sites: **0x497A46, 0x497D92, 0x498099,
  0x498363** — todos recebem buffer já convertido de hex plano.
