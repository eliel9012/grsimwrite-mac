"""simwriter - port macOS do GRSIMWrite (gravacao de SIM GSM via PC/SC).

Restricoes criticas de hardware/COS (validadas em cartao real XC-SCM-01/LY14):

- Conectar SEMPRE forçando protocolo T=0. No macOS, T0|T1 juntos retornam
  "unresponsive" no connect().
- Antes de qualquer operacao sensivel (UPDATE BINARY/RECORD, VERIFY ADM),
  usar SELECT "loud" (P2=00 + GET RESPONSE). SELECT silencioso (P2=0C)
  envenena o estado interno do COS.
- Apos CardConnectionException, aguardar >= 1s antes de reconectar.
- UPDATE BINARY em blocos <= 150 bytes (0x96).
"""

__version__ = "0.1.0"

from simwriter.session import CardSession
from simwriter.files import (
    EF_MAP,
    bcd_encode,
    bcd_decode,
    encode_iccid,
    decode_iccid,
    encode_imsi,
    decode_imsi,
    luhn_check_digit,
)

__all__ = [
    "__version__",
    "CardSession",
    "EF_MAP",
    "bcd_encode",
    "bcd_decode",
    "encode_iccid",
    "decode_iccid",
    "encode_imsi",
    "decode_imsi",
    "luhn_check_digit",
]
