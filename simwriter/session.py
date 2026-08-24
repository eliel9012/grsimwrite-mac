"""CardSession: encapsulamento pyscard para SIM GSM (T=0).

Restricoes criticas de hardware/COS (validadas em cartao real):

- Conexao SEMPRE com protocolo T=0 forcado (CardConnection.T0_protocol).
  No macOS, conectar com T0|T1 combinados retorna "unresponsive".
- tx() retransmite apos CardConnectionException, aguardando >= 1s
  antes de reconectar (o COS precisa do intervalo para recuperar).
- select_loud() usa P2=00 + GET RESPONSE para SW 9Fxx/61xx. O COS exige
  a coleta da resposta; SELECT silencioso (P2=0C) antes de operacoes
  sensiveis envenena o estado e quebra gravacoes seguintes.
- update_binary() fatia dados em blocos <= 150 bytes (0x96); blocos
  maiores sao rejeitados pelo cartao.
"""

import time

from smartcard.System import readers
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import CardConnectionException

RECONNECT_DELAY_S = 1.2
MAX_UPDATE_CHUNK = 150
MAX_READ_CHUNK = 255


class CardSession:
    """Sessao T=0 com um cartao SIM no leitor PC/SC."""

    def __init__(self, reader_index=0):
        self.reader_index = reader_index
        self.reader = None
        self.conn = None
        self.atr = b""

    def connect(self):
        """Conecta ao leitor forcando T=0. Retorna o ATR.

        CRITICO (macOS): protocolo T0 puro. T0|T1 da "unresponsive".
        """
        rs = readers()
        if not rs:
            raise RuntimeError("nenhum leitor PC/SC encontrado")
        if self.reader_index >= len(rs):
            raise RuntimeError(
                f"leitor {self.reader_index} inexistente ({len(rs)} disponivel(is))"
            )
        self.reader = rs[self.reader_index]
        conn = self.reader.createConnection()
        conn.connect(protocol=CardConnection.T0_protocol)
        self.conn = conn
        self.atr = bytes(conn.getATR())
        return self.atr

    def disconnect(self):
        if self.conn is not None:
            try:
                self.conn.disconnect()
            except Exception:
                pass
            self.conn = None

    def reconnect(self):
        """Desconecta e reconecta. Aguarda >= 1s antes de religar o canal.

        O COS do cartao requer esse intervalo apos falha de transmissao;
        reconexao imediata devolve "unresponsive"/CardConnectionException.
        """
        time.sleep(RECONNECT_DELAY_S)
        self.disconnect()
        return self.connect()

    def tx(self, apdu_hex, retries=5):
        """Transmite APDU hex, retornando (sw_hex, data_bytes).

        Em CardConnectionException reconecta (com pausa >= 1s) e retransmite,
        ate esgotar `retries`.
        """
        apdu = list(bytes.fromhex(apdu_hex))
        last_exc = None
        for attempt in range(retries):
            try:
                data, sw1, sw2 = self.conn.transmit(apdu)
                return f"{sw1:02X}{sw2:02X}", bytes(data)
            except (CardConnectionException,) as exc:
                last_exc = exc
                if attempt == retries - 1:
                    raise
                self.reconnect()
        raise last_exc

    @staticmethod
    def is_ok(sw):
        return sw == "9000"

    @staticmethod
    def _has_response(sw):
        return sw.startswith(("9F", "61"))

    def select_loud(self, fid, df=None):
        """SELECT por FID (P2=00) com GET RESPONSE para SW 9Fxx/61xx.

        Se `df` informado, seleciona o DF primeiro (selecao passo-a-passo).
        Retorna (sw, fcp_bytes).

        USAR ANTES DE QUALQUER OPERACAO SENSIVEL: o COS exige que o GET
        RESPONSE seja consumido; SELECT silencioso (P2=0C) envenena o
        estado interno e corrompe gravacoes subsequentes.
        """
        if df:
            sw, _ = self.tx(f"A0A4000002{df}")
            if not (sw == "9000" or self._has_response(sw)):
                return sw, b""
        sw, _ = self.tx(f"A0A4000002{fid}")
        fcp = b""
        if self._has_response(sw):
            n = int(sw[2:], 16)
            sw, fcp = self.tx(f"A0C00000{n:02X}")
        return sw, fcp

    def select_silent(self, fid):
        """SELECT P2=0C (sem corpo de resposta). Nao usar antes de ops sensiveis."""
        sw, _ = self.tx(f"A0A4000C02{fid}")
        return sw

    def read_binary(self, length, offset=0):
        """READ BINARY (INS B0). Corrige SW 6Cxx reemitindo com Le correto."""
        sw, data = self.tx(f"A0B0{offset:04X}{length:02X}")
        if sw.startswith("6C"):
            n = int(sw[2:], 16)
            sw, data = self.tx(f"A0B0{offset:04X}{n:02X}")
        return sw, data

    def update_binary(self, data, offset=0):
        """UPDATE BINARY (INS D6) em blocos <= 150 bytes (0x96).

        Retorna o SW do ultimo bloco ("9000" em sucesso); interrompe no
        primeiro erro e retorna esse SW.
        """
        if not data:
            return "9000"
        sw = "9000"
        for i in range(0, len(data), MAX_UPDATE_CHUNK):
            chunk = bytes(data[i : i + MAX_UPDATE_CHUNK])
            off = offset + i
            sw, _ = self.tx(f"A0D6{off:04X}{len(chunk):02X}" + chunk.hex())
            if not self.is_ok(sw):
                return sw
        return sw

    def read_record(self, rec, length=32):
        """READ RECORD absoluto (P2=04). Corrige SW 67xx com o comprimento sugerido."""
        sw, data = self.tx(f"A0B2{rec:02X}04{length:02X}")
        if sw.startswith("67"):
            n = int(sw[2:], 16)
            if n > 0:
                sw, data = self.tx(f"A0B2{rec:02X}04{n:02X}")
        return sw, data

    def update_record(self, rec, data):
        """UPDATE RECORD absoluto (INS DC, P2=04)."""
        payload = bytes(data)
        sw, _ = self.tx(f"A0DC{rec:02X}04{len(payload):02X}" + payload.hex())
        return sw

    def verify(self, hex_data, qualifier="01"):
        """VERIFY generico (INS 20): A02000{qualifier}{len}+dados.

        qualifier: 01=CHV1, 08=CHV2, 0A/0B=ADM (depende do COS).
        """
        n = len(hex_data) // 2
        sw, _ = self.tx(f"A02000{qualifier}{n:02X}{hex_data}")
        return sw

    def get_challenge(self, n=8):
        """GET CHALLENGE (INS 84) + GET RESPONSE se 9Fxx/61xx."""
        sw, data = self.tx(f"A0880000{n:02X}")
        if self._has_response(sw):
            m = int(sw[2:], 16)
            sw, data = self.tx(f"A0C00000{m:02X}")
        return sw, data

    def auth_adm(self, key_hex="3838383838383838", qualifier="0B"):
        """VERIFY ADM: A02000{qualifier}08 + chave.

        Padrao do cartao XC-SCM-01 (LY14): q=0B, chave ASCII "88888888"
        codificada em hex como 3838383838383838. Seleciona o MF loud antes,
        replicando o fluxo validado em cartao real.
        """
        self.select_loud("3F00")
        return self.verify(key_hex, qualifier=qualifier)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.disconnect()
        return False
