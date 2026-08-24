"""CLI do simwriter: identify / read / write / info.

Uso: python3 -m simwriter <comando> [opcoes]

Fluxo de gravacao segue o padrao validado em cartao real (XC-SCM-01/LY14):
SELECT loud antes de cada operacao sensivel; VERIFY ADM q=0B com
"88888888" (hex 3838383838383838); UPDATE BINARY em blocos <= 150 bytes;
conexao sempre T=0 (no macOS T0|T1 da "unresponsive").
"""

import argparse
import sys

from simwriter import __version__
from simwriter.files import (
    EF_MAP,
    decode_iccid,
    decode_imsi,
    encode_iccid,
    encode_imsi,
)
from simwriter.session import CardSession

DEFAULT_AUTH_KEY = "3838383838383838"
AUTH_QUALIFIER = "0B"


def _open_session(reader_index):
    session = CardSession(reader_index=reader_index)
    atr = session.connect()
    print(f"[OK] leitor: {session.reader}")
    print(f"     ATR: {atr.hex().upper()}")
    return session


def cmd_identify(args):
    _open_session(args.reader)
    return 0


def cmd_info(_args):
    print(f"simwriter {__version__} - port macOS do GRSIMWrite")
    return 0


def _read_transparent(session, ef):
    size = EF_MAP[ef]["size"]
    data = b""
    offset = 0
    while offset < size:
        chunk = min(size - offset, 255)
        sw, part = session.read_binary(chunk, offset)
        if not CardSession.is_ok(sw):
            return None, sw
        data += part
        offset += len(part)
        if len(part) < chunk:
            break
    return data[:size], "9000"


def _read_records(session, ef):
    rec_size = EF_MAP[ef]["size"]
    records = []
    for rec in range(1, 11):
        sw, data = session.read_record(rec, rec_size)
        if not CardSession.is_ok(sw):
            break
        records.append(data)
    return records, "9000" if records else "6B00"


def cmd_read(args):
    names = args.ef or list(EF_MAP)
    for name in names:
        if name.upper() not in EF_MAP:
            print(f"[!] EF desconhecido: {name} (validos: {', '.join(EF_MAP)})")
            return 2
    session = _open_session(args.reader)
    try:
        for name in names:
            name = name.upper()
            info = EF_MAP[name]
            try:
                sw, _fcp = session.select_loud(info["fid"], df=info["df"])
                if not CardSession.is_ok(sw) and not sw.startswith(("9F", "61")):
                    print(f"{name:<8} ({info['fid']} @{info['df'] or 'MF'}): SW={sw}")
                    continue
                if info["tipo"] == "record":
                    records, rsw = _read_records(session, name)
                    if records:
                        joined = " | ".join(r.hex() for r in records)
                        print(f"{name:<8} ({info['fid']} @{info['df'] or 'MF'}): {joined}")
                    else:
                        print(f"{name:<8} ({info['fid']} @{info['df'] or 'MF'}): SW={rsw} (sem registros)")
                else:
                    data, rsw = _read_transparent(session, name)
                    if data is None:
                        print(f"{name:<8} ({info['fid']} @{info['df'] or 'MF'}): SW={rsw}")
                    else:
                        extra = ""
                        if name == "ICCID":
                            extra = f"  -> {decode_iccid(data)}"
                        elif name == "IMSI":
                            extra = f"  -> {decode_imsi(data)}"
                        print(
                            f"{name:<8} ({info['fid']} @{info['df'] or 'MF'}): "
                            f"{data.hex()}{extra}"
                        )
            except Exception as exc:
                print(f"{name:<8}: ERRO {type(exc).__name__}: {exc}")
    finally:
        session.disconnect()
    return 0


def _validate_write_args(args):
    if not args.imsi.isdigit() or not 6 <= len(args.imsi) <= 15:
        raise SystemExit(f"[!] IMSI invalido (6-15 digitos): {args.imsi!r}")
    iccid = args.iccid.strip()
    if not iccid.isdigit() or len(iccid) not in (19, 20):
        raise SystemExit(f"[!] ICCID invalido (19 ou 20 digitos): {iccid!r}")


def cmd_write(args):
    _validate_write_args(args)
    key_hex = args.auth_key.strip().lower()
    try:
        bytes.fromhex(key_hex)
    except ValueError:
        raise SystemExit(f"[!] chave de autenticacao nao-hex: {args.auth_key!r}")
    if len(key_hex) != 16:
        raise SystemExit("[!] chave de autenticacao deve ter 8 bytes (16 hex)")

    imsi_b = encode_imsi(args.imsi)
    iccid_b = encode_iccid(args.iccid)

    session = _open_session(args.reader)
    try:
        print(f"[*] autenticando ADM (q={AUTH_QUALIFIER})...")
        sw = session.auth_adm(key_hex=key_hex, qualifier=AUTH_QUALIFIER)
        if not CardSession.is_ok(sw):
            print(f"[!] AUTH falhou: SW={sw}")
            return 1
        print("[OK] autenticado")

        results = []
        for label, fid, df, payload in (
            ("IMSI", "6F07", "7F20", imsi_b),
            ("ICCID", "2FE2", None, iccid_b),
        ):
            sw_sel, _fcp = session.select_loud(fid, df=df)
            if not CardSession.is_ok(sw_sel):
                print(f"[!] SELECT {label} {fid} falhou: SW={sw_sel}")
                results.append((label, f"SEL:{sw_sel}", False))
                continue
            sw_w = session.update_binary(payload)
            sw_v, back = session.read_binary(len(payload))
            ok = (
                CardSession.is_ok(sw_w)
                and CardSession.is_ok(sw_v)
                and back == payload
            )
            status = "OK" if ok else f"FALHOU (w={sw_w} v={sw_v})"
            print(f"[{'OK' if ok else '!!'}] {label} {fid}: {status}")
            results.append((label, status, ok))

        if all(ok for _, _, ok in results):
            print(f"\nGravado: IMSI={args.imsi} ICCID={args.iccid.strip()}")
            return 0
        return 1
    finally:
        session.disconnect()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="simwriter",
        description=f"simwriter {__version__} - port macOS do GRSIMWrite (gravacao de SIM GSM)",
    )
    parser.add_argument(
        "--reader",
        type=int,
        default=0,
        help="indice do leitor PC/SC (default: 0)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_identify = sub.add_parser("identify", help="mostra leitor e ATR do cartao")
    p_identify.set_defaults(func=cmd_identify)

    p_read = sub.add_parser("read", help="le todos os EFs ou os EFs indicados")
    p_read.add_argument(
        "--ef",
        nargs="*",
        default=None,
        metavar="NOME",
        help=f"EFs a ler ({', '.join(EF_MAP)}); omita para ler tudo",
    )
    p_read.set_defaults(func=cmd_read)

    p_write = sub.add_parser("write", help="grava ICCID/IMSI no cartao")
    p_write.add_argument("--iccid", required=True, help="ICCID (19 digitos; Luhn calculado)")
    p_write.add_argument("--imsi", required=True, help="IMSI (ate 15 digitos)")
    p_write.add_argument(
        "--auth-key",
        default=DEFAULT_AUTH_KEY,
        help=f"chave ADM em hex (default: {DEFAULT_AUTH_KEY} = ASCII '88888888')",
    )
    p_write.set_defaults(func=cmd_write)

    p_info = sub.add_parser("info", help="versao do pacote")
    p_info.set_defaults(func=cmd_info)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
