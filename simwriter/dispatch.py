"""write_card: despacho de alto nivel — autentica e grava uma familia no cartao.

Fluxo (usa CardSession de simwriter/session.py):
    1. SELECT MF "loud" e sequencia de APDUs de autenticacao da familia
       (build_auth_apdus); para na primeira resposta 9000.
    2. Para cada gravacao de build_write_ops: seleciona o DF raiz quando muda
       o contexto (voltando ao MF entre DFs diferentes), seleciona o EF alvo
       e grava via update_binary (blocos <= 150B, tratados pela sessao).
       Gravacoes cujo file_id nao selecionar (SW != 9000/9Fxx/61xx) sao
       puladas, nao abortam o lote.
    3. Read-back de verificacao: READ BINARY do tamanho gravado e comparacao
       byte a byte.

Retorno: lista de linhas de relatorio
    {"op": tipo, "file": fid|None, "sw": sw|None, "verified": bool,
     "status": "auth-ok"|"auth-fail"|"written"|"write-fail"|"skipped",
     "detail": str}
Linhas de AUTH sao incluidas para auditoria ("op": "AUTH").

`session` precisa expor tx/select_loud/read_binary/update_binary (duck typing:
um CardSession real ou um fake de teste).
"""

from __future__ import annotations

from simwriter.families import (
    MissingData,
    build_auth_apdus,
    build_write_ops,
    load_profiles,
)

__all__ = ["write_card", "df_for_file"]


def _ok(sw):
    return sw == "9000"


def _has_response(sw):
    return bool(sw) and sw.startswith(("9F", "61"))


def df_for_file(fid):
    """DF pai do FID segundo EF_MAP/heuristicas; None = direto sob o MF."""
    from simwriter.files import EF_MAP          # import tardio evita ciclo
    fid = (fid or "").upper()
    if fid in EF_MAP:
        return EF_MAP[fid]["df"]
    if fid.startswith(("2F", "3F")):
        return None                              # MF / EFs raiz (ICCID, DIR)
    if fid.startswith("7F"):
        return None                              # o proprio DF ou filho do MF
    if fid.startswith("6F"):
        return "7F20"                            # EFs GSM classicos
    return None                                  # FIDs vendor (01xx, 60xx...)


def _select_target(session, fid, state):
    """Garante contexto correto e seleciona o EF. Retorna SW do select final."""
    df = df_for_file(fid)
    if state["root"] != df:
        session.select_loud("3F00")              # volta ao MF entre contextos
        state["root"] = df
    if df is not None:
        sw_df, _ = session.select_loud(df)
        if not (_ok(sw_df) or _has_response(sw_df)):
            return sw_df                          # DF inacessivel
    sw, _ = session.select_loud(fid)
    return sw


def write_card(session, profile, dados, adm_key_ascii="88888888"):
    """Executa auth + escritas da familia. Retorna a lista de relatorio."""
    if isinstance(profile, int):
        profile = load_profiles()[profile]
    report = []
    state = {"root": object()}                    # força primeiro re-select

    # --- fase 1: autenticacao -------------------------------------------
    session.select_loud("3F00")
    authenticated = False
    last_sw = None
    for apdu in build_auth_apdus(profile, adm_key_ascii):
        try:
            sw, _ = session.tx(apdu)
        except Exception as exc:                  # leitor sumiu etc.
            report.append({"op": "AUTH", "file": None, "sw": None,
                           "verified": False, "status": "auth-fail",
                           "detail": f"tx error: {exc}"})
            continue
        last_sw = sw
        if _ok(sw):
            authenticated = True
            break                                  # primeira chave que abre
    report.insert(0, {"op": "AUTH", "file": None, "sw": last_sw,
                      "verified": authenticated,
                      "status": "auth-ok" if authenticated else "auth-fail",
                      "detail": "" if authenticated else
                      "nenhuma chave da familia retornou 9000"})

    # --- fase 2: escritas -------------------------------------------------
    try:
        writes = build_write_ops(profile, dados, on_missing="skip")
    except (MissingData, ValueError) as exc:
        report.append({"op": "PLAN", "file": None, "sw": None,
                       "verified": False, "status": "skipped",
                       "detail": f"dados insuficientes: {exc}"})
        writes = []

    for w in writes:
        fid, data = w["file"], w["data"]
        try:
            sw_sel = _select_target(session, fid, state)
        except Exception as exc:
            report.append({"op": w["op"], "file": fid, "sw": None,
                           "verified": False, "status": "skipped",
                           "detail": f"select error: {exc}"})
            continue
        if not (_ok(sw_sel) or _has_response(sw_sel)):
            report.append({"op": w["op"], "file": fid, "sw": sw_sel,
                           "verified": False, "status": "skipped",
                           "detail": "EF nao selecionavel"})
            continue

        try:
            sw_w = session.update_binary(data)
        except Exception as exc:
            report.append({"op": w["op"], "file": fid, "sw": None,
                           "verified": False, "status": "write-fail",
                           "detail": f"update error: {exc}"})
            continue
        if not _ok(sw_w):
            report.append({"op": w["op"], "file": fid, "sw": sw_w,
                           "verified": False, "status": "write-fail",
                           "detail": "UPDATE BINARY recusado"})
            continue

        # read-back
        verified = False
        detail = ""
        try:
            sw_r, back = session.read_binary(len(data))
            if _ok(sw_r):
                verified = bytes(back[:len(data)]) == data
                if not verified:
                    detail = "read-back divergente"
            else:
                detail = f"read-back SW {sw_r}"
        except Exception as exc:
            detail = f"read-back error: {exc}"
        report.append({"op": w["op"], "file": fid, "sw": sw_w,
                       "verified": verified, "status": "written",
                       "detail": detail})
    return report
