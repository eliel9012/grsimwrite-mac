#!/usr/bin/env python3
"""Tests for simwriter.families + simwriter.dispatch — SEM hardware."""

import os
import re
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from simwriter.families import (          # noqa: E402
    FamilyProfile,
    MissingData,
    Operation,
    build_auth_apdus,
    build_write_ops,
    detect_family,
    get_profile,
    load_profiles,
)
from simwriter.dispatch import df_for_file, write_card  # noqa: E402

LY14_ATR = "3B9F95801FC78031A073B6A10067CF3215CA9CD70920"

SAMPLE_DADOS = {
    "pin1": "1234", "puk1": "88888888",
    "pin2": "4321", "puk2": "99999999",
    "adm": "29083011",
    "ki": "0123456789ABCDEF0123456789ABCDEF",
    "opc": "8E27B6470E6563E7C6F03D50B1A1C0A4",
}


class TestProfileLoading(unittest.TestCase):

    def test_loads_42_profiles_without_exception(self):
        ps = load_profiles()
        self.assertEqual(len(ps), 42)
        self.assertTrue(all(isinstance(p, FamilyProfile) for p in ps))

    def test_indices_are_sequential(self):
        ps = load_profiles()
        self.assertEqual([p.index for p in ps], list(range(42)))

    def test_get_profile(self):
        p38 = get_profile(38)
        self.assertEqual(p38.index, 38)
        self.assertTrue(p38.title)

    def test_every_profile_builds_ops_with_sample_dados(self):
        for p in load_profiles():
            ops = build_write_ops(p, SAMPLE_DADOS, on_missing="skip")
            for w in ops:
                self.assertIn("file", w)
                self.assertIn("data", w)
                self.assertIsInstance(w["data"], (bytes, bytearray))
            # nenhuma op de escrita pode conter placeholder residual
            for w in ops:
                self.assertNotIn(b"[", w["data"])


class TestAuthParsing(unittest.TestCase):

    def test_profile38_ly14_auth_apdu_style(self):
        """APDU de auth do LY14: estilo VERIFY A020000B08 ou INS58 c/ chave."""
        apdus = build_auth_apdus(get_profile(38), "88888888")
        self.assertTrue(apdus, "perfil 38 sem APDUs de auth")
        want_verify = "A020000B08" + "38" * 8
        want_ins58 = "A058000008" + "38" * 8
        got_any = any(
            (want_verify in a) or a.startswith("A058000008" + "38" * 8)
            or ("A058000008" in a and a.endswith("38" * 8))
            for a in apdus
        )
        self.assertTrue(got_any, f"nenhum estilo esperado em {apdus}")

    def test_sadm_ops_become_auth_not_writes(self):
        """Ops com [SADM] viram AUTH; nunca aparecem como escrita.
        [ADM] como payload (ex.: '010000[ADM]8A8A') e escrita legitima."""
        for p in load_profiles():
            for op in p.operations:
                self.assertNotIn("[SADM]", op.template,
                                 f"perfil {p.index}: {op.template}")
                # nenhuma escrita pode ser um VERIFY disfarçado
                head_ok = op.template.endswith("[ADM]") and \
                    re.fullmatch(r"[0-9A-F]{2}20[0-9A-F]{6}", op.template[:-5])
                self.assertFalse(head_ok,
                                 f"perfil {p.index}: VERIFY em ops: {op.template}")

    def test_profile24_auth_is_ins58_with_default_key(self):
        p = get_profile(24)
        apdus = build_auth_apdus(p, "88888888")
        self.assertIn("A0580000083838383838383838", apdus)

    def test_explicit_auth_profiles_keep_factory_keys(self):
        """Perfis 0-2 trazem chaves de fabrica completas embutidas."""
        apdus = build_auth_apdus(get_profile(0), "29083011")
        self.assertIn("A020000B083838383838383838", apdus)   # "88888888"
        self.assertIn("A020000B083239303833303131", apdus)   # "29083011"

    def test_incomplete_auth_header_gets_key_appended(self):
        """Perfil 38 tem so o header A020000C08 -> chave e anexada."""
        apdus = build_auth_apdus(get_profile(38), "88888888")
        self.assertIn("A020000C083838383838383838", apdus)

    def test_expected_sw_parsed(self):
        p0 = get_profile(0)
        self.assertIn("9000", p0.expected_sw)
        self.assertIn("9804", p0.expected_sw)


class TestPlaceholderSubstitution(unittest.TestCase):

    def _find_op(self, profile_idx, template):
        for op in get_profile(profile_idx).operations:
            if op.template == template:
                return op
        return None

    def test_adm_write_template_substitution(self):
        """'010000[ADM]8A8A' + adm='29083011' ->
        b'\\x01\\x00\\x00' + b'29083011' (ASCII) + b'\\x8a\\x8a'."""
        op = self._find_op(24, "010000[ADM]8A8A")
        self.assertIsNotNone(op, "template ADM nao encontrado no perfil 24")
        expected_hex = (b"\x01\x00\x00" + b"29083011" + b"\x8a\x8a").hex()
        data = op.data_builder({"adm": "29083011"})
        self.assertEqual(data.hex(), expected_hex)

    def test_ki_encoded_as_bytes_fromhex(self):
        ki = "0123456789ABCDEF0123456789ABCDEF"
        op = self._find_op(28, "[KI]")
        self.assertIsNotNone(op, "template [KI] ausente no perfil 28")
        data = op.data_builder({"ki": ki})
        self.assertEqual(data, bytes.fromhex(ki))

    def test_opc_gets_01_prefix(self):
        opc = "8E27B6470E6563E7C6F03D50B1A1C0A4"
        # template "01[OPC]" (prefixo literal presente)
        op = self._find_op(28, "01[OPC]")
        self.assertIsNotNone(op)
        self.assertEqual(op.data_builder({"opc": opc}),
                         b"\x01" + bytes.fromhex(opc))
        # template "[LTE_OPC]" sem prefixo -> prefixo injetado
        for p in load_profiles():
            for o in p.operations:
                if o.template == "[LTE_OPC]":
                    self.assertEqual(o.data_builder({"opc": opc}),
                                     b"\x01" + bytes.fromhex(opc),
                                     f"perfil {p.index}: OPC sem prefixo 01")

    def test_pin_ascii_digits(self):
        op = self._find_op(24, "000000[PIN1]8383[PUK1]8A8A")
        self.assertIsNotNone(op)
        data = op.data_builder({"pin1": "1234", "puk1": "88888888"})
        self.assertEqual(
            data.hex(),
            (b"\x00\x00\x00" + b"1234" + b"\x83\x83" + b"88888888"
             + b"\x8a\x8a").hex())

    def test_milenage_parameter_constant(self):
        """extra_cmd '081C2A0001' no arquivo 2FE5 vira escrita MILENAGE."""
        found = False
        for p in load_profiles():
            for op in p.operations:
                if op.op_type == "MILENAGE":
                    found = True
                    self.assertEqual(op.template, "081C2A0001")
                    self.assertEqual(op.file_id, "2FE5")
                    self.assertEqual(op.data_builder({}), bytes.fromhex("081C2A0001"))
        self.assertTrue(found, "nenhuma operacao MILENAGE reconhecida")

    def test_missing_data_raises_and_skips(self):
        p = get_profile(24)
        with self.assertRaises(MissingData):
            build_write_ops(p, {})
        ops = build_write_ops(p, {}, on_missing="skip")
        self.assertEqual(ops, [])

    def test_unsupported_placeholders_are_dropped(self):
        """Templates com [AKEY]/[NAI_PASS]/... saem das ops de escrita."""
        base = {"CHV1", "CHV2", "PUK1", "PUK2", "ADM", "KI", "KI_LTE",
                "OPC", "MILENAGE"}
        for p in load_profiles():
            for op in p.operations:
                parts = op.op_type.split("+")
                self.assertTrue(set(parts) <= base and parts,
                                f"perfil {p.index}: tipo inesperado {op.op_type}")


class TestDetectFamily(unittest.TestCase):

    def test_ly14_atr_maps_to_profile_38(self):
        fam = detect_family(LY14_ATR)
        self.assertIsNotNone(fam)
        self.assertEqual(fam.index, 38)

    def test_atr_normalization(self):
        self.assertEqual(detect_family("3b 9f 95 80 1f c7 80 31 a0 73 b6 a1 "
                                       "00 67 cf 32 15 ca 9c d7 09 20").index, 38)

    def test_unknown_atr_returns_none(self):
        self.assertIsNone(detect_family("3B000000000080"))
        self.assertIsNone(detect_family(""))
        self.assertIsNone(detect_family(None))


# ---------------------------------------------------------------------------
# dispatch — FakeSession (sem hardware)
# ---------------------------------------------------------------------------

class FakeSession:
    """Session duck-typed: selects ok so para FIDs liberados; grava em RAM."""

    FAIL_SW = "9404"

    def __init__(self, selectable=()):
        self.selectable = set(selectable) | {"3F00"}
        self.log = []
        self.mem = {}
        self._cur = None

    def tx(self, apdu_hex):
        self.log.append(("TX", apdu_hex))
        # auth fake: chave "88888888" abre; outras dao 9840
        if apdu_hex.endswith("38" * 8):
            return "9000", b""
        return "9840", b""

    def select_loud(self, fid, df=None):
        self.log.append(("SEL", fid, df))
        self._cur = fid
        if fid in self.selectable:
            return "9000", b"\x00"
        return self.FAIL_SW, b""

    def update_binary(self, data, offset=0):
        self.log.append(("UPD", self._cur, bytes(data)))
        if self._cur not in self.selectable:
            return "9804"
        self.mem[self._cur] = bytes(data)
        return "9000"

    def read_binary(self, length, offset=0):
        data = self.mem.get(self._cur, b"")[:length]
        return "9000", data


class TestWriteCard(unittest.TestCase):

    def setUp(self):
        self.p24 = get_profile(24)

    def test_happy_path_all_written_and_verified(self):
        sess = FakeSession(selectable={"0100", "0200", "0B00"})
        report = write_card(sess, self.p24, {
            "pin1": "1234", "puk1": "88888888",
            "pin2": "4321", "puk2": "99999999",
            "adm": "29083011"})
        auth = report[0]
        self.assertEqual(auth["op"], "AUTH")
        self.assertTrue(auth["verified"])
        written = [r for r in report if r["status"] == "written"]
        self.assertTrue(written)
        for r in written:
            self.assertTrue(r["verified"], f"{r['op']} sem read-back igual")
            self.assertEqual(r["sw"], "9000")
            self.assertEqual(sess.mem[r["file"]],
                             [w for w in build_write_ops(self.p24, {
                                 "pin1": "1234", "puk1": "88888888",
                                 "pin2": "4321", "puk2": "99999999",
                                 "adm": "29083011"}, on_missing="skip")
                              if w["file"] == r["file"]][0]["data"])

    def test_unselectable_file_is_skipped_not_fatal(self):
        sess = FakeSession(selectable=set())     # nada seleciona exceto MF
        report = write_card(sess, self.p24, {
            "pin1": "1234", "puk1": "88888888", "pin2": "4321",
            "puk2": "99999999", "adm": "29083011"})
        skipped = [r for r in report if r["status"] == "skipped"]
        self.assertTrue(skipped)
        for r in skipped:
            self.assertFalse(r["verified"])
            self.assertIsNotNone(r["sw"])         # SW do select falho registrado

    def test_auth_failure_reported_but_writes_still_attempted(self):
        class BadKeySession(FakeSession):
            def tx(self, apdu_hex):
                self.log.append(("TX", apdu_hex))
                return "9840", b""                # nenhuma chave abre
        sess = BadKeySession(selectable={"0100", "0200", "0B00"})
        report = write_card(sess, self.p24, {
            "pin1": "1234", "puk1": "88888888", "pin2": "4321",
            "puk2": "99999999", "adm": "29083011"})
        self.assertFalse(report[0]["verified"])
        self.assertIn("9000", [r["sw"] for r in report])

    def test_mf_reselected_between_different_roots(self):
        """select_loud do MF entre contextos de DF diferentes."""
        calls = []

        class LoggingSession(FakeSession):
            def select_loud(self, fid, df=None):
                calls.append(fid)
                return super().select_loud(fid, df)

        from simwriter.files import EF_MAP
        # monta ops em DFs diferentes: IMSI (7F20) + ICCID (MF)
        p = get_profile(38)
        dados = dict(SAMPLE_DADOS)
        sess = LoggingSession(selectable={"6002", "0100", "0200", "0B00",
                                          "6F07", "2FE2", "7F20"})
        write_card(sess, p, dados)
        self.assertIn("3F00", calls)              # MF sempre visitado

    def test_write_failure_marks_not_verified(self):
        class FailUpdate(FakeSession):
            def update_binary(self, data, offset=0):
                self.log.append(("UPD", self._cur, bytes(data)))
                return "9804"
        sess = FailUpdate(selectable={"0100", "0200", "0B00"})
        report = write_card(sess, self.p24, {
            "pin1": "1234", "puk1": "88888888", "pin2": "4321",
            "puk2": "99999999", "adm": "29083011"})
        failed = [r for r in report if r["status"] == "write-fail"]
        self.assertTrue(failed)
        self.assertFalse(any(r["verified"] for r in failed))


class TestDfForFile(unittest.TestCase):

    def test_known_ef_uses_map(self):
        self.assertEqual(df_for_file("6F07"), "7F20")

    def test_root_files_have_no_df(self):
        self.assertIsNone(df_for_file("2FE2"))
        self.assertIsNone(df_for_file("3F00"))

    def test_vendor_fids_default_to_mf(self):
        self.assertIsNone(df_for_file("6002"))
        self.assertIsNone(df_for_file("0B00"))
        self.assertIsNone(df_for_file("2FE5"))


if __name__ == "__main__":
    unittest.main()
