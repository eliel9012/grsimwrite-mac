#!/usr/bin/env python3
"""Tests for simwriter.format — GRSIMWrite CREATE FILE (A0E0) template engine."""

import json
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from simwriter.format import FormatEngine, parse_command, validate_raw  # noqa: E402

CATALOG = os.path.join(BASE, "research", "format_templates.json")
EXE = os.path.join(BASE, "research", "vendor", "GRSIMWrite.exe")
LY14 = "family_1197c0"  # cluster adjacent to profiles.json index 38 (0x1197c0)


def load_engine():
    return FormatEngine.from_catalog(CATALOG)


class TestCatalog(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(CATALOG):
            raise unittest.SkipTest("catalog missing; run simwriter/format.py")
        cls.engine = load_engine()
        with open(CATALOG) as fh:
            cls.raw_catalog = json.load(fh)

    def test_catalog_loads_with_more_than_1000_commands(self):
        self.assertGreater(self.engine.total_commands, 1000)

    def test_all_raw_commands_are_valid(self):
        for fam in self.raw_catalog["families"]:
            for cmd in fam["commands"]:
                raw = cmd["raw_hex"]
                self.assertTrue(validate_raw(raw),
                                "invalid raw in %s: %r" % (fam["family"], raw[:32]))
                self.assertEqual(len(raw) % 2, 0)
                self.assertTrue(raw.startswith("A0E00000"))
                lc = int(raw[8:10], 16)
                self.assertGreaterEqual(len(raw), 10 + 2 * lc,
                                        "Lc %d exceeds payload in %s" % (lc, raw[:32]))

    def test_lc_consistency_exact_when_truncated_view(self):
        """payload slice must be fully contained and non-empty."""
        for fam in self.raw_catalog["families"]:
            for cmd in fam["commands"]:
                raw = cmd["raw_hex"]
                lc = int(raw[8:10], 16)
                payload = raw[10:10 + 2 * lc]
                self.assertEqual(len(payload), 2 * lc)

    def test_families_have_metadata(self):
        fams = self.raw_catalog["families"]
        self.assertGreater(len(fams), 5)
        for fam in fams:
            self.assertIn("family", fam)
            self.assertIn("exe_offset_range", fam)
            self.assertGreater(fam["count"], 0)
            self.assertEqual(fam["count"], len(fam["commands"]))


class TestSequences(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(CATALOG):
            raise unittest.SkipTest("catalog missing; run simwriter/format.py")
        cls.engine = load_engine()
        cls.families = cls.engine.list_families()

    def test_at_least_three_non_empty_sequences(self):
        built = 0
        for fid, _n in self.families:
            seq = self.engine.build_format_sequence(fid)
            if seq:
                built += 1
            if built >= 3:
                break
        self.assertGreaterEqual(built, 3)

    def test_every_sequence_first_step_references_mf_3f00(self):
        for fid, _n in self.families:
            seq = self.engine.build_format_sequence(fid)
            self.assertTrue(seq, "%s produced empty sequence" % fid)
            first = seq[0]
            ok = (("select" in first and first["select"][0] == "3F00") or
                  ("create" in first and first["create"][10:18].endswith("3F00")
                   and parse_command(first["create"])["fid"] == "3F00"))
            self.assertTrue(ok, "%s first step is not MF-3F00: %r" % (fid, first))

    def test_sequence_step_shapes(self):
        seq = self.engine.build_format_sequence(LY14)
        for step in seq:
            keys = set(step.keys())
            self.assertTrue(keys <= {"select", "create", "init_data"},
                            "unexpected step %r" % step)
            if "create" in step:
                self.assertTrue(step["create"].startswith("A0E00000"))
            if "select" in step:
                self.assertIsInstance(step["select"], list)
                self.assertTrue(all(len(f) == 4 for f in step["select"]))
            if "init_data" in step:
                d = step["init_data"]
                self.assertIn("fid", d)
                self.assertIn("data_hex", d)
                self.assertEqual(len(d["data_hex"]) % 2, 0)

    def test_ly14_family_exists_and_creates_adf_4f17(self):
        fids = {c["fid"] for c in self.engine.family(LY14)["commands"]}
        self.assertIn("3F00", fids)
        self.assertIn("7F10", fids)
        self.assertIn("4F17", fids)   # ADF under 5F3A (USIM-style tree)
        seq = self.engine.build_format_sequence(LY14)
        self.assertTrue(any("create" in s and s["create"][14:18] == "4F17"
                            for s in seq))


class TestParsing(unittest.TestCase):

    def test_parse_known_mf_create(self):
        raw = "A0E000001100003F0001000000000009000206060000"
        cmd = parse_command(raw)
        self.assertIsNotNone(cmd)
        self.assertEqual(cmd["fid"], "3F00")
        self.assertEqual(cmd["size"], 0)
        self.assertEqual(cmd["lc"], 0x11)

    def test_parse_known_ef_create(self):
        # EF ICCID 2FE2, 10 bytes, under MF
        raw = "A0E000000F000A2FE204030BF4BB010300000001"
        cmd = parse_command(raw)
        self.assertIsNotNone(cmd)
        self.assertEqual(cmd["fid"], "2FE2")
        self.assertEqual(cmd["size"], 0x000A)
        self.assertEqual(cmd["type_guess"], "ef_transparent")

    def test_validate_rejects_garbage(self):
        self.assertFalse(validate_raw(""))
        self.assertFalse(validate_raw("A0E00000"))
        self.assertFalse(validate_raw("A0E0000011"))          # odd / truncated
        self.assertFalse(validate_raw("ZZE000001100003F00"))  # bad prefix
        self.assertFalse(validate_raw("A0E000000F00170A00"))  # Lc > payload

    def test_list_families_returns_pairs(self):
        fams = load_engine().list_families()
        self.assertTrue(all(isinstance(f, tuple) and len(f) == 2 for f in fams))
        self.assertTrue(all(n > 0 for _f, n in fams))

    @unittest.skipUnless(os.path.exists(EXE), "vendor exe not available")
    def test_fallback_extraction_from_exe(self):
        eng = FormatEngine.extract(EXE)
        self.assertGreater(eng.total_commands, 1000)
        self.assertGreaterEqual(len(eng.list_families()), 10)
        seq = eng.build_format_sequence(LY14)
        self.assertTrue(seq)


if __name__ == "__main__":
    unittest.main(verbosity=2)
