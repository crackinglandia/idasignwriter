import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from idasigwriter.pattern import (Pattern, fmt_ida, fmt_double_qmark, fmt_raw,
                                  fmt_code_style, fmt_c_array, fmt_yara, fmt_yara_string,
                                  fmt_blob, parse_pattern, sanitize_identifier)

# E8 xx xx xx xx  call rel32 ; 48 8B 05 xx xx xx xx  mov rax, [rip+x]
VALUES = [0xE8, 0x10, 0x20, 0x30, 0x40, 0x48, 0x8B, 0x05, 0x01, 0x02, 0x03, 0x04]
WILD = [False, True, True, True, True, False, False, False, True, True, True, True]


class PatternTests(unittest.TestCase):
    def setUp(self):
        self.p = Pattern(VALUES, WILD, 0x401000)

    def test_standalone(self):
        self.assertEqual(fmt_ida(self.p), "E8 ? ? ? ? 48 8B 05 ? ? ? ?")
        self.assertEqual(fmt_double_qmark(self.p), "E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ??")
        self.assertEqual(fmt_raw(self.p), "E8 10 20 30 40 48 8B 05 01 02 03 04")
        self.assertEqual(fmt_ida(self.p, use_wildcards=False), fmt_raw(self.p))

    def test_code_style(self):
        data, mask = fmt_code_style(self.p)
        self.assertEqual(mask, "x????xxx????")
        self.assertTrue(data.startswith("\\xE8\\x00"))

    def test_c_array(self):
        out = fmt_c_array(self.p, "my sig")
        self.assertIn("const unsigned char my_sig[12]", out)
        self.assertIn('my_sig_mask[13] = "x????xxx????"', out)
        exact = fmt_c_array(self.p, "s", use_wildcards=False)
        self.assertNotIn("_mask", exact)
        self.assertIn("0x10, 0x20", exact)

    def test_yara_trims(self):
        out = fmt_yara(self.p, "r")
        self.assertIn("$pattern = { E8 ?? ?? ?? ?? 48 8B 05 }", out)
        p2 = Pattern([1, 2, 3], [True, False, True], 0x10)
        out2 = fmt_yara(p2, "r")
        self.assertIn("{ 02 }", out2)
        self.assertIn('address = "0x11"', out2)
        with self.assertRaises(ValueError):
            fmt_yara(Pattern([1], [True]), "r")
        self.assertIn("{ E8 10 20 30 40 48 8B 05 01 02 03 04 }",
                      fmt_yara(self.p, "r", use_wildcards=False))

    def test_yara_string_only(self):
        self.assertEqual(fmt_yara_string(self.p), "{ E8 ?? ?? ?? ?? 48 8B 05 }")
        self.assertEqual(fmt_yara_string(self.p, use_wildcards=False),
                         "{ E8 10 20 30 40 48 8B 05 01 02 03 04 }")
        with self.assertRaises(ValueError):
            fmt_yara_string(Pattern([1], [True]))

    def test_yara_layout_28_columns(self):
        p = Pattern(list(range(60)))
        out = fmt_yara_string(p)
        rows = out.splitlines()[1:-1]
        self.assertEqual([len(r.split()) for r in rows], [28, 28, 4])
        self.assertIn("$pattern = {", fmt_yara(p, "r"))

    def test_yara_split_pieces(self):
        # 28 * 20 = 560 bytes per piece
        self.assertNotIn("_p1", fmt_yara(Pattern([1] * 560), "r"))
        out = fmt_yara(Pattern([1] * 1200), "r")
        self.assertIn("$pattern_p1 = {", out)
        self.assertIn("// offset +1120 (0x460), 80 bytes", out)
        p3_rows = out.split("$pattern_p3 = {")[1].split("}")[0].strip().splitlines()
        self.assertEqual([len(r.split()) for r in p3_rows], [28, 28, 24])
        self.assertIn("$pattern_p2 at @pattern_p1[i] + 560", out)
        self.assertIn("$pattern_p3 at @pattern_p1[i] + 1120", out)
        only = fmt_yara_string(Pattern([1] * 1200))
        self.assertTrue(only.startswith("// offset +0"))
        self.assertIn("$pattern_p2 = {", only)

    def test_yara_split_trims_each_piece(self):
        wild = [i in (559, 560) for i in range(1000)]
        out = fmt_yara(Pattern([1] * 1000, wild), "r")
        self.assertIn("// offset +561 (0x231), 439 bytes", out)
        self.assertIn("$pattern_p2 at @pattern_p1[i] + 561", out)

    def test_blob(self):
        data, mask = fmt_blob(self.p)
        self.assertEqual(data[:2], b"\xE8\x00")
        self.assertEqual(mask[:2], b"\xFF\x00")
        data, mask = fmt_blob(self.p, use_wildcards=False)
        self.assertIsNone(mask)
        self.assertEqual(data, bytes(VALUES))

    def test_parse_roundtrip(self):
        self.assertEqual(parse_pattern(fmt_ida(self.p)).wild, WILD)
        self.assertEqual(parse_pattern("E8????????").wild, [False] + [True] * 4)

    def test_identifier(self):
        self.assertEqual(sanitize_identifier("1abc-d"), "_1abc_d")
        self.assertEqual(sanitize_identifier(""), "pattern")


ROOT = os.path.join(os.path.dirname(__file__), "..")


class Ida93CopyTests(unittest.TestCase):
    """The IDA 9.3+ version ships its own copy of pattern.py."""

    def test_pattern_copies_are_identical(self):
        with open(os.path.join(ROOT, "idasigwriter", "pattern.py"), "rb") as f82, \
             open(os.path.join(ROOT, "ida93", "SigWriter", "sigwriter9", "pattern.py"), "rb") as f93:
            self.assertEqual(f82.read(), f93.read(),
                             "idasigwriter/pattern.py and ida93/SigWriter/sigwriter9/pattern.py differ")

    def test_ida93_copy_runs(self):
        sys.path.insert(0, os.path.join(ROOT, "ida93", "SigWriter"))
        from sigwriter9 import pattern as p93
        p = p93.Pattern(VALUES, WILD, 0x401000)
        self.assertEqual(p93.fmt_yara_string(p), "{ E8 ?? ?? ?? ?? 48 8B 05 }")


if __name__ == "__main__":
    unittest.main()
