import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DOTNET = os.path.join(HERE, "..")
ROOT = os.path.join(DOTNET, "..")
sys.path.insert(0, os.path.join(DOTNET, "ida82", "idasigwriter_net"))

import cil  # noqa: E402


def mask_of(hexbytes, **opts):
    o = cil.CilWildcardOptions()
    for k, v in opts.items():
        setattr(o, k, v)
    insn = cil.decode(bytes.fromhex(hexbytes))
    return "".join("?" if m else "x" for m in cil.auto_mask(insn, o))


class DecodeTests(unittest.TestCase):
    def test_table(self):
        self.assertEqual(len(cil.OPCODES), 219)
        two_byte = [n for c, (n, _) in cil.OPCODES.items() if c > 0xFF]
        # the 2-byte list of the original dotnet_rule_creator.py, fixed
        for n in ("arglist", "ceq", "cgt", "cgt.un", "clt", "clt.un",
                  "constrained.", "cpblk", "endfilter", "initblk", "initobj",
                  "ldarga", "ldftn", "ldloca", "ldvirtftn", "localloc",
                  "readonly.", "refanytype", "sizeof", "tail.", "volatile."):
            self.assertIn(n, two_byte)
        self.assertEqual(len(two_byte), 28)

    def test_operand_formats(self):
        cases = [
            ("00", "nop", 1),
            ("FE01", "ceq", 2),
            ("0E05", "ldarg.s", 2),
            ("FE090100", "ldarg", 4),
            ("1F2A", "ldc.i4.s", 2),
            ("2039300000", "ldc.i4", 5),
            ("210100000000000000", "ldc.i8", 9),
            ("220000803F", "ldc.r4", 5),
            ("23000000000000F03F", "ldc.r8", 9),
            ("2B05", "br.s", 2),
            ("38FBFFFFFF", "br", 5),
            ("280100000A", "call", 5),
            ("724D000070", "ldstr", 5),
            ("D029000001", "ldtoken", 5),
            ("2901000011", "calli", 5),
            ("FE1611000002", "constrained.", 6),
            ("FE1201", "unaligned.", 3),
            ("FE1901", "no.", 3),
            ("DE0A", "leave.s", 2),
        ]
        for hx, name, size in cases:
            insn = cil.decode(bytes.fromhex(hx))
            self.assertIsNotNone(insn, hx)
            self.assertEqual((insn.name, insn.size), (name, size), hx)
        self.assertEqual(cil.decode(bytes.fromhex("2039300000")).operand, 12345)
        self.assertEqual(cil.decode(bytes.fromhex("23000000000000F03F")).operand, 1.0)
        self.assertEqual(cil.decode(bytes.fromhex("38FBFFFFFF")).operand, -5)

    def test_switch(self):
        insn = cil.decode(bytes.fromhex("45 02000000 05000000 F6FFFFFF"))
        self.assertEqual((insn.name, insn.size, insn.operand), ("switch", 13, [5, -10]))
        self.assertEqual(cil.decode(bytes.fromhex("45 00000000")).size, 5)

    def test_invalid(self):
        self.assertIsNone(cil.decode(bytes.fromhex("FE08")))        # unused
        self.assertIsNone(cil.decode(bytes.fromhex("24")))          # unused
        self.assertIsNone(cil.decode(bytes.fromhex("FE")))          # truncated prefix
        self.assertIsNone(cil.decode(bytes.fromhex("2801000A")))    # truncated token
        self.assertIsNone(cil.decode(bytes.fromhex("45 05000000"))) # truncated switch
        self.assertIsNone(cil.decode(b""))

    def test_offset_argument(self):
        insn = cil.decode(bytes.fromhex("00 00 2B05"), 2)
        self.assertEqual((insn.name, insn.size), ("br.s", 2))


class RealCodeTests(unittest.TestCase):
    """Method bodies from Newtonsoft.Json, expected values from dncil."""

    def test_real_methods(self):
        with open(os.path.join(HERE, "il_samples.json")) as f:
            samples = json.load(f)["methods"]
        self.assertTrue(samples)
        for m in samples:
            code = bytes.fromhex(m["il"])
            off = 0
            for name, size in m["insns"]:
                insn = cil.decode(code, off)
                self.assertIsNotNone(insn, (m["method"], off))
                self.assertEqual((insn.name, insn.size), (name, size), (m["method"], off))
                off += size
            self.assertEqual(off, len(code))


class MaskTests(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(mask_of("280100000A"), "x???x")      # call: keep table byte
        self.assertEqual(mask_of("724D000070"), "x???x")      # ldstr
        self.assertEqual(mask_of("FE1611000002"), "xx???x")   # 2-byte opcode + token
        self.assertEqual(mask_of("2B05"), "x?")               # br.s
        self.assertEqual(mask_of("38FBFFFFFF"), "x????")      # br
        self.assertEqual(mask_of("0E05"), "xx")               # vars off by default
        self.assertEqual(mask_of("2039300000"), "xxxxx")      # immediates off by default
        self.assertEqual(mask_of("45 02000000 05000000 F6FFFFFF"),
                         "x" + "xxxx" + "????" * 2)           # switch: count kept
        self.assertEqual(mask_of("FE01"), "xx")

    def test_options(self):
        self.assertEqual(mask_of("280100000A", keep_token_table=False), "x????")
        self.assertEqual(mask_of("280100000A", tokens=False), "xxxxx")
        self.assertEqual(mask_of("724D000070", strings=False), "xxxxx")
        self.assertEqual(mask_of("0E05", vars=True), "x?")
        self.assertEqual(mask_of("FE090100", vars=True), "xx??")
        self.assertEqual(mask_of("2039300000", immediates=True), "x????")
        self.assertEqual(mask_of("2B05", branches=False), "xx")
        self.assertEqual(mask_of("280100000A", enabled=False), "xxxxx")

    def test_reference_script_equivalent(self):
        # Every option on + no table byte == original script (opcode kept,
        # every operand byte wildcarded), except that the switch count is kept.
        everything = dict(tokens=True, strings=True, keep_token_table=False,
                          branches=True, switch_targets=True, vars=True,
                          immediates=True)
        for hx, op_len in (("280100000A", 1), ("FE090100", 2), ("1F2A", 1),
                           ("23000000000000F03F", 1), ("FE1611000002", 2)):
            m = mask_of(hx, **everything)
            self.assertEqual(m, "x" * op_len + "?" * (len(m) - op_len), hx)


class SharedCopiesTests(unittest.TestCase):
    """Files that must stay byte-identical across the four plugins."""

    GROUPS = {
        "pattern.py": [
            "idasigwriter/pattern.py",
            "ida93/SigWriter/sigwriter9/pattern.py",
            "dotnet/ida82/idasigwriter_net/pattern.py",
            "dotnet/ida93/SigWriterNet/sigwriter9_net/pattern.py",
        ],
        "gui.py (IDA 8.2)": [
            "idasigwriter/gui.py",
            "dotnet/ida82/idasigwriter_net/gui.py",
        ],
        "gui.py (IDA 9.3+)": [
            "ida93/SigWriter/sigwriter9/gui.py",
            "dotnet/ida93/SigWriterNet/sigwriter9_net/gui.py",
        ],
        "cil.py": [
            "dotnet/ida82/idasigwriter_net/cil.py",
            "dotnet/ida93/SigWriterNet/sigwriter9_net/cil.py",
        ],
        ".NET ida_backend.py": [
            "dotnet/ida82/idasigwriter_net/ida_backend.py",
            "dotnet/ida93/SigWriterNet/sigwriter9_net/ida_backend.py",
        ],
    }

    def test_copies_identical(self):
        for group, paths in self.GROUPS.items():
            blobs = []
            for p in paths:
                with open(os.path.join(ROOT, p), "rb") as f:
                    blobs.append(f.read())
            for p, b in zip(paths[1:], blobs[1:]):
                self.assertEqual(blobs[0], b, "%s: %s differs from %s" % (group, p, paths[0]))


if __name__ == "__main__":
    unittest.main()
