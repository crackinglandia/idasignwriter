"""
CIL (ECMA-335 / .NET IL bytecode) decoder used to build signatures.

Pure Python, no IDA imports, so it can be unit-tested outside IDA and is
shared verbatim by the IDA 8.2 and IDA 9.3+ .NET plugins.

Sources:
  * ECMA-335 6th ed., Partition III "CIL Instruction Set" (encodings and
    operand formats; all operands are little-endian).
  * dotnet/runtime src/coreclr/inc/opcode.def (master opcode table); the
    OPCODES table below was generated from it, plus `no.` (FE 19), which is
    in ECMA-335 III.2.2 but marked unused by CoreCLR.

Encoding: one-byte opcodes 0x00-0xE0, two-byte opcodes 0xFE xx.
"""

import struct

# Operand formats (System.Reflection.Emit.OperandType names).
InlineNone = "InlineNone"                     # no operand
ShortInlineI = "ShortInlineI"                 # int8 (also unaligned./no. flags)
ShortInlineVar = "ShortInlineVar"             # uint8 arg/local index
ShortInlineBrTarget = "ShortInlineBrTarget"   # int8 branch offset
ShortInlineR = "ShortInlineR"                 # float32
InlineVar = "InlineVar"                       # uint16 arg/local index
InlineI = "InlineI"                           # int32
InlineBrTarget = "InlineBrTarget"             # int32 branch offset
InlineI8 = "InlineI8"                         # int64
InlineR = "InlineR"                           # float64
InlineMethod = "InlineMethod"                 # metadata token
InlineField = "InlineField"                   # metadata token
InlineType = "InlineType"                     # metadata token
InlineTok = "InlineTok"                       # metadata token (type/method/field)
InlineSig = "InlineSig"                       # StandAloneSig token (calli)
InlineString = "InlineString"                 # user-string token (0x70xxxxxx)
InlineSwitch = "InlineSwitch"                 # uint32 N + N * int32 offsets

OPERAND_SIZE = {
    InlineNone: 0,
    ShortInlineI: 1, ShortInlineVar: 1, ShortInlineBrTarget: 1,
    InlineVar: 2,
    InlineI: 4, InlineBrTarget: 4, ShortInlineR: 4,
    InlineMethod: 4, InlineField: 4, InlineType: 4, InlineTok: 4,
    InlineSig: 4, InlineString: 4,
    InlineI8: 8, InlineR: 8,
    # InlineSwitch is variable: 4 + 4 * N
}

# Field kinds produced by the decoder; each maps to a wildcard option.
F_TOKEN = "token"                 # Method/Field/Type/Tok/Sig tokens
F_STRING = "string"               # ldstr user-string token
F_BRANCH = "branch"               # br*, leave* offsets
F_SWITCH_COUNT = "switch_count"   # N in switch (never wildcarded)
F_SWITCH_TARGET = "switch_target"
F_VAR = "var"                     # ldarg/ldloc/... indices
F_IMM = "imm"                     # ldc.* constants, unaligned./no. flags

_KIND_OF = {
    InlineMethod: F_TOKEN, InlineField: F_TOKEN, InlineType: F_TOKEN,
    InlineTok: F_TOKEN, InlineSig: F_TOKEN,
    InlineString: F_STRING,
    ShortInlineBrTarget: F_BRANCH, InlineBrTarget: F_BRANCH,
    ShortInlineVar: F_VAR, InlineVar: F_VAR,
    ShortInlineI: F_IMM, InlineI: F_IMM, InlineI8: F_IMM,
    ShortInlineR: F_IMM, InlineR: F_IMM,
}

# ECMA-335 II.22 metadata table ids (high byte of a token), for display.
TOKEN_TABLES = {
    0x01: "TypeRef", 0x02: "TypeDef", 0x04: "Field", 0x06: "MethodDef",
    0x0A: "MemberRef", 0x11: "StandAloneSig", 0x1B: "TypeSpec",
    0x2B: "MethodSpec", 0x70: "UserString",
}

OPCODES = {
    0x00: ("nop",            InlineNone),
    0x01: ("break",          InlineNone),
    0x02: ("ldarg.0",        InlineNone),
    0x03: ("ldarg.1",        InlineNone),
    0x04: ("ldarg.2",        InlineNone),
    0x05: ("ldarg.3",        InlineNone),
    0x06: ("ldloc.0",        InlineNone),
    0x07: ("ldloc.1",        InlineNone),
    0x08: ("ldloc.2",        InlineNone),
    0x09: ("ldloc.3",        InlineNone),
    0x0A: ("stloc.0",        InlineNone),
    0x0B: ("stloc.1",        InlineNone),
    0x0C: ("stloc.2",        InlineNone),
    0x0D: ("stloc.3",        InlineNone),
    0x0E: ("ldarg.s",        ShortInlineVar),
    0x0F: ("ldarga.s",       ShortInlineVar),
    0x10: ("starg.s",        ShortInlineVar),
    0x11: ("ldloc.s",        ShortInlineVar),
    0x12: ("ldloca.s",       ShortInlineVar),
    0x13: ("stloc.s",        ShortInlineVar),
    0x14: ("ldnull",         InlineNone),
    0x15: ("ldc.i4.m1",      InlineNone),
    0x16: ("ldc.i4.0",       InlineNone),
    0x17: ("ldc.i4.1",       InlineNone),
    0x18: ("ldc.i4.2",       InlineNone),
    0x19: ("ldc.i4.3",       InlineNone),
    0x1A: ("ldc.i4.4",       InlineNone),
    0x1B: ("ldc.i4.5",       InlineNone),
    0x1C: ("ldc.i4.6",       InlineNone),
    0x1D: ("ldc.i4.7",       InlineNone),
    0x1E: ("ldc.i4.8",       InlineNone),
    0x1F: ("ldc.i4.s",       ShortInlineI),
    0x20: ("ldc.i4",         InlineI),
    0x21: ("ldc.i8",         InlineI8),
    0x22: ("ldc.r4",         ShortInlineR),
    0x23: ("ldc.r8",         InlineR),
    0x25: ("dup",            InlineNone),
    0x26: ("pop",            InlineNone),
    0x27: ("jmp",            InlineMethod),
    0x28: ("call",           InlineMethod),
    0x29: ("calli",          InlineSig),
    0x2A: ("ret",            InlineNone),
    0x2B: ("br.s",           ShortInlineBrTarget),
    0x2C: ("brfalse.s",      ShortInlineBrTarget),
    0x2D: ("brtrue.s",       ShortInlineBrTarget),
    0x2E: ("beq.s",          ShortInlineBrTarget),
    0x2F: ("bge.s",          ShortInlineBrTarget),
    0x30: ("bgt.s",          ShortInlineBrTarget),
    0x31: ("ble.s",          ShortInlineBrTarget),
    0x32: ("blt.s",          ShortInlineBrTarget),
    0x33: ("bne.un.s",       ShortInlineBrTarget),
    0x34: ("bge.un.s",       ShortInlineBrTarget),
    0x35: ("bgt.un.s",       ShortInlineBrTarget),
    0x36: ("ble.un.s",       ShortInlineBrTarget),
    0x37: ("blt.un.s",       ShortInlineBrTarget),
    0x38: ("br",             InlineBrTarget),
    0x39: ("brfalse",        InlineBrTarget),
    0x3A: ("brtrue",         InlineBrTarget),
    0x3B: ("beq",            InlineBrTarget),
    0x3C: ("bge",            InlineBrTarget),
    0x3D: ("bgt",            InlineBrTarget),
    0x3E: ("ble",            InlineBrTarget),
    0x3F: ("blt",            InlineBrTarget),
    0x40: ("bne.un",         InlineBrTarget),
    0x41: ("bge.un",         InlineBrTarget),
    0x42: ("bgt.un",         InlineBrTarget),
    0x43: ("ble.un",         InlineBrTarget),
    0x44: ("blt.un",         InlineBrTarget),
    0x45: ("switch",         InlineSwitch),
    0x46: ("ldind.i1",       InlineNone),
    0x47: ("ldind.u1",       InlineNone),
    0x48: ("ldind.i2",       InlineNone),
    0x49: ("ldind.u2",       InlineNone),
    0x4A: ("ldind.i4",       InlineNone),
    0x4B: ("ldind.u4",       InlineNone),
    0x4C: ("ldind.i8",       InlineNone),
    0x4D: ("ldind.i",        InlineNone),
    0x4E: ("ldind.r4",       InlineNone),
    0x4F: ("ldind.r8",       InlineNone),
    0x50: ("ldind.ref",      InlineNone),
    0x51: ("stind.ref",      InlineNone),
    0x52: ("stind.i1",       InlineNone),
    0x53: ("stind.i2",       InlineNone),
    0x54: ("stind.i4",       InlineNone),
    0x55: ("stind.i8",       InlineNone),
    0x56: ("stind.r4",       InlineNone),
    0x57: ("stind.r8",       InlineNone),
    0x58: ("add",            InlineNone),
    0x59: ("sub",            InlineNone),
    0x5A: ("mul",            InlineNone),
    0x5B: ("div",            InlineNone),
    0x5C: ("div.un",         InlineNone),
    0x5D: ("rem",            InlineNone),
    0x5E: ("rem.un",         InlineNone),
    0x5F: ("and",            InlineNone),
    0x60: ("or",             InlineNone),
    0x61: ("xor",            InlineNone),
    0x62: ("shl",            InlineNone),
    0x63: ("shr",            InlineNone),
    0x64: ("shr.un",         InlineNone),
    0x65: ("neg",            InlineNone),
    0x66: ("not",            InlineNone),
    0x67: ("conv.i1",        InlineNone),
    0x68: ("conv.i2",        InlineNone),
    0x69: ("conv.i4",        InlineNone),
    0x6A: ("conv.i8",        InlineNone),
    0x6B: ("conv.r4",        InlineNone),
    0x6C: ("conv.r8",        InlineNone),
    0x6D: ("conv.u4",        InlineNone),
    0x6E: ("conv.u8",        InlineNone),
    0x6F: ("callvirt",       InlineMethod),
    0x70: ("cpobj",          InlineType),
    0x71: ("ldobj",          InlineType),
    0x72: ("ldstr",          InlineString),
    0x73: ("newobj",         InlineMethod),
    0x74: ("castclass",      InlineType),
    0x75: ("isinst",         InlineType),
    0x76: ("conv.r.un",      InlineNone),
    0x79: ("unbox",          InlineType),
    0x7A: ("throw",          InlineNone),
    0x7B: ("ldfld",          InlineField),
    0x7C: ("ldflda",         InlineField),
    0x7D: ("stfld",          InlineField),
    0x7E: ("ldsfld",         InlineField),
    0x7F: ("ldsflda",        InlineField),
    0x80: ("stsfld",         InlineField),
    0x81: ("stobj",          InlineType),
    0x82: ("conv.ovf.i1.un", InlineNone),
    0x83: ("conv.ovf.i2.un", InlineNone),
    0x84: ("conv.ovf.i4.un", InlineNone),
    0x85: ("conv.ovf.i8.un", InlineNone),
    0x86: ("conv.ovf.u1.un", InlineNone),
    0x87: ("conv.ovf.u2.un", InlineNone),
    0x88: ("conv.ovf.u4.un", InlineNone),
    0x89: ("conv.ovf.u8.un", InlineNone),
    0x8A: ("conv.ovf.i.un",  InlineNone),
    0x8B: ("conv.ovf.u.un",  InlineNone),
    0x8C: ("box",            InlineType),
    0x8D: ("newarr",         InlineType),
    0x8E: ("ldlen",          InlineNone),
    0x8F: ("ldelema",        InlineType),
    0x90: ("ldelem.i1",      InlineNone),
    0x91: ("ldelem.u1",      InlineNone),
    0x92: ("ldelem.i2",      InlineNone),
    0x93: ("ldelem.u2",      InlineNone),
    0x94: ("ldelem.i4",      InlineNone),
    0x95: ("ldelem.u4",      InlineNone),
    0x96: ("ldelem.i8",      InlineNone),
    0x97: ("ldelem.i",       InlineNone),
    0x98: ("ldelem.r4",      InlineNone),
    0x99: ("ldelem.r8",      InlineNone),
    0x9A: ("ldelem.ref",     InlineNone),
    0x9B: ("stelem.i",       InlineNone),
    0x9C: ("stelem.i1",      InlineNone),
    0x9D: ("stelem.i2",      InlineNone),
    0x9E: ("stelem.i4",      InlineNone),
    0x9F: ("stelem.i8",      InlineNone),
    0xA0: ("stelem.r4",      InlineNone),
    0xA1: ("stelem.r8",      InlineNone),
    0xA2: ("stelem.ref",     InlineNone),
    0xA3: ("ldelem",         InlineType),
    0xA4: ("stelem",         InlineType),
    0xA5: ("unbox.any",      InlineType),
    0xB3: ("conv.ovf.i1",    InlineNone),
    0xB4: ("conv.ovf.u1",    InlineNone),
    0xB5: ("conv.ovf.i2",    InlineNone),
    0xB6: ("conv.ovf.u2",    InlineNone),
    0xB7: ("conv.ovf.i4",    InlineNone),
    0xB8: ("conv.ovf.u4",    InlineNone),
    0xB9: ("conv.ovf.i8",    InlineNone),
    0xBA: ("conv.ovf.u8",    InlineNone),
    0xC2: ("refanyval",      InlineType),
    0xC3: ("ckfinite",       InlineNone),
    0xC6: ("mkrefany",       InlineType),
    0xD0: ("ldtoken",        InlineTok),
    0xD1: ("conv.u2",        InlineNone),
    0xD2: ("conv.u1",        InlineNone),
    0xD3: ("conv.i",         InlineNone),
    0xD4: ("conv.ovf.i",     InlineNone),
    0xD5: ("conv.ovf.u",     InlineNone),
    0xD6: ("add.ovf",        InlineNone),
    0xD7: ("add.ovf.un",     InlineNone),
    0xD8: ("mul.ovf",        InlineNone),
    0xD9: ("mul.ovf.un",     InlineNone),
    0xDA: ("sub.ovf",        InlineNone),
    0xDB: ("sub.ovf.un",     InlineNone),
    0xDC: ("endfinally",     InlineNone),
    0xDD: ("leave",          InlineBrTarget),
    0xDE: ("leave.s",        ShortInlineBrTarget),
    0xDF: ("stind.i",        InlineNone),
    0xE0: ("conv.u",         InlineNone),
    0xFE00: ("arglist",        InlineNone),
    0xFE01: ("ceq",            InlineNone),
    0xFE02: ("cgt",            InlineNone),
    0xFE03: ("cgt.un",         InlineNone),
    0xFE04: ("clt",            InlineNone),
    0xFE05: ("clt.un",         InlineNone),
    0xFE06: ("ldftn",          InlineMethod),
    0xFE07: ("ldvirtftn",      InlineMethod),
    0xFE09: ("ldarg",          InlineVar),
    0xFE0A: ("ldarga",         InlineVar),
    0xFE0B: ("starg",          InlineVar),
    0xFE0C: ("ldloc",          InlineVar),
    0xFE0D: ("ldloca",         InlineVar),
    0xFE0E: ("stloc",          InlineVar),
    0xFE0F: ("localloc",       InlineNone),
    0xFE11: ("endfilter",      InlineNone),
    0xFE12: ("unaligned.",     ShortInlineI),
    0xFE13: ("volatile.",      InlineNone),
    0xFE14: ("tail.",          InlineNone),
    0xFE15: ("initobj",        InlineType),
    0xFE16: ("constrained.",   InlineType),
    0xFE17: ("cpblk",          InlineNone),
    0xFE18: ("initblk",        InlineNone),
    0xFE19: ("no.",            ShortInlineI),
    0xFE1A: ("rethrow",        InlineNone),
    0xFE1C: ("sizeof",         InlineType),
    0xFE1D: ("refanytype",     InlineNone),
    0xFE1E: ("readonly.",      InlineNone),
}


class Field(object):
    """An operand field inside an instruction: [offset, offset+size)."""

    __slots__ = ("kind", "offset", "size")

    def __init__(self, kind, offset, size):
        self.kind = kind
        self.offset = offset
        self.size = size

    def __repr__(self):
        return "Field(%s, %d, %d)" % (self.kind, self.offset, self.size)


class Instruction(object):
    __slots__ = ("opcode", "name", "operand_type", "opcode_size", "size",
                 "fields", "operand")

    def __init__(self, opcode, name, operand_type, opcode_size, size, fields,
                 operand):
        self.opcode = opcode
        self.name = name
        self.operand_type = operand_type
        self.opcode_size = opcode_size   # 1 or 2 (0xFE prefix)
        self.size = size                 # total size in bytes
        self.fields = fields             # [Field]
        self.operand = operand           # decoded value (int/float/list) or None

    def __repr__(self):
        return "Instruction(%s, size=%d)" % (self.name, self.size)

    def text(self):
        """Simple ildasm-like rendering (used when IDA gives no text)."""
        op, t = self.operand, self.operand_type
        if op is None:
            return self.name
        if t in (InlineMethod, InlineField, InlineType, InlineTok, InlineSig,
                 InlineString):
            table = TOKEN_TABLES.get(op >> 24, "table 0x%02X" % (op >> 24))
            return "%s 0x%08X  // %s" % (self.name, op, table)
        if t == InlineSwitch:
            return "%s (%s)" % (self.name, ", ".join("%+d" % x for x in op))
        if t in (ShortInlineBrTarget, InlineBrTarget):
            return "%s %+d" % (self.name, op)
        return "%s %r" % (self.name, op)


def decode(data, offset=0):
    """
    Decode one CIL instruction from `data` (bytes) at `offset`.
    Returns an Instruction, or None for an unknown opcode or truncated data.
    """
    if offset >= len(data):
        return None
    b0 = data[offset]
    if b0 == 0xFE:
        if offset + 1 >= len(data):
            return None
        code, opsz = 0xFE00 | data[offset + 1], 2
    else:
        code, opsz = b0, 1
    entry = OPCODES.get(code)
    if entry is None:
        return None
    name, otype = entry
    pos = offset + opsz

    if otype == InlineSwitch:
        if pos + 4 > len(data):
            return None
        (n,) = struct.unpack_from("<I", data, pos)
        size = opsz + 4 + 4 * n
        if offset + size > len(data):
            return None
        targets = list(struct.unpack_from("<%di" % n, data, pos + 4)) if n else []
        fields = [Field(F_SWITCH_COUNT, opsz, 4)]
        fields += [Field(F_SWITCH_TARGET, opsz + 4 + 4 * i, 4) for i in range(n)]
        return Instruction(code, name, otype, opsz, size, fields, targets)

    osz = OPERAND_SIZE[otype]
    size = opsz + osz
    if offset + size > len(data):
        return None
    if osz == 0:
        return Instruction(code, name, otype, opsz, size, [], None)
    raw = data[pos:pos + osz]
    if otype == ShortInlineR:
        val = struct.unpack("<f", raw)[0]
    elif otype == InlineR:
        val = struct.unpack("<d", raw)[0]
    elif otype in (ShortInlineI, ShortInlineBrTarget):
        val = struct.unpack("<b", raw)[0]
    elif otype == ShortInlineVar:
        val = raw[0]
    elif otype == InlineVar:
        val = struct.unpack("<H", raw)[0]
    elif otype in (InlineI, InlineBrTarget):
        val = struct.unpack("<i", raw)[0]
    elif otype == InlineI8:
        val = struct.unpack("<q", raw)[0]
    else:  # tokens
        val = struct.unpack("<I", raw)[0]
    return Instruction(code, name, otype, opsz, size,
                       [Field(_KIND_OF[otype], opsz, osz)], val)


class CilWildcardOptions(object):
    """Which operand kinds are wildcarded automatically."""

    def __init__(self):
        self.enabled = True
        self.tokens = True            # method/field/type/tok/sig tokens
        self.strings = True           # ldstr tokens
        self.keep_token_table = True  # keep the token's table byte (MSB)
        self.branches = True          # branch / leave offsets
        self.switch_targets = True    # switch jump table
        self.vars = False             # arg / local indices
        self.immediates = False       # ldc.* constants


def auto_mask(insn, opts):
    """Per-byte wildcard mask (list of bool, len == insn.size)."""
    mask = [False] * insn.size
    if not opts.enabled:
        return mask
    for f in insn.fields:
        k = f.kind
        if k == F_TOKEN:
            want = opts.tokens
        elif k == F_STRING:
            want = opts.strings
        elif k == F_BRANCH:
            want = opts.branches
        elif k == F_SWITCH_TARGET:
            want = opts.switch_targets
        elif k == F_VAR:
            want = opts.vars
        elif k == F_IMM:
            want = opts.immediates
        else:   # F_SWITCH_COUNT: the count fixes the instruction length
            want = False
        if not want:
            continue
        size = f.size
        if k in (F_TOKEN, F_STRING) and opts.keep_token_table:
            size = 3   # little-endian: RID in bytes 0-2, table id in byte 3
        for i in range(f.offset, f.offset + size):
            mask[i] = True
    return mask
