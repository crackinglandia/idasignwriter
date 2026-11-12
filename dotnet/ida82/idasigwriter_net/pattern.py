"""
Pure-Python pattern model and exporters.

This module does not import anything from IDA, so it can be unit-tested
outside of IDA (see tests/test_pattern.py).
"""

import re

__all__ = [
    "Pattern",
    "fmt_ida",
    "fmt_double_qmark",
    "fmt_raw",
    "fmt_code_style",
    "fmt_c_array",
    "fmt_yara",
    "fmt_yara_string",
    "fmt_blob",
    "parse_pattern",
    "sanitize_identifier",
]


class Pattern(object):
    """A byte pattern: a list of byte values plus a per-byte wildcard flag."""

    def __init__(self, values, wild=None, start_ea=None):
        self.values = [int(v) & 0xFF for v in values]
        if wild is None:
            wild = [False] * len(self.values)
        if len(wild) != len(self.values):
            raise ValueError("values/wild length mismatch")
        self.wild = [bool(w) for w in wild]
        self.start_ea = start_ea

    def __len__(self):
        return len(self.values)

    def __eq__(self, other):
        return (isinstance(other, Pattern)
                and self.values == other.values
                and self.wild == other.wild)

    def __repr__(self):
        return "Pattern(%r)" % fmt_double_qmark(self)

    @property
    def wildcard_count(self):
        return sum(1 for w in self.wild if w)

    def without_wildcards(self):
        return Pattern(self.values, None, self.start_ea)

    def masked_values(self, fill=0x00):
        """Byte values with every wildcard replaced by `fill`."""
        return [fill if w else v for v, w in zip(self.values, self.wild)]

    def trimmed(self):
        """
        Return (pattern, leading_trim) with leading/trailing wildcards
        removed. `leading_trim` is the number of bytes dropped at the start.
        """
        lo, hi = 0, len(self.values)
        while lo < hi and self.wild[lo]:
            lo += 1
        while hi > lo and self.wild[hi - 1]:
            hi -= 1
        start = None if self.start_ea is None else self.start_ea + lo
        return Pattern(self.values[lo:hi], self.wild[lo:hi], start), lo


# ---------------------------------------------------------------------------
# Standalone text formats
# ---------------------------------------------------------------------------
def _fmt_tokens(pattern, wildcard_token, use_wildcards=True):
    out = []
    for v, w in zip(pattern.values, pattern.wild):
        out.append(wildcard_token if (w and use_wildcards) else "%02X" % v)
    return " ".join(out)


def fmt_ida(pattern, use_wildcards=True):
    """IDA / SigMaker style: `48 8B 05 ? ? ? ?`."""
    return _fmt_tokens(pattern, "?", use_wildcards)


def fmt_double_qmark(pattern, use_wildcards=True):
    """x64dbg / Cheat Engine / YARA-like style: `48 8B 05 ?? ?? ?? ??`."""
    return _fmt_tokens(pattern, "??", use_wildcards)


def fmt_raw(pattern):
    """Exact bytes, no wildcards at all: `48 8B 05 10 20 30 40`."""
    return _fmt_tokens(pattern, "", use_wildcards=False)


def fmt_code_style(pattern, use_wildcards=True):
    """
    Code style used by most C/C++ scanners:
    ("\\x48\\x8B\\x05\\x00", "xxx?")
    """
    data = "".join("\\x%02X" % v for v in pattern.masked_values()) \
        if use_wildcards else "".join("\\x%02X" % v for v in pattern.values)
    if use_wildcards:
        mask = "".join("?" if w else "x" for w in pattern.wild)
    else:
        mask = "x" * len(pattern)
    return data, mask


# ---------------------------------------------------------------------------
# C / C++
# ---------------------------------------------------------------------------
_IDENT_RE = re.compile(r"[^A-Za-z0-9_]")


def sanitize_identifier(name, default="pattern"):
    name = _IDENT_RE.sub("_", (name or "").strip())
    if not name:
        name = default
    if name[0].isdigit():
        name = "_" + name
    return name[:128]


def fmt_c_array(pattern, name="pattern", use_wildcards=True, per_line=16):
    name = sanitize_identifier(name)
    has_wild = use_wildcards and pattern.wildcard_count > 0
    values = pattern.masked_values() if has_wild else pattern.values
    n = len(values)

    lines = []
    header = "// %d bytes" % n
    if has_wild:
        header += ", %d wildcards" % pattern.wildcard_count
    if pattern.start_ea is not None:
        header += ", generated from 0x%X" % pattern.start_ea
    lines.append(header)
    lines.append("// %s" % (fmt_ida(pattern) if has_wild else fmt_raw(pattern)))

    lines.append("const unsigned char %s[%d] = {" % (name, n))
    for i in range(0, n, per_line):
        chunk = ", ".join("0x%02X" % v for v in values[i:i + per_line])
        lines.append("    " + chunk + ("," if i + per_line < n else ""))
    lines.append("};")

    if has_wild:
        mask = "".join("?" if w else "x" for w in pattern.wild)
        lines.append("const char %s_mask[%d] = \"%s\";" % (name, n + 1, mask))
        lines.append("")
        lines.append("// Wildcard bitmap (1 = must match, 0 = wildcard)")
        lines.append("const unsigned char %s_bitmap[%d] = {" % (name, n))
        bits = [0 if w else 1 for w in pattern.wild]
        for i in range(0, n, per_line):
            chunk = ", ".join(str(b) for b in bits[i:i + per_line])
            lines.append("    " + chunk + ("," if i + per_line < n else ""))
        lines.append("};")

    data, mask = fmt_code_style(pattern, has_wild)
    lines.append("")
    lines.append("// Code style")
    lines.append("// \"%s\", \"%s\"" % (data, mask))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# YARA
# ---------------------------------------------------------------------------
def _yara_escape(s):
    return str(s).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ")


# Layout limits for YARA hex strings: bytes per row, and rows per string.
# Longer patterns are split into $pattern_p1, $pattern_p2, ...
YARA_COLUMNS = 28
YARA_MAX_ROWS = 20


def _yara_trimmed(pattern, use_wildcards):
    """
    YARA does not accept hex strings that begin or end with a wildcard, so
    leading/trailing wildcards are trimmed. Returns (pattern, leading_trim).
    Raises ValueError if nothing is left after trimming.
    """
    p = pattern if use_wildcards else pattern.without_wildcards()
    p, lead = p.trimmed()
    if len(p) == 0:
        raise ValueError("The pattern contains only wildcards; "
                         "YARA needs at least one concrete byte.")
    return p, lead


def _yara_pieces(p, columns, max_rows):
    """
    Split an already-trimmed pattern into pieces of at most columns*max_rows
    bytes. Each piece is trimmed again (a piece cannot start or end with a
    wildcard either). Returns [(offset_in_p, piece)]; pieces made only of
    wildcards are dropped.
    """
    size = columns * max_rows
    pieces = []
    for off in range(0, len(p), size):
        chunk = Pattern(p.values[off:off + size], p.wild[off:off + size])
        chunk, lead = chunk.trimmed()
        if len(chunk):
            pieces.append((off + lead, chunk))
    return pieces


def _yara_hex_block(piece, columns, indent):
    """`{ .. }` on one line if it fits in a row, else one row per line."""
    tokens = ["??" if w else "%02X" % v for v, w in zip(piece.values, piece.wild)]
    rows = [" ".join(tokens[i:i + columns]) for i in range(0, len(tokens), columns)]
    if len(rows) == 1:
        return ["{ %s }" % rows[0]]
    return ["{"] + [indent + "    " + r for r in rows] + [indent + "}"]


def _yara_strings(p, columns, max_rows, indent):
    """Lines declaring $pattern (or $pattern_p1..N). Returns (lines, pieces)."""
    pieces = _yara_pieces(p, columns, max_rows)
    lines = []
    if len(pieces) == 1:
        block = _yara_hex_block(pieces[0][1], columns, indent)
        lines.append(indent + "$pattern = " + block[0])
        lines.extend(block[1:])
        return lines, pieces
    base = pieces[0][0]
    for k, (off, piece) in enumerate(pieces, 1):
        block = _yara_hex_block(piece, columns, indent)
        lines.append(indent + "// offset +%d (0x%X), %d bytes"
                     % (off - base, off - base, len(piece)))
        lines.append(indent + "$pattern_p%d = %s" % (k, block[0]))
        lines.extend(block[1:])
    return lines, pieces


def fmt_yara_string(pattern, use_wildcards=True,
                    columns=YARA_COLUMNS, max_rows=YARA_MAX_ROWS):
    """
    Only the YARA hex string(s), without the rule: `{ E8 ?? ?? 48 8B }`.
    Patterns longer than columns*max_rows bytes are emitted as
    `$pattern_p1 = {...}`, `$pattern_p2 = {...}`, ...
    """
    p, _ = _yara_trimmed(pattern, use_wildcards)
    lines, pieces = _yara_strings(p, columns, max_rows, "")
    if len(pieces) == 1:
        lines[0] = lines[0][len("$pattern = "):]
    return "\n".join(lines)


def fmt_yara(pattern, rule_name="pattern", use_wildcards=True, meta=None,
             columns=YARA_COLUMNS, max_rows=YARA_MAX_ROWS):
    """Build a complete YARA rule (see _yara_trimmed for trimming rules)."""
    rule_name = sanitize_identifier(rule_name, "pattern")
    p, lead = _yara_trimmed(pattern, use_wildcards)
    string_lines, pieces = _yara_strings(p, columns, max_rows, " " * 8)

    out = ["rule %s" % rule_name, "{"]
    meta_items = list((meta or {}).items())
    if p.start_ea is not None:
        meta_items.append(("address", "0x%X" % p.start_ea))
    if lead:
        meta_items.append(("note", "%d leading wildcard byte(s) trimmed" % lead))
    if len(pieces) > 1:
        meta_items.append(("pieces", "%d pieces of up to %d bytes, %d bytes total"
                           % (len(pieces), columns * max_rows, len(p))))
    if meta_items:
        out.append("    meta:")
        for k, v in meta_items:
            out.append("        %s = \"%s\"" % (sanitize_identifier(k, "key"),
                                                _yara_escape(v)))
    out.append("    strings:")
    out.extend(string_lines)
    out.append("    condition:")
    if len(pieces) == 1:
        out.append("        $pattern")
    else:
        # Every piece must appear at its exact offset from $pattern_p1.
        base = pieces[0][0]
        conds = ["$pattern_p%d at @pattern_p1[i] + %d" % (k, off - base)
                 for k, (off, _) in enumerate(pieces, 1) if k > 1]
        out.append("        for any i in (1..#pattern_p1) : (")
        for j, c in enumerate(conds):
            out.append("            " + c + (" and" if j + 1 < len(conds) else ""))
        out.append("        )")
    out.append("}")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Binary blob
# ---------------------------------------------------------------------------
def fmt_blob(pattern, use_wildcards=True, fill=0x00):
    """
    Return (data, mask). `mask` is None when there are no wildcards,
    otherwise it has one byte per pattern byte: 0xFF = must match,
    0x00 = wildcard. Wildcarded bytes in `data` are replaced by `fill`.
    """
    if not use_wildcards or pattern.wildcard_count == 0:
        return bytes(bytearray(pattern.values)), None
    data = bytes(bytearray(pattern.masked_values(fill)))
    mask = bytes(bytearray(0x00 if w else 0xFF for w in pattern.wild))
    return data, mask


# ---------------------------------------------------------------------------
# Parsing (accepts "48 8B ? ??", "488B??", "\x48\x8B" + mask is not handled)
# ---------------------------------------------------------------------------
def parse_pattern(text):
    tokens = text.replace(",", " ").split()
    values, wild = [], []
    for tok in tokens:
        if tok in ("?", "??"):
            values.append(0)
            wild.append(True)
            continue
        if tok.lower().startswith("0x"):
            tok = tok[2:]
        if len(tok) % 2:
            raise ValueError("Invalid token: %r" % tok)
        for i in range(0, len(tok), 2):
            pair = tok[i:i + 2]
            if pair == "??":
                values.append(0)
                wild.append(True)
            else:
                values.append(int(pair, 16))
                wild.append(False)
    return Pattern(values, wild)
