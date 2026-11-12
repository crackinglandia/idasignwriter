"""
IDA-side logic for .NET (CLI) databases: reads the IL bytes, decodes them
with our own ECMA-335 decoder (cil.py) and computes which bytes should be
wildcarded automatically.

Same interface as the x86 backend, so the GUI module is shared verbatim.
This file is identical in the IDA 8.2 and the IDA 9.3+ .NET plugins: the
only API difference it touches (byte search) is resolved at runtime.
"""

import ida_bytes
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_funcs

from . import cil
from .pattern import Pattern

BADADDR = ida_idaapi.BADADDR
TITLE = "SigWriter .NET"

# Bytes per grid row (long instructions such as `switch` span several rows).
ROW_SIZE = 16

PLFM_NET = getattr(ida_idp, "PLFM_NET", 19)

WildcardOptions = cil.CilWildcardOptions

OPTION_ITEMS = [
    ("tokens", "Tokens de metadatos (call, newobj, ldfld...)",
     "Metodos, campos, tipos, ldtoken y calli: el RID cambia entre compilaciones"),
    ("strings", "Tokens de strings (ldstr)",
     "Token 0x70xxxxxx del heap #US"),
    ("keep_token_table", "Conservar la tabla del token (byte alto)",
     "Mantiene el byte alto del token: 06 MethodDef, 0A MemberRef, "
     "04 Field, 01 TypeRef, 02 TypeDef, 1B TypeSpec, 2B MethodSpec, 70 String"),
    ("branches", "Offsets de saltos (br, brtrue, leave...)"),
    ("switch_targets", "Tabla de destinos de switch",
     "El numero de casos se mantiene: fija el largo de la instruccion"),
    ("vars", "Indices de locals/args (ldloc.s, ldarg, stloc...)"),
    ("immediates", "Constantes (ldc.i4, ldc.i8, ldc.r4, ldc.r8...)"),
]

OPTION_ENABLED_IF = {
    "keep_token_table": lambda c: c["tokens"] or c["strings"],
}


def is_dotnet_db():
    """True when the database uses the .NET (CLI) processor module."""
    return ida_idp.ph_get_id() == PLFM_NET


class Row(object):
    """One row of the byte grid: an instruction (or part of it) or data."""

    __slots__ = ("ea", "offset", "size", "text", "is_code")

    def __init__(self, ea, offset, size, text, is_code):
        self.ea = ea
        self.offset = offset
        self.size = size
        self.text = text
        self.is_code = is_code


class Selection(object):
    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.values = []
        self.auto_wild = []
        self.rows = []

    def __len__(self):
        return len(self.values)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def db_bounds():
    return ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()


def get_user_selection(widget=None):
    try:
        ok, start, end = ida_kernwin.read_range_selection(widget)
    except Exception:
        ok = False
    if ok and start != BADADDR and end != BADADDR and end > start:
        return start, end
    return None


def get_current_item_range(ea=None):
    if ea is None:
        ea = ida_kernwin.get_screen_ea()
    if ea == BADADDR:
        return None
    head = ida_bytes.get_item_head(ea)
    end = ida_bytes.get_item_end(head)
    if end <= head:
        end = head + 1
    return head, end


def get_function_range(ea=None):
    if ea is None:
        ea = ida_kernwin.get_screen_ea()
    f = ida_funcs.get_func(ea)
    if f is None:
        return None
    return f.start_ea, f.end_ea


def _read_bytes(ea, size):
    data = ida_bytes.get_bytes(ea, size)
    values, unloaded = [], []
    for i in range(size):
        if data is not None and i < len(data) and ida_bytes.is_loaded(ea + i):
            values.append(data[i])
            unloaded.append(False)
        else:
            values.append(0)
            unloaded.append(True)
    return values, unloaded


def _disasm_text(ea):
    line = ida_lines.generate_disasm_line(ea, 0)
    if line is None:
        return ""
    return ida_lines.tag_remove(line).strip()


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def _add_rows(sel, ea, offset, size, text, is_code):
    """Append `size` bytes as one or more rows of at most ROW_SIZE bytes."""
    first = True
    for off in range(0, size, ROW_SIZE):
        n = min(ROW_SIZE, size - off)
        sel.rows.append(Row(ea + off, offset + off, n,
                            text if first else "    (cont.)", is_code))
        first = False


def analyze_range(start, end, opts):
    """Build a Selection (bytes + automatic wildcards + rows) for [start, end)."""
    sel = Selection(start, end)
    values, unloaded = _read_bytes(start, end - start)
    data = bytes(bytearray(values))
    sel.values = values
    sel.auto_wild = list(unloaded)

    ea = start
    while ea < end:
        off = ea - start
        flags = ida_bytes.get_flags(ea)
        item_end = ida_bytes.get_item_end(ea)
        if item_end <= ea:
            item_end = ea + 1

        insn = None
        if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):
            insn = cil.decode(data, off)

        if insn is not None:
            mask = cil.auto_mask(insn, opts)
            for i, m in enumerate(mask):
                if m:
                    sel.auto_wild[off + i] = True
            text = _disasm_text(ea) or insn.text()
            if item_end - ea != insn.size:
                # IDA and ECMA-335 disagree on the length: trust the spec,
                # but make it visible.
                text += "  [IDA: %d bytes, CIL: %d]" % (item_end - ea, insn.size)
            _add_rows(sel, ea, off, insn.size, text, True)
            ea += insn.size
            continue

        # Data, method headers, unknown opcodes or an instruction cut by the
        # end of the range: raw bytes, no automatic wildcards.
        chunk_end = min(item_end, end)
        head = ida_bytes.get_item_head(ea)
        if head == ea:
            text = _disasm_text(ea)
        else:
            text = "(+0x%X in item at 0x%X)" % (ea - head, head)
        if ida_bytes.is_code(flags) and head == ea:
            if item_end > end:
                text += "  [truncated]"
            else:
                text += "  [CIL no reconocido]"
        _add_rows(sel, ea, off, chunk_end - ea, text, False)
        ea = chunk_end
    return sel


# ---------------------------------------------------------------------------
# Searching
# ---------------------------------------------------------------------------
def _search_flags():
    return (ida_bytes.BIN_SEARCH_FORWARD
            | getattr(ida_bytes, "BIN_SEARCH_CASE", 0)
            | ida_bytes.BIN_SEARCH_NOBREAK
            | ida_bytes.BIN_SEARCH_NOSHOW)


def _find_next(ea, max_ea, image, wild):
    if hasattr(ida_bytes, "find_bytes"):
        # IDA 9.x: the (image, mask, step, flags) bin_search overload is gone.
        mask = bytes(bytearray(0x00 if w else 0xFF for w in wild))
        return ida_bytes.find_bytes(image, ea, range_end=max_ea, mask=mask,
                                    flags=_search_flags())
    # IDA 8.x: mask uses 1 = defined / 0 = wildcard (a leading 0xFF would
    # be read as "all bytes defined").
    mask = bytes(bytearray(0 if w else 1 for w in wild))
    return ida_bytes.bin_search(ea, max_ea, image, mask,
                                ida_bytes.BIN_SEARCH_FORWARD, _search_flags())


def find_matches(pattern, limit=100):
    """Return the list of addresses (up to `limit`) where `pattern` matches."""
    if len(pattern) == 0:
        return []
    p, lead = pattern.trimmed()
    if len(p) == 0:
        return []
    image = bytes(bytearray(p.masked_values()))
    min_ea, max_ea = db_bounds()
    results = []
    ea = min_ea
    while len(results) < limit:
        ea = _find_next(ea, max_ea, image, p.wild)
        if ea == BADADDR or ea is None:
            break
        results.append(ea - lead)
        ea += 1
    return results


def auto_unique(start, opts, max_len=256):
    """
    Grow a pattern instruction by instruction starting at `start` until it
    matches exactly one location. Returns (end, match_count).
    """
    ea = ida_bytes.get_item_head(start)
    end = ea
    count = 0
    ida_kernwin.show_wait_box("Buscando patron unico...")
    try:
        while end - ea < max_len:
            if ida_kernwin.user_cancelled():
                break
            nxt = ida_bytes.get_item_end(end)
            if nxt <= end:
                nxt = end + 1
            end = nxt
            sel = analyze_range(ea, end, opts)
            p = Pattern(sel.values, sel.auto_wild if opts.enabled else None, ea)
            if len(p.trimmed()[0]) == 0:
                continue
            count = len(find_matches(p, limit=2))
            if count == 1:
                break
    finally:
        ida_kernwin.hide_wait_box()
    return end, count
