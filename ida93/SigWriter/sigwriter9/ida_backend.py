"""
IDA-side logic: reads bytes from the database, decodes instructions and
computes which bytes should be wildcarded automatically.

Written against the IDA Pro 9.3+ IDAPython API (checked against the
official SDK sources of 9.3.0 and 9.5.0).
"""

import ida_bytes
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_segment
import ida_ua
import ida_funcs
import ida_idp

try:
    import ida_fixup
except ImportError:  # pragma: no cover
    ida_fixup = None

from .pattern import Pattern

BADADDR = ida_idaapi.BADADDR

# UA_MAXOP is defined in ida.hpp, so IDAPython exposes it in ida_ida and not
# in ida_ua. Look it up in both places, falling back to the SDK value (8).
UA_MAXOP = getattr(ida_ida, "UA_MAXOP", None) or getattr(ida_ua, "UA_MAXOP", None) or 8

# Bytes per row used for data / unknown / partial items.
DATA_ROW_SIZE = 16

# Immediate values below this are never considered addresses by the
# "address immediates" heuristic (avoids wildcarding small constants).
MIN_ADDRESS_IMM = 0x10000


TITLE = "SigWriter"

# Wildcard options shown by the GUI: (WildcardOptions attribute, label[, tooltip]).
OPTION_ITEMS = [
    ("branches", "Destinos de saltos/calls"),
    ("memory", "Referencias a memoria global"),
    ("address_imm", "Inmediatos que son direcciones"),
    ("all_imm", "Todos los inmediatos"),
    ("displacements", "Desplazamientos [reg+disp]"),
    ("fixups", "Bytes con relocaciones (fixups)"),
    ("whole_insn_fallback", "Instruccion completa si no se conoce el operando (RISC)"),
]

# Option -> predicate over {key: checked}; the option is greyed out when False.
OPTION_ENABLED_IF = {
    "address_imm": lambda c: not c["all_imm"],
}

PLFM_NET = getattr(ida_idp, "PLFM_NET", 19)


def is_dotnet_db():
    """True when the database uses the .NET (CLI) processor module."""
    return ida_idp.ph_get_id() == PLFM_NET


class WildcardOptions(object):
    """Which kinds of bytes get wildcarded automatically."""

    def __init__(self):
        self.enabled = True          # master switch
        self.branches = True         # relative/absolute jump & call targets (o_near/o_far)
        self.memory = True           # global memory references (o_mem, RIP-relative)
        self.address_imm = True      # immediates that are offsets/addresses
        self.all_imm = False         # every immediate value
        self.displacements = False   # [reg+disp] displacements (o_displ)
        self.fixups = True           # bytes covered by relocations/fixups
        self.whole_insn_fallback = True  # wildcard the whole insn if the
                                         # operand offset is unknown (RISC)


class Row(object):
    """One row of the byte grid: an instruction or a chunk of data."""

    __slots__ = ("ea", "offset", "size", "text", "is_code")

    def __init__(self, ea, offset, size, text, is_code):
        self.ea = ea            # address of the first byte in this row
        self.offset = offset    # index of the first byte in the flat pattern
        self.size = size
        self.text = text
        self.is_code = is_code


class Selection(object):
    """
    Result of analysing an address range.
      values[i]     byte value
      auto_wild[i]  True if the automatic rules wildcard this byte
      rows          rows for display
    """

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


def _ptr_size():
    return 8 if ida_ida.inf_is_64bit() else 4


def get_user_selection(widget=None):
    """
    Return (start, end) for the current selection in `widget` (or the last
    active address-based view when widget is None), or None if there is no
    selection.
    """
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
# Automatic wildcard rules
# ---------------------------------------------------------------------------
def _looks_like_address(value):
    if value < MIN_ADDRESS_IMM:
        return False
    return ida_segment.getseg(value) is not None


def _operand_wanted(insn, n, op, flags, opts):
    t = op.type
    if t in (ida_ua.o_near, ida_ua.o_far):
        return opts.branches
    if t == ida_ua.o_mem:
        return opts.memory
    if t == ida_ua.o_displ:
        if opts.displacements:
            return True
        # [reg*4 + table] style: the displacement is really a global address
        return opts.memory and (ida_bytes.is_off(flags, n)
                                or _looks_like_address(op.addr))
    if t == ida_ua.o_imm:
        if opts.all_imm:
            return True
        return opts.address_imm and (ida_bytes.is_off(flags, n)
                                     or _looks_like_address(op.value))
    return False


def _insn_auto_mask(insn, opts):
    size = insn.size
    mask = [False] * size
    flags = ida_bytes.get_flags(insn.ea)

    ops = []
    for n in range(UA_MAXOP):
        try:
            op = insn.ops[n]
        except (IndexError, KeyError):
            break
        if op.type == ida_ua.o_void:
            break
        ops.append((n, op))

    # Field boundaries inside the instruction (start of every operand field).
    boundaries = {size}
    for _, op in ops:
        if op.offb:
            boundaries.add(op.offb)
        if op.offo:
            boundaries.add(op.offo)

    for n, op in ops:
        if not _operand_wanted(insn, n, op, flags, opts):
            continue
        offsets = [o for o in (op.offb, op.offo) if 0 < o < size]
        if not offsets:
            # Processor does not tell where the operand lives (typical on
            # fixed-width RISC ISAs): optionally wildcard the whole insn.
            if opts.whole_insn_fallback:
                mask = [True] * size
            continue
        for off in offsets:
            nxt = min(b for b in boundaries if b > off)
            for i in range(off, nxt):
                mask[i] = True
    return mask


def _apply_fixups(sel, opts):
    if ida_fixup is None or not opts.fixups:
        return
    start, end = sel.start, sel.end
    ptr_size = _ptr_size()
    try:
        if ida_fixup.exists_fixup(start):
            ea = start
        else:
            ea = ida_fixup.get_next_fixup_ea(start)
        # A fixup that starts right before the range can still cover it.
        prev = ida_fixup.get_prev_fixup_ea(start)
        candidates = []
        if prev != BADADDR and start - prev < 8:
            candidates.append(prev)
        while ea != BADADDR and ea < end:
            candidates.append(ea)
            ea = ida_fixup.get_next_fixup_ea(ea)
        for fea in candidates:
            fd = ida_fixup.fixup_data_t()
            if not fd.get(fea):
                continue
            try:
                fsize = fd.calc_size()
            except Exception:
                fsize = ptr_size
            if fsize <= 0:
                fsize = ptr_size
            for a in range(fea, fea + fsize):
                if start <= a < end:
                    sel.auto_wild[a - start] = True
    except Exception as e:  # never let fixup quirks break the plugin
        print("[SigWriter] fixup scan failed: %s" % e)


def analyze_range(start, end, opts):
    """Build a Selection (bytes + automatic wildcards + rows) for [start, end)."""
    sel = Selection(start, end)
    ea = start
    while ea < end:
        flags = ida_bytes.get_flags(ea)
        row_start = len(sel.values)

        insn = None
        if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) <= 0:
                insn = None

        if insn is not None and ea + insn.size <= end:
            size = insn.size
            values, unloaded = _read_bytes(ea, size)
            if opts.enabled:
                mask = _insn_auto_mask(insn, opts)
            else:
                mask = [False] * size
            sel.values.extend(values)
            sel.auto_wild.extend(m or u for m, u in zip(mask, unloaded))
            sel.rows.append(Row(ea, row_start, size, _disasm_text(ea), True))
            ea += size
            continue

        # Data, unknown bytes, or an instruction cut by the range end.
        item_end = ida_bytes.get_item_end(ea)
        if item_end <= ea:
            item_end = ea + 1
        chunk_end = min(item_end, end, ea + DATA_ROW_SIZE)
        size = chunk_end - ea
        values, unloaded = _read_bytes(ea, size)
        sel.values.extend(values)
        sel.auto_wild.extend(unloaded)
        head = ida_bytes.get_item_head(ea)
        if head == ea:
            text = _disasm_text(ea)
        else:
            text = "(+0x%X in item at 0x%X)" % (ea - head, head)
        if insn is not None or (ida_bytes.is_code(flags) and head != ea):
            text += "  [truncated]"
        sel.rows.append(Row(ea, row_start, size, text, False))
        ea = chunk_end

    if opts.enabled:
        _apply_fixups(sel, opts)
    return sel


# ---------------------------------------------------------------------------
# Searching
# ---------------------------------------------------------------------------
def _search_flags():
    # BIN_SEARCH_CASE: find_bytes() is case-insensitive by default; we want
    # raw byte comparison.
    return (ida_bytes.BIN_SEARCH_FORWARD
            | ida_bytes.BIN_SEARCH_CASE
            | ida_bytes.BIN_SEARCH_NOBREAK
            | ida_bytes.BIN_SEARCH_NOSHOW)


def _find_next(ea, max_ea, image, mask):
    """
    One forward search. IDA 9.x removed the (image, mask, step, flags)
    overload of bin_search; find_bytes() builds the compiled pattern for us.
    Mask bytes are 0xFF (must match) / 0x00 (wildcard), which is valid
    both with and without BIN_SEARCH_BITMASK.
    """
    return ida_bytes.find_bytes(image, ea, range_end=max_ea, mask=mask,
                                flags=_search_flags())


def find_matches(pattern, limit=100):
    """Return the list of addresses (up to `limit`) where `pattern` matches."""
    if len(pattern) == 0:
        return []
    p, lead = pattern.trimmed()
    if len(p) == 0:
        return []
    image = bytes(bytearray(p.masked_values()))
    mask = bytes(bytearray(0x00 if w else 0xFF for w in p.wild))

    min_ea, max_ea = db_bounds()
    results = []
    ea = min_ea
    while len(results) < limit:
        ea = _find_next(ea, max_ea, image, mask)
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
