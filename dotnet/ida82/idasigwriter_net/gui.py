"""
PyQt5 GUI hosted in a dockable ida_kernwin.PluginForm (IDA Pro 8.2).
"""

import os

import ida_bytes
import ida_kernwin

from PyQt5 import QtCore, QtGui, QtWidgets

from . import ida_backend as backend
from .pattern import (Pattern, fmt_ida, fmt_double_qmark, fmt_raw,
                      fmt_c_array, fmt_yara, fmt_yara_string, fmt_blob,
                      sanitize_identifier)

# The backend decides the window title and which wildcard options exist, so
# this module is shared verbatim by the x86 and the .NET plugins.
TITLE = getattr(backend, "TITLE", "SigWriter")
MAX_GRID_BYTES = 16          # byte columns in the grid (x86 max insn = 15)
LARGE_RANGE = 0x10000        # ask before loading ranges bigger than this

COL_ADDR = 0
COL_BYTE0 = 1
COL_TEXT = COL_BYTE0 + MAX_GRID_BYTES

# Export formats: (id, label, file filter)
FMT_IDA = "ida"
FMT_QQ = "qq"
FMT_RAW = "raw"
FMT_C = "c"
FMT_YARA = "yara"
FMT_BLOB = "blob"
FORMATS = [
    (FMT_IDA,  "Patron standalone (IDA: ? )",           "*.txt"),
    (FMT_QQ,   "Patron standalone (x64dbg/CE: ?? )",    "*.txt"),
    (FMT_RAW,  "Patron standalone sin wildcards",       "*.txt"),
    (FMT_C,    "Array C/C++",                           "*.h"),
    (FMT_YARA, "Regla YARA",                            "*.yar"),
    (FMT_BLOB, "Blob binario",                          "*.bin"),
]

COLOR_AUTO = QtGui.QColor(255, 200, 120)      # automatic wildcard
COLOR_MANUAL = QtGui.QColor(200, 160, 255)    # manually wildcarded
COLOR_FORCED = QtGui.QColor(170, 230, 170)    # manually un-wildcarded


class SigWriterForm(ida_kernwin.PluginForm):

    def __init__(self, on_close=None):
        ida_kernwin.PluginForm.__init__(self)
        self._on_close = on_close
        self.opts = backend.WildcardOptions()
        self.sel = None
        self.manual = {}        # byte index -> forced wildcard state (bool)
        self.range = None
        self._updating = False

    # ------------------------------------------------------------------
    # PluginForm callbacks
    # ------------------------------------------------------------------
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self._build_ui()
        if self.range:
            self._reload()

    def OnClose(self, form):
        if self._on_close:
            self._on_close()

    def show(self):
        return self.Show(TITLE, options=ida_kernwin.PluginForm.WOPN_PERSIST)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self):
        root = QtWidgets.QVBoxLayout()

        # --- range -----------------------------------------------------
        grp_range = QtWidgets.QGroupBox("Rango")
        lr = QtWidgets.QHBoxLayout(grp_range)
        self.ed_start = QtWidgets.QLineEdit()
        self.ed_end = QtWidgets.QLineEdit()
        for ed in (self.ed_start, self.ed_end):
            ed.setPlaceholderText("0x...")
            ed.setMaximumWidth(160)
            ed.returnPressed.connect(self._on_range_edited)
        lr.addWidget(QtWidgets.QLabel("Inicio:"))
        lr.addWidget(self.ed_start)
        lr.addWidget(QtWidgets.QLabel("Fin:"))
        lr.addWidget(self.ed_end)
        btn_sel = QtWidgets.QPushButton("Seleccion actual")
        btn_sel.clicked.connect(self._on_use_selection)
        btn_func = QtWidgets.QPushButton("Funcion actual")
        btn_func.clicked.connect(self._on_use_function)
        btn_uniq = QtWidgets.QPushButton("Unico desde el cursor")
        btn_uniq.setToolTip("Agrega instrucciones desde el cursor hasta que "
                            "el patron sea unico en la base de datos")
        btn_uniq.clicked.connect(self._on_auto_unique)
        lr.addWidget(btn_sel)
        lr.addWidget(btn_func)
        lr.addWidget(btn_uniq)
        lr.addStretch(1)
        root.addWidget(grp_range)

        # --- wildcard options ------------------------------------------
        grp_wc = QtWidgets.QGroupBox("Wildcards")
        lw = QtWidgets.QGridLayout(grp_wc)
        self.cb_enabled = QtWidgets.QCheckBox("Permitir wildcards")
        self.cb_enabled.setChecked(self.opts.enabled)
        lw.addWidget(self.cb_enabled, 0, 0, 1, 4)
        self.cb_opts = {}
        for i, item in enumerate(backend.OPTION_ITEMS):
            key, label = item[0], item[1]
            cb = QtWidgets.QCheckBox(label)
            if len(item) > 2:
                cb.setToolTip(item[2])
            cb.setChecked(getattr(self.opts, key))
            cb.toggled.connect(self._on_options_changed)
            self.cb_opts[key] = cb
            lw.addWidget(cb, 1 + i // 3, i % 3)
        self.cb_enabled.toggled.connect(self._on_options_changed)
        btn_clear = QtWidgets.QPushButton("Descartar cambios manuales")
        btn_clear.clicked.connect(self._on_clear_manual)
        lw.addWidget(btn_clear, 0, 3)
        root.addWidget(grp_wc)

        # --- byte grid -------------------------------------------------
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(COL_TEXT + 1)
        headers = ["Direccion"] + ["%X" % i for i in range(MAX_GRID_BYTES)] + ["Instruccion"]
        self.table.setHorizontalHeaderLabels(headers)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.table.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont))
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(COL_ADDR, QtWidgets.QHeaderView.ResizeToContents)
        for c in range(COL_BYTE0, COL_TEXT):
            hdr.setSectionResizeMode(c, QtWidgets.QHeaderView.Fixed)
            self.table.setColumnWidth(c, 28)
        hdr.setSectionResizeMode(COL_TEXT, QtWidgets.QHeaderView.Stretch)
        self.table.verticalHeader().setDefaultSectionSize(20)
        self.table.cellClicked.connect(self._on_cell_clicked)
        self.table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        self.table.setToolTip("Click en un byte: alternar wildcard.  "
                              "Doble click en la direccion: saltar a ella.")

        legend = QtWidgets.QLabel(
            "<span style='background:%s'>&nbsp;auto&nbsp;</span> "
            "<span style='background:%s'>&nbsp;manual&nbsp;</span> "
            "<span style='background:%s'>&nbsp;forzado fijo&nbsp;</span> "
            "&mdash; click en un byte para alternar wildcard"
            % (COLOR_AUTO.name(), COLOR_MANUAL.name(), COLOR_FORCED.name()))

        # --- output ----------------------------------------------------
        grp_out = QtWidgets.QGroupBox("Exportar")
        lo = QtWidgets.QVBoxLayout(grp_out)
        top = QtWidgets.QHBoxLayout()
        self.cmb_format = QtWidgets.QComboBox()
        for fid, label, _ in FORMATS:
            self.cmb_format.addItem(label, fid)
        self.cmb_format.currentIndexChanged.connect(self._refresh_output)
        top.addWidget(QtWidgets.QLabel("Formato:"))
        top.addWidget(self.cmb_format)
        top.addWidget(QtWidgets.QLabel("Nombre:"))
        self.ed_name = QtWidgets.QLineEdit("pattern")
        self.ed_name.setMaximumWidth(200)
        self.ed_name.setToolTip("Nombre de la variable C/C++ o de la regla YARA")
        self.ed_name.textChanged.connect(self._refresh_output)
        top.addWidget(self.ed_name)
        self.cb_yara_only = QtWidgets.QCheckBox("Solo patron")
        self.cb_yara_only.setToolTip("Generar solo el hex string { ... } en lugar "
                                     "de la regla YARA completa")
        self.cb_yara_only.toggled.connect(self._refresh_output)
        top.addWidget(self.cb_yara_only)
        top.addStretch(1)
        lo.addLayout(top)

        self.txt_out = QtWidgets.QPlainTextEdit()
        self.txt_out.setReadOnly(True)
        self.txt_out.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont))
        self.txt_out.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
        lo.addWidget(self.txt_out)

        btns = QtWidgets.QHBoxLayout()
        b_copy = QtWidgets.QPushButton("Copiar")
        b_copy.clicked.connect(self._on_copy)
        b_save = QtWidgets.QPushButton("Guardar...")
        b_save.clicked.connect(self._on_save)
        b_print = QtWidgets.QPushButton("Imprimir en Output")
        b_print.clicked.connect(self._on_print)
        b_search = QtWidgets.QPushButton("Buscar coincidencias")
        b_search.clicked.connect(self._on_search)
        for b in (b_copy, b_save, b_print, b_search):
            btns.addWidget(b)
        btns.addStretch(1)
        lo.addLayout(btns)

        self.lbl_status = QtWidgets.QLabel("Selecciona un rango en el desensamblado.")

        grid_box = QtWidgets.QWidget()
        gl = QtWidgets.QVBoxLayout(grid_box)
        gl.setContentsMargins(0, 0, 0, 0)
        gl.addWidget(self.table)
        gl.addWidget(legend)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.addWidget(grid_box)
        splitter.addWidget(grp_out)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)
        root.addWidget(self.lbl_status)

        self.parent.setLayout(root)
        self._sync_option_widgets()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def set_range(self, start, end):
        if end - start > LARGE_RANGE:
            if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO,
                                  "El rango tiene %d bytes. Continuar?" % (end - start)) != ida_kernwin.ASKBTN_YES:
                return
        self.range = (start, end)
        self.manual = {}
        if hasattr(self, "table"):
            self._reload()

    # ------------------------------------------------------------------
    # Model
    # ------------------------------------------------------------------
    def _effective_wild(self, i):
        if not self.opts.enabled:
            return False
        if i in self.manual:
            return self.manual[i]
        return self.sel.auto_wild[i]

    def current_pattern(self):
        if not self.sel or len(self.sel) == 0:
            return None
        wild = [self._effective_wild(i) for i in range(len(self.sel))]
        return Pattern(self.sel.values, wild, self.sel.start)

    def _reload(self):
        if not self.range:
            return
        start, end = self.range
        self._updating = True
        self.ed_start.setText("0x%X" % start)
        self.ed_end.setText("0x%X" % end)
        self._updating = False
        self.sel = backend.analyze_range(start, end, self.opts)
        self._fill_table()
        self._refresh_output()

    def _fill_table(self):
        t = self.table
        t.setUpdatesEnabled(False)
        t.setRowCount(0)
        t.setRowCount(len(self.sel.rows))
        for r, row in enumerate(self.sel.rows):
            it = QtWidgets.QTableWidgetItem("%X" % row.ea)
            it.setData(QtCore.Qt.UserRole, row.ea)
            t.setItem(r, COL_ADDR, it)
            for j in range(MAX_GRID_BYTES):
                if j < row.size and j < MAX_GRID_BYTES:
                    cell = QtWidgets.QTableWidgetItem()
                    cell.setTextAlignment(QtCore.Qt.AlignCenter)
                    cell.setData(QtCore.Qt.UserRole, row.offset + j)
                    t.setItem(r, COL_BYTE0 + j, cell)
            text = row.text
            if row.size > MAX_GRID_BYTES:
                text = "(%d bytes, solo se muestran %d) %s" % (row.size, MAX_GRID_BYTES, text)
            t.setItem(r, COL_TEXT, QtWidgets.QTableWidgetItem(text))
        self._paint_bytes()
        t.setUpdatesEnabled(True)

    def _paint_bytes(self):
        t = self.table
        for r in range(t.rowCount()):
            for j in range(MAX_GRID_BYTES):
                cell = t.item(r, COL_BYTE0 + j)
                if cell is None:
                    continue
                i = cell.data(QtCore.Qt.UserRole)
                self._paint_cell(cell, i)

    def _paint_cell(self, cell, i):
        wild = self._effective_wild(i)
        cell.setText("??" if wild else "%02X" % self.sel.values[i])
        if not self.opts.enabled:
            cell.setData(QtCore.Qt.BackgroundRole, None)
        elif i in self.manual:
            cell.setBackground(COLOR_MANUAL if wild else COLOR_FORCED)
        elif wild:
            cell.setBackground(COLOR_AUTO)
        else:
            cell.setData(QtCore.Qt.BackgroundRole, None)
        if wild or i in self.manual:
            cell.setForeground(QtGui.QColor(0, 0, 0))
        else:
            cell.setData(QtCore.Qt.ForegroundRole, None)

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    def _format_id(self):
        return self.cmb_format.currentData()

    def _render(self):
        """Return (text_preview, blob_tuple_or_None)."""
        p = self.current_pattern()
        if p is None:
            return "", None
        use_wc = self.opts.enabled
        fid = self._format_id()
        name = sanitize_identifier(self.ed_name.text(), "pattern")
        if fid == FMT_IDA:
            return fmt_ida(p, use_wc), None
        if fid == FMT_QQ:
            return fmt_double_qmark(p, use_wc), None
        if fid == FMT_RAW:
            return fmt_raw(p), None
        if fid == FMT_C:
            return fmt_c_array(p, name, use_wc), None
        if fid == FMT_YARA and self.cb_yara_only.isChecked():
            try:
                return fmt_yara_string(p, use_wc), None
            except ValueError as e:
                return "// Error: %s" % e, None
        if fid == FMT_YARA:
            meta = {"generator": "IDA " + TITLE}
            try:
                import ida_nalt
                root = ida_nalt.get_root_filename()
                if root:
                    meta["sample"] = root
                md5 = ida_nalt.retrieve_input_file_md5()
                if md5:
                    meta["md5"] = md5.hex()
            except Exception:
                pass
            try:
                return fmt_yara(p, name, use_wc, meta), None
            except ValueError as e:
                return "// Error: %s" % e, None
        if fid == FMT_BLOB:
            data, mask = fmt_blob(p, use_wc)
            lines = ["Blob binario: %d bytes" % len(data)]
            if mask is not None:
                lines.append("Contiene %d wildcards: se escriben como 0x00 y se genera "
                             "ademas un archivo .mask (0xFF = fijo, 0x00 = wildcard)."
                             % p.wildcard_count)
            lines.append("")
            lines.append(_hexdump(data, p.start_ea or 0))
            if mask is not None:
                lines.append("")
                lines.append("Mask:")
                lines.append(_hexdump(mask, p.start_ea or 0))
            return "\n".join(lines), (data, mask)
        return "", None

    def _refresh_output(self, *args):
        if not hasattr(self, "txt_out"):
            return
        fid = self._format_id()
        yara_only = fid == FMT_YARA and self.cb_yara_only.isChecked()
        self.cb_yara_only.setVisible(fid == FMT_YARA)
        self.ed_name.setEnabled(fid == FMT_C or (fid == FMT_YARA and not yara_only))
        text, _ = self._render()
        self.txt_out.setPlainText(text)
        p = self.current_pattern()
        if p is None:
            self.lbl_status.setText("Selecciona un rango en el desensamblado.")
        else:
            self.lbl_status.setText("0x%X - 0x%X  |  %d bytes  |  %d wildcards"
                                    % (self.sel.start, self.sel.end, len(p), p.wildcard_count))

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------
    def _sync_option_widgets(self):
        enabled = self.cb_enabled.isChecked()
        for key, cb in self.cb_opts.items():
            cb.setEnabled(enabled)
        # backend.OPTION_ENABLED_IF: {key: f(checked) -> bool}, where checked
        # maps every option key to its checkbox state.
        checked = {k: cb.isChecked() for k, cb in self.cb_opts.items()}
        for key, cond in getattr(backend, "OPTION_ENABLED_IF", {}).items():
            self.cb_opts[key].setEnabled(enabled and cond(checked))

    def _on_options_changed(self, *args):
        self.opts.enabled = self.cb_enabled.isChecked()
        for key, cb in self.cb_opts.items():
            setattr(self.opts, key, cb.isChecked())
        self._sync_option_widgets()
        if self.range:
            # keep manual toggles: indices remain valid for the same range
            self.sel = backend.analyze_range(self.range[0], self.range[1], self.opts)
            self._paint_bytes()
            self._refresh_output()

    def _on_clear_manual(self):
        self.manual = {}
        if self.sel:
            self._paint_bytes()
            self._refresh_output()

    def _on_cell_clicked(self, r, c):
        if not (COL_BYTE0 <= c < COL_TEXT) or not self.sel:
            return
        cell = self.table.item(r, c)
        if cell is None:
            return
        if not self.opts.enabled:
            self.lbl_status.setText("Activa 'Permitir wildcards' para editar bytes.")
            return
        i = cell.data(QtCore.Qt.UserRole)
        new = not self._effective_wild(i)
        if new == self.sel.auto_wild[i]:
            self.manual.pop(i, None)
        else:
            self.manual[i] = new
        self._paint_cell(cell, i)
        self._refresh_output()

    def _on_cell_double_clicked(self, r, c):
        it = self.table.item(r, COL_ADDR)
        if it is not None:
            ida_kernwin.jumpto(it.data(QtCore.Qt.UserRole))

    def _on_range_edited(self):
        if self._updating:
            return
        try:
            start = int(self.ed_start.text().strip(), 0)
            end = int(self.ed_end.text().strip(), 0)
        except ValueError:
            ida_kernwin.warning("Direcciones invalidas (usa formato 0x...).")
            return
        if end <= start:
            ida_kernwin.warning("El fin debe ser mayor que el inicio.")
            return
        self.set_range(start, end)

    def _on_use_selection(self):
        rng = backend.get_user_selection(None)
        if rng is None:
            rng = backend.get_current_item_range()
        if rng:
            self.set_range(*rng)

    def _on_use_function(self):
        rng = backend.get_function_range()
        if rng is None:
            ida_kernwin.warning("El cursor no esta dentro de una funcion.")
            return
        self.set_range(*rng)

    def _on_auto_unique(self):
        ea = ida_kernwin.get_screen_ea()
        end, count = backend.auto_unique(ea, self.opts)
        self.set_range(ida_bytes.get_item_head(ea), end)
        if count == 1:
            self.lbl_status.setText(self.lbl_status.text() + "  |  patron UNICO")
        else:
            ida_kernwin.warning("No se encontro un patron unico dentro del limite "
                                "(coincidencias: %s)." % ("2+" if count > 1 else count))

    def _on_copy(self):
        text, blob = self._render()
        if blob is not None:
            # For the binary blob, copy the bytes as a plain hex string.
            text = blob[0].hex().upper()
        QtWidgets.QApplication.clipboard().setText(text)
        self.lbl_status.setText("Copiado al portapapeles.")

    def _on_print(self):
        text, _ = self._render()
        print(text)

    def _on_save(self):
        text, blob = self._render()
        if not text:
            return
        fid = self._format_id()
        ext = [f for f in FORMATS if f[0] == fid][0][2]
        if fid == FMT_YARA and self.cb_yara_only.isChecked():
            ext = "*.txt"
        path = ida_kernwin.ask_file(1, ext, "Guardar patron")
        if not path:
            return
        try:
            if blob is not None:
                data, mask = blob
                with open(path, "wb") as f:
                    f.write(data)
                if mask is not None:
                    with open(os.path.splitext(path)[0] + ".mask", "wb") as f:
                        f.write(mask)
            else:
                with open(path, "w") as f:
                    f.write(text if text.endswith("\n") else text + "\n")
        except (IOError, OSError) as e:
            ida_kernwin.warning("No se pudo guardar: %s" % e)
            return
        self.lbl_status.setText("Guardado en %s" % path)

    def _on_search(self):
        p = self.current_pattern()
        if p is None:
            return
        limit = 100
        ida_kernwin.show_wait_box("Buscando coincidencias...")
        try:
            matches = backend.find_matches(p, limit)
        finally:
            ida_kernwin.hide_wait_box()
        n = len(matches)
        desc = "%d%s" % (n, "+" if n >= limit else "")
        print("[SigWriter] %s coincidencia(s) para: %s" % (desc, fmt_ida(p, self.opts.enabled)))
        for ea in matches:
            print("    0x%X" % ea)
        self.lbl_status.setText("%s coincidencia(s)%s" %
                                (desc, " - UNICO" if n == 1 else " (ver Output)"))


def _hexdump(data, base, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join("%02X" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%08X  %-*s  %s" % (base + i, width * 3 - 1, hx, asc))
    return "\n".join(lines)
