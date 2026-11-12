"""
IDA SigWriter .NET - generates patterns from the selected CIL (.NET IL) code.

Target: IDA Pro 8.2 (IDAPython 3, PyQt5), .NET databases only.
Install: copy this file and the `idasigwriter_net/` directory into
         <IDA>/plugins  (or %APPDATA%/Hex-Rays/IDA Pro/plugins).
         It can live next to the x86 SigWriter: each one only activates on
         its own kind of database.
"""

import os
import sys

import ida_idaapi
import ida_kernwin

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

from idasigwriter_net import __version__
from idasigwriter_net import ida_backend as backend

PLUGIN_NAME = "SigWriter .NET"
PLUGIN_HOTKEY = "Ctrl+Alt+S"
ACTION_NAME = "idasigwriter_net:from_selection"
ACTION_LABEL = "Generar patron .NET (SigWriter)..."


class FromSelectionHandler(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.open(ctx.widget)
        return 1

    def update(self, ctx):
        if ctx.widget_type in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DUMP):
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class PopupHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        if ida_kernwin.get_widget_type(widget) in (ida_kernwin.BWN_DISASM,
                                                   ida_kernwin.BWN_DUMP):
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME, None)


class SigWriterNetPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Genera patrones de bytecode .NET (CIL) a partir de la seleccion"
    help = "Selecciona IL en IDA View y usa el menu contextual o %s" % PLUGIN_HOTKEY
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        self.form = None
        self.hooks = None
        # IDA 9.x has its own version (dotnet/ida93/SigWriterNet). Bail out
        # before importing PyQt5, which on 9.2+ pops up the PyQt5-shim dialog.
        try:
            major = int(ida_kernwin.get_kernel_version().split(".")[0])
        except Exception:
            major = 8
        if major >= 9:
            return ida_idaapi.PLUGIN_SKIP
        if not backend.is_dotnet_db():
            return ida_idaapi.PLUGIN_SKIP   # the x86 SigWriter handles it
        try:
            from PyQt5 import QtWidgets  # noqa: F401
        except ImportError:
            print("[SigWriter .NET] PyQt5 no disponible; plugin desactivado.")
            return ida_idaapi.PLUGIN_SKIP

        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            ACTION_NAME, ACTION_LABEL, FromSelectionHandler(self),
            PLUGIN_HOTKEY, "Generar un patron CIL a partir de la seleccion", -1))
        self.hooks = PopupHooks()
        self.hooks.hook()
        print("[SigWriter .NET] v%s cargado (%s)" % (__version__, PLUGIN_HOTKEY))
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.open(None)

    def term(self):
        if self.hooks is not None:
            self.hooks.unhook()
            self.hooks = None
        ida_kernwin.unregister_action(ACTION_NAME)

    # ------------------------------------------------------------------
    def _forget_form(self):
        self.form = None

    def open(self, widget):
        from idasigwriter_net.gui import SigWriterForm

        rng = backend.get_user_selection(widget)
        if rng is None:
            rng = backend.get_current_item_range()

        if self.form is None:
            self.form = SigWriterForm(on_close=self._forget_form)
            if rng:
                self.form.range = rng
            self.form.show()
        else:
            self.form.show()
            if rng:
                self.form.set_range(*rng)


def PLUGIN_ENTRY():
    return SigWriterNetPlugin()
