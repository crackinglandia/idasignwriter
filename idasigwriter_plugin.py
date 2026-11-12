"""
IDA SigWriter - generates code patterns/signatures from the selected code.

Target: IDA Pro 8.2 (IDAPython 3, PyQt5).
Install: copy this file and the `idasigwriter/` directory into
         <IDA>/plugins  (or %APPDATA%/Hex-Rays/IDA Pro/plugins).
"""

import os
import sys

import ida_idaapi
import ida_kernwin

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

from idasigwriter import __version__
from idasigwriter import ida_backend as backend

PLUGIN_NAME = "SigWriter"
PLUGIN_HOTKEY = "Ctrl+Alt+S"
ACTION_NAME = "idasigwriter:from_selection"
ACTION_LABEL = "Generar patron (SigWriter)..."


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
    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) in (ida_kernwin.BWN_DISASM,
                                                   ida_kernwin.BWN_DUMP):
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME, None)


class SigWriterPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Genera patrones de codigo a partir de la seleccion"
    help = "Selecciona codigo en IDA View y usa el menu contextual o %s" % PLUGIN_HOTKEY
    wanted_name = PLUGIN_NAME
    # The hotkey is handled by our action (so it works from the popup too).
    wanted_hotkey = ""

    def init(self):
        self.form = None
        self.hooks = None
        # IDA 9.x has its own version (ida93/SigWriter). Bail out before
        # importing PyQt5, which on 9.2+ would pop up the PyQt5-shim dialog.
        try:
            major = int(ida_kernwin.get_kernel_version().split(".")[0])
        except Exception:
            major = 8
        if major >= 9:
            print("[SigWriter] Esta version es para IDA 8.x; en IDA %s usa ida93/SigWriter."
                  % ida_kernwin.get_kernel_version())
            return ida_idaapi.PLUGIN_SKIP
        if backend.is_dotnet_db():
            print("[SigWriter] Base de datos .NET: usa SigWriter .NET (dotnet/).")
            return ida_idaapi.PLUGIN_SKIP
        try:
            from PyQt5 import QtWidgets  # noqa: F401
        except ImportError:
            print("[SigWriter] PyQt5 no disponible; plugin desactivado.")
            return ida_idaapi.PLUGIN_SKIP

        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            ACTION_NAME, ACTION_LABEL, FromSelectionHandler(self),
            PLUGIN_HOTKEY, "Generar un patron a partir de la seleccion", -1))
        self.hooks = PopupHooks()
        self.hooks.hook()
        print("[SigWriter] v%s cargado (%s)" % (__version__, PLUGIN_HOTKEY))
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
        from idasigwriter.gui import SigWriterForm

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
    return SigWriterPlugin()
