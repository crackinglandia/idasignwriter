"""
IDA SigWriter .NET - generates patterns from the selected CIL (.NET IL) code.

Target: IDA Pro 9.3+ (IDAPython 3, Qt 6 / PySide6), .NET databases only.
Install: copy the whole `SigWriterNet/` directory (the one containing
         ida-plugin.json) into <IDA>/plugins or $IDAUSR/plugins.
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

from sigwriter9_net import __version__
from sigwriter9_net import ida_backend as backend

PLUGIN_NAME = "SigWriter .NET"
PLUGIN_HOTKEY = "Ctrl+Alt+S"
ACTION_NAME = "sigwriter9_net:from_selection"
ACTION_LABEL = "Generar patron .NET (SigWriter)..."

# BWN_DUMP was renamed to BWN_HEXVIEW in IDA 9.x.
SUPPORTED_WIDGETS = (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_HEXVIEW)


class FromSelectionHandler(ida_kernwin.action_handler_t):
    def __init__(self, mod):
        ida_kernwin.action_handler_t.__init__(self)
        self.mod = mod

    def activate(self, ctx):
        self.mod.open(ctx.widget)
        return 1

    def update(self, ctx):
        if ctx.widget_type in SUPPORTED_WIDGETS:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class PopupHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        if ida_kernwin.get_widget_type(widget) in SUPPORTED_WIDGETS:
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME, None)


class SigWriterNetMod(ida_idaapi.plugmod_t):
    """Per-database plugin instance (PLUGIN_MULTI)."""

    def __init__(self):
        ida_idaapi.plugmod_t.__init__(self)
        self.form = None
        ida_kernwin.unregister_action(ACTION_NAME)  # stale from a reload
        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            ACTION_NAME, ACTION_LABEL, FromSelectionHandler(self),
            PLUGIN_HOTKEY, "Generar un patron CIL a partir de la seleccion", -1))
        self.hooks = PopupHooks()
        self.hooks.hook()
        print("[SigWriter .NET] v%s cargado (%s)" % (__version__, PLUGIN_HOTKEY))

    def __del__(self):
        if self.hooks is not None:
            self.hooks.unhook()
            self.hooks = None
        if self.form is not None:
            self.form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            self.form = None
        ida_kernwin.unregister_action(ACTION_NAME)

    def run(self, arg):
        self.open(None)
        return True

    def _forget_form(self):
        self.form = None

    def open(self, widget):
        from sigwriter9_net.gui import SigWriterForm

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


class SigWriterNetPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "Genera patrones de bytecode .NET (CIL) a partir de la seleccion"
    help = "Selecciona IL en IDA View y usa el menu contextual o %s" % PLUGIN_HOTKEY
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        if not backend.is_dotnet_db():
            return ida_idaapi.PLUGIN_SKIP   # the x86 SigWriter handles it
        try:
            import PySide6.QtWidgets  # noqa: F401
        except ImportError:
            print("[SigWriter .NET] PySide6 no disponible; plugin desactivado.")
            return ida_idaapi.PLUGIN_SKIP
        return SigWriterNetMod()


def PLUGIN_ENTRY():
    return SigWriterNetPlugin()
