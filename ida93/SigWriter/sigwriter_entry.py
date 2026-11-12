"""
IDA SigWriter - generates code patterns/signatures from the selected code.

Target: IDA Pro 9.3+ (IDAPython 3, Qt 6 / PySide6).
Install: copy the whole `SigWriter/` directory (the one containing
         ida-plugin.json) into <IDA>/plugins or $IDAUSR/plugins
         (%APPDATA%/Hex-Rays/IDA Pro/plugins on Windows).
"""

import os
import sys

import ida_idaapi
import ida_kernwin

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

from sigwriter9 import __version__
from sigwriter9 import ida_backend as backend

PLUGIN_NAME = "SigWriter"
PLUGIN_HOTKEY = "Ctrl+Alt+S"
ACTION_NAME = "sigwriter9:from_selection"
ACTION_LABEL = "Generar patron (SigWriter)..."

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


class SigWriterMod(ida_idaapi.plugmod_t):
    """Per-database plugin instance (PLUGIN_MULTI)."""

    def __init__(self):
        ida_idaapi.plugmod_t.__init__(self)
        self.form = None
        ida_kernwin.unregister_action(ACTION_NAME)  # stale from a reload
        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            ACTION_NAME, ACTION_LABEL, FromSelectionHandler(self),
            PLUGIN_HOTKEY, "Generar un patron a partir de la seleccion", -1))
        self.hooks = PopupHooks()
        self.hooks.hook()
        print("[SigWriter] v%s cargado (%s)" % (__version__, PLUGIN_HOTKEY))

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
        from sigwriter9.gui import SigWriterForm

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


class SigWriterPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "Genera patrones de codigo a partir de la seleccion"
    help = "Selecciona codigo en IDA View y usa el menu contextual o %s" % PLUGIN_HOTKEY
    wanted_name = PLUGIN_NAME
    # The hotkey is handled by our action (so it works from the popup too).
    wanted_hotkey = ""

    def init(self):
        if backend.is_dotnet_db():
            print("[SigWriter] Base de datos .NET: usa SigWriter .NET (dotnet/).")
            return ida_idaapi.PLUGIN_SKIP
        try:
            import PySide6.QtWidgets  # noqa: F401
        except ImportError:
            print("[SigWriter] PySide6 no disponible; plugin desactivado.")
            return ida_idaapi.PLUGIN_SKIP
        return SigWriterMod()


def PLUGIN_ENTRY():
    return SigWriterPlugin()
