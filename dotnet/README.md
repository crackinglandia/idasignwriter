# SigWriter .NET

Versión de SigWriter para binarios **.NET**. Genera patrones del bytecode CIL
(MSIL) seleccionado en IDA, con la misma GUI y los mismos formatos de exportación
que el plugin x86: IDA, x64dbg, sin wildcards, C/C++, YARA (regla o solo patrón),
blob binario, búsqueda de coincidencias y "Único desde el cursor".

Es un plugin aparte. Cada plugin se activa solo en su tipo de base de datos
(`ida_idp.ph_get_id() == PLFM_NET`), así que pueden instalarse juntos y comparten
el atajo **Ctrl+Alt+S** sin conflicto.

## Instalación

| IDA | Copiar a `plugins/` |
|---|---|
| 8.2 | `ida82/idasigwriter_net_plugin.py` + `ida82/idasigwriter_net/` |
| 9.3+ | la carpeta `ida93/SigWriterNet/` completa (contiene `ida-plugin.json`) |

Uso: selecciona IL en *IDA View* → click derecho → **Generar patron .NET
(SigWriter)...**, o Ctrl+Alt+S, o *Edit → Plugins → SigWriter .NET*.

## Wildcards automáticos

El decodificador es propio (`cil.py`) y sigue ECMA-335 Partición III. No depende
de los mnemónicos de IDA. Cada byte de operando se clasifica:

| Opción | Operandos | Por defecto |
|---|---|---|
| Tokens de metadatos | `call`, `callvirt`, `newobj`, `ldfld`, `stfld`, `ldsfld`, `box`, `castclass`, `ldtoken`, `calli`, `constrained.`… | ✔ |
| Tokens de strings | `ldstr` (`0x70xxxxxx`) | ✔ |
| Conservar la tabla del token | deja fijo el byte alto del token (`06` MethodDef, `0A` MemberRef, `04` Field, `01` TypeRef, `02` TypeDef, `1B` TypeSpec, `2B` MethodSpec, `70` String) y solo pone wildcard en el RID | ✔ |
| Offsets de saltos | `br`, `brtrue`, `beq`, `leave` (cortos y largos) | ✔ |
| Tabla de switch | destinos de `switch`; el número de casos queda fijo porque determina el largo | ✔ |
| Índices de locals/args | `ldloc.s`, `stloc.s`, `ldarg.s`, `ldloca`, `starg`… | ✘ |
| Constantes | `ldc.i4.s`, `ldc.i4`, `ldc.i8`, `ldc.r4`, `ldc.r8`, flags de `unaligned.`/`no.` | ✘ |

Ejemplo (`call` a un MethodDef, `ldstr`, `br.s`):

```
28 ?? ?? ?? 06    72 ?? ?? ?? 70    2B ??
```

Los opcodes de 2 bytes (`FE xx`: `ceq`, `ldftn`, `initobj`, `constrained.`…)
conservan los dos bytes. Los bytes que IDA no marca como código (cabeceras de
método, datos) se copian tal cual, sin wildcards automáticos. Como en el plugin
x86, cualquier byte se puede alternar a mano con un click.

Con todas las opciones activadas y "Conservar la tabla del token" desactivada,
el resultado equivale al del script original `dotnet_rule_creator.py`: opcode
fijo y todo el operando con wildcard.

## Validación

- Tabla de 219 opcodes generada de `src/coreclr/inc/opcode.def` (dotnet/runtime),
  más `no.` (`FE 19`), que está en ECMA-335 III.2.2 pero CoreCLR marca como no usado.
- Comparado contra el decodificador independiente **dncil** (Mandiant) sobre
  todos los métodos de Newtonsoft.Json 13.0.3: 4 092 métodos y 99 662
  instrucciones, con 0 diferencias en opcode, largo y operandos.
- `tests/il_samples.json` contiene 3 métodos reales de esa assembly (MIT) con
  los valores esperados de dncil, así los tests no necesitan dncil.

```
python3 -m unittest discover -s dotnet/tests
```

## Estructura y archivos compartidos

```
dotnet/
  ida82/idasigwriter_net_plugin.py  entrada IDA 8.2 (PyQt5, PLUGIN_KEEP)
  ida82/idasigwriter_net/
  ida93/SigWriterNet/               IDA 9.3+ (PySide6, PLUGIN_MULTI, ida-plugin.json)
    sigwriter_net_entry.py
    sigwriter9_net/
  tests/
```

Cada paquete es autocontenido, así que algunos archivos son copias.
`tests/test_cil.py` verifica que sigan siendo idénticas:

| Archivo | Copias idénticas |
|---|---|
| `cil.py`, `ida_backend.py` (.NET) | los dos paquetes .NET |
| `gui.py` | la del plugin x86 de la misma versión de IDA |
| `pattern.py` | los cuatro plugins |

Si cambias uno, copia el cambio a las demás copias.
