"""
collect_artifacts.py — IDA Python script that runs INSIDE idat64.exe

Launch command:
    idat64.exe -A -c -o<idb_path> -S"collect_artifacts.py" <dll_path>

Optional script args (via -S):
    --output <dir>  or  --output=<dir>

Env vars consumed (best-effort):
    RESOURCE_OUTPUT_DIR   — where to write JSON artifacts
    RESOURCE_JOB_ID       — job id (for logging)

Output layout (all under output dir):
    summary.json
    raw/globals.json
    raw/func_<ADDR>.json   (one per function)

Progress lines are printed to stdout and parsed by IDARunner:
    [RR] PROGRESS <done>/<total> ok=<n> fail=<n>
    [RR] DONE ok=<n> fail=<n>
    [RR] ERROR <message>
"""

import json
import os
import traceback
from pathlib import Path

# ── IDA imports (available because this runs inside idat64) ──────────────────
import idaapi
import ida_funcs
import ida_name
import ida_nalt
import ida_struct
import ida_typeinf
import idautils
import idc

# optional — Hex-Rays decompiler
try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None


# ── helpers ──────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    print(f"[RR] {msg}", flush=True)


def _exit(code: int) -> None:
    """IDA 8.x-safe exit helper."""
    try:
        if hasattr(idc, "qexit"):
            idc.qexit(code)
            return
    except Exception:
        pass

    try:
        import ida_pro

        ida_pro.qexit(code)
        return
    except Exception:
        raise SystemExit(code)


def _resolve_output_dir() -> Path:
    argv = list(getattr(idc, "ARGV", []) or [])
    for i, arg in enumerate(argv[1:], start=1):
        if arg.startswith("--output="):
            return Path(arg.split("=", 1)[1])
        if arg == "--output" and i + 1 < len(argv):
            return Path(argv[i + 1])

    env_output = os.environ.get("RESOURCE_OUTPUT_DIR")
    if env_output:
        return Path(env_output)

    # Fallback for WSL -> Windows idat64 launches where env var propagation can fail.
    return Path.cwd()


def _safe_collect(name: str, collector) -> list:
    try:
        return collector()
    except Exception as e:
        _log(f"ERROR collecting {name}: {e}")
        return []


def _collect_imports() -> list:
    imports = []

    qty_fn = getattr(ida_nalt, "get_import_module_qty", None) or getattr(
        idaapi, "get_import_module_qty", None
    )
    name_fn = getattr(ida_nalt, "get_import_module_name", None) or getattr(
        idaapi, "get_import_module_name", None
    )
    enum_fn = getattr(ida_nalt, "enum_import_names", None) or getattr(
        idaapi, "enum_import_names", None
    )

    if not (qty_fn and name_fn and enum_fn):
        return imports

    for i in range(int(qty_fn())):
        mod_name = name_fn(i) or f"module_{i}"

        def _cb(ea, name, ordinal, *_):
            imports.append(
                {
                    "module": mod_name,
                    "name": name or f"ord_{ordinal}",
                    "address": ea,
                    "ordinal": ordinal,
                }
            )
            return True

        enum_fn(i, _cb)

    return imports


def _collect_exports() -> list:
    exports = []

    get_qty = getattr(idaapi, "get_entry_qty", None)
    get_ord = getattr(idaapi, "get_entry_ordinal", None)
    get_entry = getattr(idaapi, "get_entry", None)
    if not (get_qty and get_ord and get_entry):
        return exports

    for i in range(get_qty()):
        ordinal = get_ord(i)
        ea = get_entry(ordinal)
        name = ida_name.get_ea_name(ea) or f"sub_{ea:X}"
        exports.append({"address": ea, "name": name, "ordinal": ordinal})

    return exports


def _collect_strings(limit: int = 5000) -> list:
    result = []
    for s in idautils.Strings():
        try:
            result.append({"address": s.ea, "length": s.length, "value": str(s)})
        except Exception:
            pass
        if len(result) >= limit:
            break
    return result


def _collect_structs() -> list:
    structs = []

    idx = ida_struct.get_first_struc_idx()
    while idx not in (idc.BADADDR, -1):
        sid = ida_struct.get_struc_id(idx)
        if sid not in (idc.BADADDR, -1):
            name = ida_struct.get_struc_name(sid)
            size = ida_struct.get_struc_size(sid)
            if name:
                structs.append({"name": name, "size": size})
        idx = ida_struct.get_next_struc_idx(idx)

    return structs


def _enable_hexrays() -> bool:
    if ida_hexrays is None:
        return False
    try:
        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False


def _collect_function(ea: int, export_addrs: set[int], hexrays_ready: bool) -> dict:
    func = ida_funcs.get_func(ea)
    name = idc.get_func_name(ea)
    demangled = ida_name.get_ea_name(ea, ida_name.GN_DEMANGLED | ida_name.GN_SHORT)
    size = func.size() if func else 0

    art: dict = {
        "address": ea,
        "name": name,
        "demangled_name": demangled if demangled and demangled != name else None,
        "size": size,
        "is_exported": ea in export_addrs,
        "decompile_ok": False,
        "decompiled_code": None,
        "decompile_error": None,
        "prototype": None,
        "type_ok": False,
        "callees": [],
        "callers": [],
        "stack_vars": [],
        "module": None,
        "confidence_score": 0,
        "confidence_level": "LOW",
        "confidence_reasons": [],
    }

    # Decompile
    if hexrays_ready:
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                art["decompiled_code"] = str(cfunc)
                art["decompile_ok"] = True
                tif = ida_typeinf.tinfo_t()
                if cfunc.get_func_type(tif):
                    art["prototype"] = tif._print()
                    art["type_ok"] = True
        except Exception as e:
            art["decompile_error"] = str(e)
    else:
        art["decompile_error"] = "hexrays_unavailable"

    # Callees (code refs from this function entry)
    for xref in idautils.CodeRefsFrom(ea, True):
        if ida_funcs.get_func(xref):
            art["callees"].append(xref)

    # Callers (code refs to this function)
    for xref in idautils.CodeRefsTo(ea, True):
        art["callers"].append(xref)

    return art


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    output_dir = _resolve_output_dir()
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    _log(f"Output dir: {output_dir}")
    _log(f"ARGV: {list(getattr(idc, 'ARGV', []) or [])}")

    hexrays_ready = _enable_hexrays()
    _log(f"Hex-Rays available: {hexrays_ready}")

    # Auto-analysis must complete before we do anything
    idaapi.auto_wait()
    _log("Auto-analysis complete")

    # ── Globals ──────────────────────────────────────────────────────────────
    globals_data = {
        "imports": _safe_collect("imports", _collect_imports),
        "exports": _safe_collect("exports", _collect_exports),
        "strings": _safe_collect("strings", _collect_strings),
        "structs": _safe_collect("structs", _collect_structs),
    }

    globals_json = json.dumps(globals_data, indent=2, default=int)
    # canonical location used by CacheService
    (raw_dir / "globals.json").write_text(globals_json, encoding="utf-8")
    # keep backward-compatible copy
    (output_dir / "globals.json").write_text(globals_json, encoding="utf-8")

    _log(
        f"Globals: {len(globals_data['imports'])} imports, "
        f"{len(globals_data['exports'])} exports, "
        f"{len(globals_data['strings'])} strings, "
        f"{len(globals_data['structs'])} structs"
    )

    export_addrs = {int(e.get("address", 0)) for e in globals_data["exports"]}

    # ── Functions ─────────────────────────────────────────────────────────────
    funcs = list(idautils.Functions())
    total = len(funcs)
    _log(f"Functions: {total}")

    ok = 0
    fail = 0

    for i, ea in enumerate(funcs):
        try:
            art = _collect_function(ea, export_addrs, hexrays_ready)
            path = raw_dir / f"func_{ea:016X}.json"
            path.write_text(json.dumps(art, indent=2, default=int), encoding="utf-8")
            if art["decompile_ok"]:
                ok += 1
            else:
                fail += 1
        except Exception as e:
            fail += 1
            _log(f"ERROR func 0x{ea:X}: {e}")

        # Progress every 25 functions or at the end
        if (i + 1) % 25 == 0 or i == total - 1:
            print(f"[RR] PROGRESS {i + 1}/{total} ok={ok} fail={fail}", flush=True)

    summary = {"total": total, "decompiled": ok, "failed": fail}
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[RR] DONE ok={ok} fail={fail}", flush=True)

    _exit(0)


try:
    main()
except Exception:
    print(f"[RR] ERROR {traceback.format_exc()}", flush=True)
    _exit(1)
