"""
Phase C-3 module classifier.

Assigns each function to a logical module using:
  1. Compiler/runtime buckets
  2. Known third-party libraries
  3. Engine/framework code
  4. Guessed source path from strings / __FILE__ / logs
  5. App-level heuristics and callgraph propagation
"""
from __future__ import annotations

import re
from typing import Optional

try:
    import networkx as nx

    _HAS_NX = True
except ImportError:
    _HAS_NX = False

from app.models.artifact import FunctionArtifact, GlobalArtifact
from app.pipeline.heuristics import derive_module_path, enrich_artifact_metadata, sanitize_identifier

_IMPORT_HINTS: dict[str, str] = {
    "WinHttpOpen": "net",
    "WinHttpConnect": "net",
    "InternetOpen": "net",
    "HttpSendRequest": "net",
    "CryptEncrypt": "crypto",
    "CryptDecrypt": "crypto",
    "BCryptEncrypt": "crypto",
    "RegOpenKey": "registry",
    "RegSetValue": "registry",
    "CreateFile": "io",
    "WriteFile": "io",
    "ReadFile": "io",
    "CreateThread": "thread",
    "CreateProcess": "process",
}

_EXPORT_PREFIX_RE = [
    (re.compile(r"^net_", re.I), "net"),
    (re.compile(r"^crypto_|^crypt_", re.I), "crypto"),
    (re.compile(r"^io_|^file_", re.I), "io"),
    (re.compile(r"^str_|^string_", re.I), "string"),
    (re.compile(r"^reg_|^registry_", re.I), "registry"),
    (re.compile(r"^mem_|^alloc_", re.I), "memory"),
    (re.compile(r"^log_|^trace_", re.I), "logging"),
    (re.compile(r"^ui_|^wnd_|^dlg_", re.I), "ui"),
]

_STRING_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"http|https|socket|websocket|url", re.I), "net"),
    (re.compile(r"crypt|bcrypt|hash|sha|aes|rsa", re.I), "crypto"),
    (re.compile(r"registry|hkey|reg(open|set|query)", re.I), "registry"),
    (re.compile(r"file|path|directory|read|write", re.I), "io"),
    (re.compile(r"log|trace|warn|error|assert", re.I), "logging"),
    (re.compile(r"window|dialog|button|menu|messagebox", re.I), "ui"),
]

_SYMBOL_PREFIX_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^\?__scrt_", re.I), "runtime/msvc_crt"),
    (re.compile(r"^(?:__)?scrt_", re.I), "runtime/msvc_crt"),
    (re.compile(r"^(?:__)?std_", re.I), "runtime/stl"),
    (re.compile(r"^std_", re.I), "runtime/stl"),
    (re.compile(r"^concurrency", re.I), "runtime/concurrency"),
    (re.compile(r"^unknown_libname_", re.I), "runtime/msvc_crt"),
    (re.compile(r"^(?:j_)?free$|^malloc$|^calloc$|^realloc$", re.I), "runtime/memory"),
    (re.compile(r"^(?:guard|_guard|guard_check|guard_dispatch|guard_xfg)", re.I), "runtime/security"),
    (re.compile(r"^(?:security|_security|gshandler|seh_|raise$|initterm|dllmain|cfltcvt|localeupdate|configure_narrow|initialize_narrow|register_onexit|execute_onexit)", re.I), "runtime/msvc_crt"),
    (re.compile(r"^(?:thread|process)_", re.I), "runtime/threading"),
    (re.compile(r"^net_", re.I), "net"),
    (re.compile(r"^(?:crypto|crypt)_", re.I), "crypto"),
    (re.compile(r"^(?:io|file)_", re.I), "io"),
    (re.compile(r"^(?:reg|registry)_", re.I), "registry"),
    (re.compile(r"^(?:log|trace)_", re.I), "logging"),
    (re.compile(r"^(?:ui|wnd|dlg)_", re.I), "ui"),
]

_NAMESPACE_HINTS = {
    "std": "runtime/stl",
    "concurrency": "runtime/concurrency",
}

_CLASS_ALIAS_HINTS = {
    "_localeupdate": "runtime/stl",
    "directory_iterator": "runtime/stl",
}

_PROPAGATABLE_REASONS = {
    "known_third_party",
    "engine_framework",
    "source_path",
    "namespace_or_class",
    "export_prefix",
    "import_usage",
    "symbol_prefix",
    "bulk_string_init",
    "string_signature",
}
_MAX_CLUSTER_PROPAGATION_SIZE = 64
_GLOBAL_ASSIGN_MARKERS = ("qword_", "dword_", "xmmword_", "word_", "byte_", "unk_")
_RUNTIME_DEMANGLED_MARKERS = ("__acrt_", "__crt_", "_wcrtomb_s_l")
_FONT_TABLE_TAGS = {"cmap", "loca", "head", "glyf", "hhea", "hmtx", "kern", "gpos", "cff", "maxp"}
_FMT_ERROR_MARKERS = (
    "invalid format string",
    "argument not found.",
    "missing '}' in format string.",
    "unmatched '}' in format string.",
    "integral cannot be stored in char",
    "number is too big",
    "invalid type specification.",
    "invalid presentation type for",
    "precision not allowed for this argument type.",
    "format specifier requires numeric argument.",
)
_THIRD_PARTY_IDENTITY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:imgui|imdrawlist|imfontatlas|imfont|imguiio|imguistyle)\b|[/\\]imgui(?:[/\\]|$)", re.I), "third_party/imgui"),
    (re.compile(r"[/\\]minhook(?:[/\\]|$)|\bMH_[A-Za-z0-9_]+\b|\bminhook\b", re.I), "third_party/minhook"),
    (re.compile(r"\bfmt::|\bfmt\b|[/\\]fmt(?:[/\\]|$)", re.I), "third_party/fmt"),
    (re.compile(r"\bspdlog::|\bspdlog_ex\b|\bspdlog\b|[/\\]spdlog(?:[/\\]|$)", re.I), "third_party/spdlog"),
    (re.compile(r"\b(?:deflate|inflate|crc32|adler32|zlibVersion|compress2|uncompress)\w*\b|[/\\]zlib(?:[/\\]|$)", re.I), "third_party/zlib"),
    (re.compile(r"\b(?:SSL|BIO|EVP|X509|ASN1|PEM|OPENSSL)_[A-Za-z0-9_]+\b|libcrypto|libssl|[/\\]openssl(?:[/\\]|$)", re.I), "third_party/openssl"),
    (re.compile(r"\bgoogle::protobuf\b|\bprotobuf::|\bwireformatlite\b|\bmessagelite\b|[/\\]protobuf(?:[/\\]|$)", re.I), "third_party/protobuf"),
    (re.compile(r"\bsqlite3_[A-Za-z0-9_]+\b|sqlite format 3|[/\\]sqlite(?:[/\\]|$)", re.I), "third_party/sqlite"),
]
_ENGINE_IDENTITY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:uobject|uclass|ustruct|aactor|apawn|uhud|ugameplaystatics|fname|fstring)\b|\bprocessevent\b|[/\\]unreal(?:[/\\]|$)", re.I), "engine/unreal"),
    (re.compile(r"\bil2cpp_[A-Za-z0-9_]+\b|\bunityplayer\b|\biunityinterfaces\b|\bmonobehaviour\b|\bunityengine\b|[/\\]unity(?:[/\\]|$)", re.I), "engine/unity"),
    (re.compile(r"\b(?:d3d11|d3d12|dxgi|idxgiswapchain|id3d11device|id3d11devicecontext|d3dcompiler|d3dcompile)\b|\bsv_position\b|\btexture2d\b|\bsampler0\b", re.I), "engine/directx"),
]
_THIRD_PARTY_STRING_MARKERS: dict[str, tuple[str, ...]] = {
    "third_party/imgui": ("dear imgui", "imgui_impl_", "imdrawlist", "imfontatlas", "imgui context"),
    "third_party/minhook": ("mh_error_", "unsupported function", "already created", "not initialized", "memory protect", "trampoline"),
    "third_party/fmt": _FMT_ERROR_MARKERS,
    "third_party/spdlog": ("spdlog", "%^%l%$", "rotating file", "daily_logger", "async logger", "spdlog_ex"),
    "third_party/zlib": ("need dictionary", "stream end", "incorrect data check", "invalid distance code", "invalid stored block lengths"),
    "third_party/openssl": ("openssl", "ssl routines", "tlsv1.3", "certificate verify failed", "x509"),
    "third_party/protobuf": ("protocol buffer", ".proto", "google/protobuf", "wireformatlite"),
    "third_party/sqlite": ("sqlite format 3", "no such table", "database is locked", "unable to open database file"),
}
_ENGINE_STRING_MARKERS: dict[str, tuple[str, ...]] = {
    "engine/unreal": ("uobject", "processevent", "gameplaystatics", "blueprint", "worldcontextobject", "fname", "fstring"),
    "engine/unity": ("unityplayer", "il2cpp_", "unityengine", "gameobject", "monobehaviour", "transform"),
    "engine/directx": ("d3d11", "d3d12", "dxgi", "idxgiswapchain", "id3d11device", "id3d11devicecontext", "sv_position", "texture2d", "sampler0", "rendertargetview"),
}


class ModuleClassifier:
    """Assigns ``artifact.module`` for every function."""

    def run(
        self,
        artifacts: list[FunctionArtifact],
        globals_: GlobalArtifact,
    ) -> dict[str, list[FunctionArtifact]]:
        import_map = self._build_import_map(globals_)
        addr_to_art = {a.address: a for a in artifacts}

        for art in artifacts:
            enrich_artifact_metadata(art)
            art.module, art.module_reason = self._classify(art, import_map)

        self._local_neighbor_classify(artifacts, addr_to_art)

        if _HAS_NX:
            self._community_classify(artifacts, addr_to_art)

        for art in artifacts:
            if not art.module:
                art.module = "misc"
                art.module_reason = art.module_reason or "fallback"

        modules: dict[str, list[FunctionArtifact]] = {}
        for art in artifacts:
            modules.setdefault(art.module or "misc", []).append(art)
        return modules

    def _classify(
        self,
        art: FunctionArtifact,
        import_map: dict[int, str],
    ) -> tuple[Optional[str], Optional[str]]:
        third_party_module = self._by_known_third_party(art)
        if third_party_module:
            return third_party_module, "known_third_party"

        engine_module = self._by_engine_framework(art)
        if engine_module:
            return engine_module, "engine_framework"

        source_module = self._by_source_path(art)
        if source_module:
            return source_module, "source_path"

        namespace_module = self._by_namespace(art)
        if namespace_module:
            return namespace_module, "namespace_or_class"

        symbol_module = self._by_symbol_prefix(art)
        if symbol_module:
            return symbol_module, "symbol_prefix"

        export_module = self._by_export_prefix(art)
        if export_module:
            return export_module, "export_prefix"

        import_module = self._by_import_usage(art, import_map)
        if import_module:
            return import_module, "import_usage"

        runtime_demangled_module = self._by_runtime_demangled_name(art)
        if runtime_demangled_module:
            return runtime_demangled_module, "demangled_runtime"

        data_module = self._by_bulk_string_init(art)
        if data_module:
            return data_module, "bulk_string_init"

        signature_module = self._by_string_signatures(art)
        if signature_module:
            return signature_module, "string_signature"

        string_module = self._by_strings(art)
        if string_module:
            return string_module, "string_hint"

        return None, None

    def _build_import_map(self, globals_: GlobalArtifact) -> dict[int, str]:
        result: dict[int, str] = {}
        for imp in globals_.imports:
            name = imp.get("name", "")
            addr = imp.get("address")
            if not isinstance(addr, int):
                continue
            for api, module in _IMPORT_HINTS.items():
                if api.lower() in name.lower():
                    result[addr] = module
                    break
        return result

    def _by_source_path(self, art: FunctionArtifact) -> Optional[str]:
        if not art.source_candidates:
            return None
        return self._normalize_module(derive_module_path(art.source_candidates[0]))

    def _by_known_third_party(self, art: FunctionArtifact) -> Optional[str]:
        identity_text = self._identity_text(art)
        string_text = self._string_text(art)

        for pattern, module in _THIRD_PARTY_IDENTITY_PATTERNS:
            if pattern.search(identity_text):
                return module

        for module, markers in _THIRD_PARTY_STRING_MARKERS.items():
            min_hits = 1 if module in {"third_party/imgui", "third_party/fmt", "third_party/spdlog"} else 2
            if self._marker_hits(string_text, markers) >= min_hits:
                return module
        return None

    def _by_engine_framework(self, art: FunctionArtifact) -> Optional[str]:
        identity_text = self._identity_text(art)
        string_text = self._string_text(art)

        for pattern, module in _ENGINE_IDENTITY_PATTERNS:
            if pattern.search(identity_text):
                return module

        for module, markers in _ENGINE_STRING_MARKERS.items():
            if self._marker_hits(string_text, markers) >= 2:
                return module
        return None

    def _by_namespace(self, art: FunctionArtifact) -> Optional[str]:
        display_name = art.demangled_name or art.display_name
        match = re.search(r"([A-Za-z_]\w*)::", display_name)
        if match:
            namespace = match.group(1).strip()
            lowered = namespace.lower()
            mapped = _NAMESPACE_HINTS.get(lowered) or _CLASS_ALIAS_HINTS.get(lowered) or lowered
            return self._normalize_module(mapped)
        if art.class_hint:
            lowered = art.class_hint.lower()
            mapped = _NAMESPACE_HINTS.get(lowered) or _CLASS_ALIAS_HINTS.get(lowered) or lowered
            return self._normalize_module(mapped)
        return None

    def _by_symbol_prefix(self, art: FunctionArtifact) -> Optional[str]:
        candidate = art.guessed_name or art.name
        for pattern, module in _SYMBOL_PREFIX_HINTS:
            if pattern.match(candidate):
                return self._normalize_module(module)
        return None

    def _by_export_prefix(self, art: FunctionArtifact) -> Optional[str]:
        if not art.is_exported:
            return None
        for pattern, module in _EXPORT_PREFIX_RE:
            if pattern.match(art.name):
                return self._normalize_module(module)
        return None

    def _by_import_usage(self, art: FunctionArtifact, import_map: dict[int, str]) -> Optional[str]:
        for callee_addr in art.callees:
            hint = import_map.get(callee_addr)
            if hint:
                return self._normalize_module(hint)
        return None

    def _by_runtime_demangled_name(self, art: FunctionArtifact) -> Optional[str]:
        demangled = art.demangled_name or ""
        if any(marker in demangled for marker in _RUNTIME_DEMANGLED_MARKERS):
            return "runtime/msvc_crt"
        return None

    def _by_strings(self, art: FunctionArtifact) -> Optional[str]:
        for text in art.string_refs:
            for pattern, module in _STRING_HINTS:
                if pattern.search(text):
                    return self._normalize_module(module)
        return None

    def _by_bulk_string_init(self, art: FunctionArtifact) -> Optional[str]:
        code = art.decompiled_code or ""
        if not code:
            return None

        string_count = len(art.string_refs)
        global_assign_hits = sum(code.count(marker) for marker in _GLOBAL_ASSIGN_MARKERS)
        has_exit_registration = "atexit(" in code or "onexit" in code

        if string_count >= 50:
            return "data/init_tables"
        if string_count >= 12 and (global_assign_hits >= 12 or has_exit_registration):
            return "data/init_tables"
        if art.name.startswith("_cfltcvt_init") and string_count >= 8:
            return "data/init_tables"
        return None

    def _by_string_signatures(self, art: FunctionArtifact) -> Optional[str]:
        strings = art.string_refs
        if not strings:
            return None

        if sum(1 for s in strings if "|" in s) >= 3:
            return "data/catalog"

        lowered = [s.lower() for s in strings]
        lower_set = set(lowered)
        joined = " ".join(lowered)

        if self._looks_ui_asset_blob(strings):
            return "ui/assets"

        if any("imgui" in s for s in lowered):
            return "third_party/imgui"
        if any("dx11" in s and "rendertargetview" in s for s in lowered):
            return "engine/directx"
        if any("sv_position" in s or "texture2d" in s or "sampler0" in s for s in lowered):
            return "engine/directx"
        if self._looks_font_signature(strings):
            return "ui/font"
        if any("##" in s for s in strings):
            return "ui/debug"
        if any("[%s]" in s for s in strings) or any("refscale=" in s for s in lowered):
            return "ui/debug"
        if any("m_rendertargetview" in s or "dx11 draw" in s for s in lowered):
            return "engine/directx"
        if sum(1 for marker in ("pos=%i,%i", "size=%i,%i", "collapsed=%d", "ischild=%d") if marker in joined) >= 2:
            return "ui/debug"
        if sum(1 for s in strings if s.startswith("#")) >= 2:
            return "ui/debug"
        if any(marker in joined for marker in ("[%05d]", "%.0fpx")):
            return "ui/debug"

        if {"player", "exploit", "database", "teleporter", "appearance"} & lower_set:
            return "ui/menu"

        if any(
            marker in joined
            for marker in (
                "vector too long",
                "unordered_map/set too long",
                "invalid stoi argument",
                "stoi argument out of range",
                "invalid stof argument",
                "stof argument out of range",
            )
        ):
            return "runtime/stl"

        if any(
            marker in joined
            for marker in _FMT_ERROR_MARKERS
        ):
            return "third_party/fmt"
        if any(marker in joined for marker in ("nan(ind)", "nan(snan)", "0123456789abcdefghijklmnopqrstuvwxyz0b")):
            return "runtime/format"
        if {"0b", "0x", "0"} <= lower_set:
            return "runtime/format"

        if any(
            marker in joined
            for marker in (
                "palshootercomponent",
                "palweaponbase",
                "paldynamicweaponitemdatabase",
                "getremainbulletcount",
            )
        ):
            return "gameplay/weapon"

        if any(
            marker in joined
            for marker in (
                "skinnedmeshcomponent",
                "getbonename",
                "pelvis",
                "hair_01",
            )
        ):
            return "gameplay/character"

        if any(
            marker in joined
            for marker in (
                "palplayercontroller",
                "palcharacterparametercomponent",
                "getplayerviewpoint",
                "k2_getactorlocation",
                "requestchangecharactermakeinfo_toserver",
                "projectworldlocationtoscreen",
                "islocalplayercontroller",
                "palplayerstate",
                "palplayerinventorydata",
                "requestmove_toserver",
                "palnetworkitemcomponent",
                "getlocalinventorydata",
            )
        ):
            return "gameplay/player"
        if any(
            marker in joined
            for marker in (
                "palindividualcharacterhandle",
                "palstatuscomponent",
            )
        ):
            return "gameplay/character"
        if "ontriggerinteract" in joined and any(
            marker in joined
            for marker in (
                "pallevelobject",
                "unlockablefasttravelpoint",
                "obtainable",
                "relic",
            )
        ):
            return "gameplay/world"
        if "requestpickup" in joined and "palmapobjectpickableitemmodelbase" in joined:
            return "gameplay/world"
        if "paldatabasecharacterparameter" in joined and "getlocalizedcharactername" in joined:
            return "data/catalog"

        identifier_like = [s for s in strings if self._looks_catalog_identifier(s)]
        if len(identifier_like) >= 4 and not any(
            token in joined
            for token in ("component", "controller", "get", "request", "projectworldlocationtoscreen")
        ):
            return "data/catalog"

        return None

    @staticmethod
    def _looks_catalog_identifier(value: str) -> bool:
        if not value or "|" in value or " " in value or "." in value or "/" in value:
            return False
        if len(value) < 4 or len(value) > 48:
            return False
        if not any(ch.isalpha() for ch in value):
            return False
        return "_" in value or any(ch.isupper() for ch in value[1:]) or any(ch.isdigit() for ch in value)

    @staticmethod
    def _looks_ui_asset_blob(strings: list[str]) -> bool:
        if len(strings) < 2:
            return False
        long_strings = [s for s in strings if len(s) >= 64]
        if not long_strings:
            return False
        joined = " ".join(long_strings)
        return "xxxxxxx" in joined.lower() and "..-" in joined

    @staticmethod
    def _looks_font_signature(strings: list[str]) -> bool:
        lowered = {s.strip().lower() for s in strings}
        if len(_FONT_TABLE_TAGS & lowered) >= 4:
            return True
        return "\\font\\" in " ".join(lowered) and "create_directories" in lowered

    @staticmethod
    def _identity_text(art: FunctionArtifact) -> str:
        return "\n".join(
            part.lower()
            for part in [
                art.name,
                art.demangled_name or "",
                art.class_hint or "",
                *art.source_candidates,
            ]
            if part
        )

    @staticmethod
    def _string_text(art: FunctionArtifact) -> str:
        return "\n".join(text.lower() for text in art.string_refs if text)

    @staticmethod
    def _marker_hits(haystack: str, markers: tuple[str, ...]) -> int:
        return sum(1 for marker in markers if marker in haystack)

    def _community_classify(
        self,
        artifacts: list[FunctionArtifact],
        addr_to_art: dict[int, FunctionArtifact],
    ) -> None:
        g = nx.DiGraph()
        for art in artifacts:
            g.add_node(art.address)
            for callee in art.callees:
                g.add_edge(art.address, callee)

        components = list(nx.connected_components(g.to_undirected()))
        for i, component in enumerate(components):
            if len(component) < 3:
                continue

            if len(component) > _MAX_CLUSTER_PROPAGATION_SIZE:
                continue

            classified = [
                (addr_to_art[addr].module, addr_to_art[addr].module_reason)
                for addr in component
                if (
                    addr in addr_to_art
                    and addr_to_art[addr].module
                    and addr_to_art[addr].module_reason in _PROPAGATABLE_REASONS
                )
            ]
            if classified:
                module_names = [module for module, _ in classified]
                dominant = max(set(module_names), key=module_names.count)
                dominant_count = module_names.count(dominant)
                if dominant.startswith("runtime/"):
                    continue
                if dominant_count < 2 and len(component) > 8:
                    continue
                for addr in component:
                    if addr in addr_to_art and not addr_to_art[addr].module:
                        addr_to_art[addr].module = dominant
                        addr_to_art[addr].module_reason = "callgraph_cluster"
            else:
                label = f"cluster_{i}"
                for addr in component:
                    if addr in addr_to_art and not addr_to_art[addr].module:
                        addr_to_art[addr].module = label
                        addr_to_art[addr].module_reason = "callgraph_cluster"

    def _local_neighbor_classify(
        self,
        artifacts: list[FunctionArtifact],
        addr_to_art: dict[int, FunctionArtifact],
    ) -> None:
        for art in artifacts:
            if art.module:
                continue

            votes: dict[str, int] = {}
            for ea in set(art.callees + art.callers):
                other = addr_to_art.get(ea)
                if not other or not other.module or other.module.startswith("runtime/"):
                    continue
                if other.module_reason not in _PROPAGATABLE_REASONS:
                    continue
                votes[other.module] = votes.get(other.module, 0) + 1

            if not votes:
                continue

            ranked = sorted(votes.items(), key=lambda item: item[1], reverse=True)
            top_module, top_count = ranked[0]
            second_count = ranked[1][1] if len(ranked) > 1 else 0
            if top_count >= 2 and top_count > second_count:
                art.module = top_module
                art.module_reason = "local_neighbors"

    def _normalize_module(self, module: str) -> str:
        parts = [
            sanitize_identifier(part).lower()
            for part in module.replace("\\", "/").split("/")
            if part
        ]
        if any(len(part) > 40 for part in parts):
            return "misc"
        return "/".join(parts) or "misc"
