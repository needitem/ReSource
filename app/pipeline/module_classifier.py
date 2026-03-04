"""
Phase C-3 — Module Classifier.

Assigns each function to a logical module using:
  1. Demangled C++ namespace
  2. Export name prefix (net_, crypto_, …)
  3. Import API family (WinHTTP, CryptoAPI, Registry…)
  4. Callgraph community detection (networkx)
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


# Win32 API → module bucket
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

# Export prefix → module name
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


class ModuleClassifier:
    """
    Assigns `artifact.module` for every function.
    Unclassified functions end up in "misc".
    """

    def run(
        self,
        artifacts: list[FunctionArtifact],
        globals_: GlobalArtifact,
    ) -> dict[str, list[FunctionArtifact]]:
        import_map = self._build_import_map(globals_)
        addr_to_art = {a.address: a for a in artifacts}

        # Pass 1: explicit rules
        for art in artifacts:
            art.module = (
                self._by_namespace(art)
                or self._by_export_prefix(art)
                or self._by_import_usage(art, import_map, addr_to_art)
                or None
            )

        # Pass 2: callgraph community for unclassified
        if _HAS_NX:
            self._community_classify(artifacts, addr_to_art)

        # Pass 3: fallback
        for art in artifacts:
            if not art.module:
                art.module = "misc"

        # Build module → functions mapping
        modules: dict[str, list[FunctionArtifact]] = {}
        for art in artifacts:
            modules.setdefault(art.module or "misc", []).append(art)
        return modules

    # ------------------------------------------------------------------

    def _build_import_map(self, globals_: GlobalArtifact) -> dict[str, str]:
        """Map import address → module hint from known API names."""
        result: dict[str, str] = {}
        for imp in globals_.imports:
            name = imp.get("name", "")
            addr = imp.get("address")
            for api, mod in _IMPORT_HINTS.items():
                if api.lower() in name.lower():
                    if addr:
                        result[addr] = mod
        return result

    def _by_namespace(self, art: FunctionArtifact) -> Optional[str]:
        name = art.demangled_name or art.name
        # C++ namespace: e.g. Net::Connect → "net"
        m = re.match(r"^([A-Za-z_]\w*)[:_]{1,2}", name)
        if m:
            return m.group(1).lower()
        return None

    def _by_export_prefix(self, art: FunctionArtifact) -> Optional[str]:
        if not art.is_exported:
            return None
        for pattern, mod in _EXPORT_PREFIX_RE:
            if pattern.match(art.name):
                return mod
        return None

    def _by_import_usage(
        self,
        art: FunctionArtifact,
        import_map: dict[str, str],
        addr_to_art: dict[int, FunctionArtifact],
    ) -> Optional[str]:
        # If any callee is a known import → inherit its module
        for callee_addr in art.callees:
            hint = import_map.get(callee_addr)  # type: ignore[arg-type]
            if hint:
                return hint
        return None

    def _community_classify(
        self,
        artifacts: list[FunctionArtifact],
        addr_to_art: dict[int, FunctionArtifact],
    ) -> None:
        """Use Louvain-style community detection to group unclassified functions."""
        g = nx.DiGraph()
        for art in artifacts:
            g.add_node(art.address)
            for callee in art.callees:
                g.add_edge(art.address, callee)

        # Find communities via weakly connected components as fallback
        # (full Louvain requires networkx-community or cdlib)
        ug = g.to_undirected()
        components = list(nx.connected_components(ug))
        for i, component in enumerate(components):
            if len(component) < 3:
                continue  # too small to bother
            # Check if any member is already classified
            classified = [
                addr_to_art[a].module
                for a in component
                if a in addr_to_art and addr_to_art[a].module
            ]
            if classified:
                dominant = max(set(classified), key=classified.count)
                for addr in component:
                    if addr in addr_to_art and not addr_to_art[addr].module:
                        addr_to_art[addr].module = dominant
            else:
                label = f"cluster_{i}"
                for addr in component:
                    if addr in addr_to_art and not addr_to_art[addr].module:
                        addr_to_art[addr].module = label
