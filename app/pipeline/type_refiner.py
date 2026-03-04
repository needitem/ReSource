"""
Phase C-2 — Type Refiner.

Scores confidence and annotates /* TODO: inferred */ where types are uncertain.
"""
from __future__ import annotations

from app.models.artifact import FunctionArtifact, GlobalArtifact, ConfidenceLevel


class TypeRefiner:
    """Mutates FunctionArtifact list in-place: scores confidence, refines types."""

    def run(
        self,
        artifacts: list[FunctionArtifact],
        globals_: GlobalArtifact,
    ) -> None:
        export_names = {e.get("name") for e in globals_.exports}
        for art in artifacts:
            self._score(art, export_names)
            self._annotate_inferred(art)

    # ------------------------------------------------------------------

    def _score(self, art: FunctionArtifact, export_names: set) -> None:
        if art.decompile_ok:
            art.add_confidence(30, "decompile_success")
        if art.type_ok:
            art.add_confidence(20, "type_inferred")
        if art.callees:
            art.add_confidence(20, "callgraph_present")
        if art.demangled_name or (art.name and not art.name.startswith("sub_")):
            art.add_confidence(15, "name_known")
        if art.is_exported or art.name in export_names:
            art.add_confidence(5, "is_export")
            art.is_exported = True

    def _annotate_inferred(self, art: FunctionArtifact) -> None:
        if not art.decompiled_code:
            return
        if art.confidence_level != ConfidenceLevel.HIGH:
            # Mark top of decompiled block if types are uncertain
            art.decompiled_code = (
                "/* TODO: inferred — confidence "
                f"{art.confidence_level} ({art.confidence_score}/100) */\n"
                + art.decompiled_code
            )
