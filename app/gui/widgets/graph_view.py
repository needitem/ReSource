"""
Call-graph visualization widget (placeholder).

Full implementation would use PyQtGraph or a custom QPainter renderer.
Currently renders a simple text representation.
"""
from __future__ import annotations

from PyQt6.QtWidgets import QTextEdit
from PyQt6.QtGui import QFont


class GraphView(QTextEdit):
    """Placeholder graph view — shows adjacency text until a proper graph widget is added."""

    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 9))
        self.setPlaceholderText("Call graph will be rendered here…")

    def set_function(self, name: str, callees: list[str], callers: list[str]) -> None:
        lines = [
            f"=== {name} ===",
            "",
            "Callers:",
            *[f"  ← {c}" for c in callers],
            "",
            "Callees:",
            *[f"  → {c}" for c in callees],
        ]
        self.setPlainText("\n".join(lines))
