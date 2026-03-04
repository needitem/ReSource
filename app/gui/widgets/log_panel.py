"""Scrolling log panel widget."""
from __future__ import annotations

from PyQt6.QtWidgets import QTextEdit
from PyQt6.QtGui import QFont, QColor, QTextCursor


class LogPanel(QTextEdit):
    MAX_LINES = 5000

    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 9))
        self.setStyleSheet("background:#1e1e1e; color:#d4d4d4;")

    def append(self, message: str) -> None:  # type: ignore[override]
        # Trim if too long
        if self.document().lineCount() > self.MAX_LINES:
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.select(QTextCursor.SelectionType.LineUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar()

        super().append(message)
        self.moveCursor(QTextCursor.MoveOperation.End)
