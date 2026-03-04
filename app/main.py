"""Entry point — launches the PyQt6 GUI."""
from __future__ import annotations

import logging
import sys

from PyQt6.QtWidgets import QApplication

from app.gui.main_window import MainWindow


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("ReSource Recover")
    app.setOrganizationName("ReSource")

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
