"""PyInstaller entry point for BoneliaAI.exe (Portable Monitor)."""

import multiprocessing
import os
import sys

# The double-click build (BoneliaAI.exe) has no console: give libraries a harmless sink.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")

from bonelia.monitor.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
