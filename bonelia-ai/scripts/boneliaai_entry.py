"""PyInstaller entry point for BoneliaAI.exe (Portable Monitor)."""

import multiprocessing
import sys

from bonelia.monitor.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
