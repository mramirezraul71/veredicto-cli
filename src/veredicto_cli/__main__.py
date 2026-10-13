"""Permite `python -m veredicto_cli check ...`."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
