"""Permite correr la suite sin instalar el paquete: mete src/ en sys.path.

Con `pip install -e .` este archivo es innecesario pero inocuo.
"""
import sys
from pathlib import Path

SRC = Path(__file__).parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
