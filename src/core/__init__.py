#src/core/__init__.py

from .scan_engine import scan
from .extractors  import extract_text
from .utils       import parse_json      # ➊  add this

__all__ = [
    "scan",
    "extract_text",
    "parse_json",
]

