"""Single source of truth for report renderer identity and trusted font assets."""

import hashlib
from pathlib import Path

import reportlab


FONT_DIRECTORY = Path(reportlab.__file__).resolve().parent / "fonts"
FONT_FILES = (FONT_DIRECTORY / "Vera.ttf", FONT_DIRECTORY / "VeraBd.ttf")


def _font_bundle_digest() -> str:
    digest = hashlib.sha256()
    for font_path in FONT_FILES:
        digest.update(font_path.name.encode("utf-8"))
        digest.update(font_path.read_bytes())
    return digest.hexdigest()[:12]


RENDERER_VERSION = (
    f"reportlab-platypus-1.1/reportlab-{reportlab.Version}/fonts-{_font_bundle_digest()}"
)

