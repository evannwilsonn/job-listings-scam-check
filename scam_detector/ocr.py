"""
Read the text out of a screenshot (plan item 23), so a student can check a text message, a WhatsApp chat or a
LinkedIn DM without retyping it.

    image_text(data: bytes) -> str          # raises OcrError with a message a student can read

Uses the Tesseract OCR program (`apt install tesseract-ocr`, plus `tesseract-ocr-spa` / `tesseract-ocr-chi-sim`
for Spanish and Chinese when installed; whatever languages are present are used). The image is read in memory and
never stored. Only PNG, JPEG and WebP are accepted, at most 5 MB and 40 megapixels, so a crafted image can't tie up
the server, and Tesseract gets 30 seconds at most.
"""

from __future__ import annotations

import io
import shutil
import subprocess
from functools import lru_cache

MAX_BYTES = 5 * 1024 * 1024
MAX_PIXELS = 40_000_000
TIMEOUT = 30
LANGS = ("eng", "spa", "chi_sim")


class OcrError(Exception):
    """Why the image couldn't be read, in words a student can act on."""


class OcrUnavailable(OcrError):
    """Tesseract isn't installed on this server."""


def image_kind(data: bytes) -> str:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return ""


@lru_cache(maxsize=1)
def _langs() -> str:
    exe = shutil.which("tesseract")
    if not exe:
        return ""
    try:
        out = subprocess.run([exe, "--list-langs"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    have = {line.strip() for line in out.splitlines()}
    return "+".join(l for l in LANGS if l in have) or "eng"


def _prepare(data: bytes) -> bytes:
    """Check the size, then hand Tesseract a grayscale PNG, upscaled when small (phone crops of a few lines)."""
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    try:
        img = Image.open(io.BytesIO(data))
        w, h = img.size
        if w * h > MAX_PIXELS:
            raise OcrError("That image is too large. Crop it to the message and try again.")
        img = img.convert("L")
        if max(w, h) < 1200:
            k = 1200 / max(w, h)
            img = img.resize((int(w * k), int(h * k)))
        out = io.BytesIO()
        img.save(out, format="PNG")
        return out.getvalue()
    except OcrError:
        raise
    except Exception as exc:                     # noqa: BLE001 - truncated, corrupt or decompression-bomb images
        raise OcrError("That image couldn't be opened. Try a PNG or JPEG screenshot.") from exc


def image_text(data: bytes) -> str:
    if not data:
        raise OcrError("No image was sent.")
    if len(data) > MAX_BYTES:
        raise OcrError("That image is over 5 MB. Crop it to the message and try again.")
    if not image_kind(data):
        raise OcrError("Only PNG, JPEG and WebP screenshots can be read.")
    langs = _langs()
    if not langs:
        raise OcrUnavailable("Reading screenshots isn't available right now. Copy and paste the text instead.")
    png = _prepare(data)
    try:
        run = subprocess.run([shutil.which("tesseract"), "stdin", "stdout", "-l", langs, "--psm", "4"],
                             input=png, capture_output=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise OcrError("That image took too long to read. Crop it to the message and try again.") from exc
    text = run.stdout.decode("utf-8", "replace")
    lines = [" ".join(l.split()) for l in text.splitlines()]
    text = "\n".join(l for l in lines if l).strip()
    if len(text) < 8:
        raise OcrError("No readable text was found in that image. Try a sharper screenshot, or paste the text.")
    return text[:20000]
