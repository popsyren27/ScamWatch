"""
visual.py — Visual matching of screenshots (notes).

Uses a dHash to compare screenshots against `brand_refs/`. Good for spotting
imitation of login pages. Library is empty by default — drop in brand PNGs.

TODO:
- Consider adding image downscaling tweaks if false positives crop up.
- Add unit tests for dhash edge-cases.
- Warn if VISUAL_REFERENCE_DIR is empty so operators know the lib is missing.
"""

# pure pixel comparison, no ML — a hit can be coincidental, don't over-trust it

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from config import VISUAL_HASH_THRESHOLD, VISUAL_REFERENCE_DIR
from models import VisualMatch
from modules.logging_setup import get_logger

log = get_logger("recon.visual")

_HASH_SIZE = 8  # 8x8 grid = 64-bit hash. touching this number is a bad time
_HASH_BITS = _HASH_SIZE * _HASH_SIZE  # 64, used for similarity math below


def _load_grayscale_grid(image_path: str, size: int) -> list:
    """Open image, shrink it, hand back raw grayscale pixels."""
    from PIL import Image  # type: ignore

    with Image.open(image_path) as img:
        small = img.convert("L").resize((size + 1, size), Image.LANCZOS)
        return list(small.getdata())


def _bits_from_pixels(pixels: list, size: int) -> int:
    """Turn grayscale pixel grid into one big number, bit by bit."""
    bits = 0
    for row in range(size):
        base = row * (size + 1)
        for col in range(size):
            left = pixels[base + col]
            right = pixels[base + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return bits


def dhash(image_path: str, size: int = _HASH_SIZE) -> Optional[int]:
    """Compute a difference hash of an image, or None if the image is unusable."""
    try:
        pixels = _load_grayscale_grid(image_path, size)
        return _bits_from_pixels(pixels, size)
    except Exception as exc:
        # corrupt image, missing file, Pillow error — one bad image shouldn't
        # nuke the entire matching run
        log.info("dhash failed for %s: %s", image_path, exc)
        return None


def hamming(a: int, b: int) -> int:
    """Count how many bits differ between two hashes."""
    return bin(a ^ b).count("1")


def _reference_images() -> List[Path]:
    """List every brand PNG in the reference library, sorted for stable results."""
    ref_dir = Path(VISUAL_REFERENCE_DIR)
    if not ref_dir.is_dir():
        return []
    return sorted(ref_dir.glob("*.png"))


def _similarity(distance: int) -> float:
    """Turn a hamming distance into a 0-1 'how alike' score."""
    return round(1.0 - distance / _HASH_BITS, 3)


def _match_against_reference(target_hash: int, ref_path: Path) -> Optional[VisualMatch]:
    """Compare screenshot hash to one reference image, return a match if close enough."""
    ref_hash = dhash(str(ref_path))
    if ref_hash is None:
        return None

    distance = hamming(target_hash, ref_hash)
    if distance > VISUAL_HASH_THRESHOLD:
        return None

    brand = ref_path.stem
    return VisualMatch(
        brand=brand,
        similarity=_similarity(distance),
        reference=ref_path.name,
        detail=f"Screenshot visually matches the '{brand}' login page "
               f"(dHash distance {distance}/{_HASH_BITS}) — likely brand impersonation.",
    )


def assess_visual(screenshot_path: Optional[str]) -> List[VisualMatch]:
    """Compare the screenshot to every brand reference; emit close matches."""
    if not screenshot_path or not Path(screenshot_path).exists():
        return []

    references = _reference_images()
    if not references:
        return []  # empty library, nothing to compare against

    target_hash = dhash(screenshot_path)
    if target_hash is None:
        return []

    matches: List[VisualMatch] = []
    try:
        for ref_path in references:
            match = _match_against_reference(target_hash, ref_path)
            if match is not None:
                matches.append(match)
    except Exception as exc:
        # something outside the per-image handling went sideways — keep
        # whatever matches already exist rather than losing the whole run
        log.error("Visual match error (continuing): %s", exc)
    finally:
        log.info("Visual match complete: %d match(es).", len(matches))
    return matches