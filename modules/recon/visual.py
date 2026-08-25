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

from config import (
    VISUAL_HASH_THRESHOLD, VISUAL_TILE_GRID,
    VISUAL_TILE_HASH_THRESHOLD,
)
from models import VisualMatch
from modules.logging_setup import get_logger

log = get_logger("recon.visual")

_TILE_TMP_DIR = Path("artifacts") / "_tiles"


def _get_ref_dir() -> Path:
    from config import VISUAL_REFERENCE_DIR
    return Path(VISUAL_REFERENCE_DIR)

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
    """List every brand PNG in the reference library, sorted for stable results.

    Supports two layouts:
      flat:      brand_refs/<brand>.png
      versioned: brand_refs/<brand>/<version>.png   (preferred — see README)
    """
    ref_dir = _get_ref_dir()
    if not ref_dir.is_dir():
        return []
    return sorted(ref_dir.glob("*.png")) + sorted(
        p for p in ref_dir.glob("*/*.png") if p.is_file())


def _similarity(distance: int) -> float:
    """Turn a hamming distance into a 0-1 'how alike' score."""
    return round(1.0 - distance / _HASH_BITS, 3)


def _brand_and_version(ref_path: Path) -> tuple[str, str]:
    """Derive (brand, version-label) from the reference path.

    brand_refs/gcash.png            -> ('gcash', 'flat')
    brand_refs/gcash/2026.08.png    -> ('gcash', '2026.08')
    """
    ref_dir = _get_ref_dir()
    if ref_path.parent.name != ref_dir.name and ref_path.parent.parent.name == ref_dir.name:
        return ref_path.parent.name.lower(), ref_path.stem
    return ref_path.stem, "flat"


def _tile_hashes(image_path: str, grid: int = VISUAL_TILE_GRID) -> List[int]:
    """dHash each N x N tile of the image; empty list if hashing fails."""
    try:
        from PIL import Image  # type: ignore
    except ImportError as exc:
        log.info("Tile hashing unavailable (Pillow missing): %s", exc)
        return []
    try:
        with Image.open(image_path) as img:
            w, h = img.size
            hashes: List[int] = []
            for row in range(grid):
                for col in range(grid):
                    box = (col * w // grid, row * h // grid,
                           (col + 1) * w // grid, (row + 1) * h // grid)
                    crop = img.crop(box)
                    tmp = _TILE_TMP_DIR / f"tile_{row}_{col}.png"
                    tmp.parent.mkdir(parents=True, exist_ok=True)
                    crop.save(tmp)
                    th = dhash(str(tmp))
                    if th is not None:
                        hashes.append(th)
                    tmp.unlink(missing_ok=True)
            return hashes
    except Exception as exc:
        log.info("Tile hashing failed for %s: %s", image_path, exc)
        return []


def _match_against_reference(target_hash: int, ref_path: Path) -> Optional[VisualMatch]:
    """Compare screenshot hash to one reference image, return a match if close enough."""
    ref_hash = dhash(str(ref_path))
    if ref_hash is None:
        return None

    distance = hamming(target_hash, ref_hash)
    if distance > VISUAL_HASH_THRESHOLD:
        return None

    brand, version = _brand_and_version(ref_path)
    return VisualMatch(
        brand=brand,
        similarity=_similarity(distance),
        reference=ref_path.name,
        detail=f"Screenshot visually matches the '{brand}' ({version}) login page "
               f"(dHash distance {distance}/{_HASH_BITS}) — likely brand impersonation.",
    )


def _match_tiles_against_reference(target_tiles: List[int], ref_path: Path) -> Optional[VisualMatch]:
    """Any single tile within the tighter threshold counts as a region match."""
    ref_tiles = _tile_hashes(str(ref_path))
    if not ref_tiles or not target_tiles:
        return None
    best = min(hamming(a, b) for a in target_tiles for b in ref_tiles)
    if best > VISUAL_TILE_HASH_THRESHOLD:
        return None
    brand, version = _brand_and_version(ref_path)
    return VisualMatch(
        brand=brand,
        similarity=_similarity(best),
        reference=ref_path.name,
        detail=f"A {VISUAL_TILE_GRID}x{VISUAL_TILE_GRID} region of the screenshot matches "
               f"the '{brand}' ({version}) reference (best tile dHash distance "
               f"{best}/{_HASH_BITS}) — localized widget impersonation, e.g. a copied "
               "login box inside an otherwise different page.",
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
        target_tiles = _tile_hashes(screenshot_path)
        for ref_path in references:
            match = _match_against_reference(target_hash, ref_path)
            if match is not None:
                matches.append(match)
                continue  # full-page hit already covers this reference
            tile_match = _match_tiles_against_reference(target_tiles, ref_path)
            if tile_match is not None:
                matches.append(tile_match)
    except Exception as exc:
        # something outside the per-image handling went sideways — keep
        # whatever matches already exist rather than losing the whole run
        log.error("Visual match error (continuing): %s", exc)
    finally:
        log.info("Visual match complete: %d match(es).", len(matches))
    return matches