# Brand reference images (visual impersonation matching)

Drop full-page screenshots of each **legitimate** brand login page here.

Two layouts are supported:

```
brand_refs/
  gcash.png                  # flat (legacy, still works)
  gcash/
    2026.08.png              # versioned (preferred)
    2026.11.png
  maya/
    2026.08.png
```

The **versioned** layout is preferred: when a brand rebrands or refreshes its
login page, drop in a new dated PNG instead of overwriting the old one — old
references keep matching old scam campaigns that reuse the previous design.
`<version>` is any label; a date like `2026.08` works well.

[visual.py](../modules/recon/visual.py) difference-hashes a scanned site's
screenshot and compares it to every image here, two ways:

1. **Full-page dHash** — whole screenshot vs whole reference (Hamming distance
   ≤ `VISUAL_HASH_THRESHOLD` in [config.py](../config.py)).
2. **Tiled region hash** — the screenshot and each reference are split into a
   `VISUAL_TILE_GRID x VISUAL_TILE_GRID` grid and hashed per tile. A single
   tile match (≤ `VISUAL_TILE_HASH_THRESHOLD`) catches a copied login widget
   embedded in an otherwise different page.

Either hit is reported as visual brand impersonation and feeds the risk score
(a tile-only match scores lower than a full-page match).

This folder ships empty — the check simply no-ops until you add references, so
the scanner runs fine without it. The fastest way to capture a reference is to
run a scan of the real site and copy its screenshot from `artifacts/`.
