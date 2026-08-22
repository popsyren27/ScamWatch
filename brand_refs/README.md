# Brand reference images (visual impersonation matching)

Drop a full-page screenshot of each **legitimate** brand login page here, named
`<brand>.png` — e.g. `gcash.png`, `maya.png`, `bpi.png`.

[visual.py](../modules/recon/visual.py) difference-hashes a scanned site's
screenshot and compares it to every image here. A close match (Hamming distance
≤ `VISUAL_HASH_THRESHOLD` in [config.py](../config.py)) is reported as visual
brand impersonation and feeds the risk score.

This folder ships empty — the check simply no-ops until you add references, so
the scanner runs fine without it. The fastest way to capture a reference is to
run a scan of the real site and copy its screenshot from `artifacts/`.
