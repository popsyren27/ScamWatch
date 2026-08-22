# ScamWatch

- Runs reconnaissance and heuristic checks against targets (tech stack,
	security headers, CVE lookups, etc.).
- Collects evidence and stores artifacts for later review.
- Can run through Tor (see `torrc` and `tor-data/`) to reduce direct exposure.
- Generates a simple report via the `report` module and serves a minimal GUI
	under `gui/` for quick inspection.

## Quick start

Requirements

- Python 3.10+ (I develop and test on 3.10/3.11)
- See `requirements.txt` for exact packages

Install

```bash
python -m pip install -r requirements.txt
```

Run the tool (headless)

`run.bat` and `run.sh` for convenience.

There are helper scripts `run.bat` and `run.sh` for convenience.

