"""Thin wrapper kept for existing instructions: the downloader lives in ``vantage.download``
(also runnable as ``python -m vantage.download`` from an installed wheel)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vantage.download import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
