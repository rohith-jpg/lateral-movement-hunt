"""Compatibility launcher; supports running a checkout without installation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from lateral_hunt.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
