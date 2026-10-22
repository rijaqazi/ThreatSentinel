"""Nmap detector command backed by the packaged detection engine."""

import subprocess
import sys
from pathlib import Path

from ...core.settings import PROJECT_ROOT


DETECTOR_ENGINE = PROJECT_ROOT / "backend" / "app" / "workers" / "detectors" / "nmap_engine.py"


def run_detector(arguments, runner=subprocess.run):
    """Run the established detector without shell command construction."""
    if not DETECTOR_ENGINE.is_file():
        raise FileNotFoundError(f"Nmap detector engine not found: {DETECTOR_ENGINE}")
    return runner([sys.executable, str(DETECTOR_ENGINE), *arguments], check=False)


def main():
    result = run_detector(sys.argv[1:])
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
