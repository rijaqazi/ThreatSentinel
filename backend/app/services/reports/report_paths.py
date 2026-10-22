"""Project-relative paths for generated rule reports."""

from pathlib import Path
from typing import Optional, Union

from ...core.paths import RULES_DIR
from ...core.settings import settings


def report_output_paths(base_dir: Optional[Union[str, Path]] = None):
    """Return the report root plus the PDF and ZIP subdirectories."""
    root = Path(base_dir) if base_dir else settings.reports_output_dir
    return root, root / "REPORT", root / "zip"
