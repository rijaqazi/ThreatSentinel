"""Project-relative directories used by TAXII clients and server."""

import os
from pathlib import Path

from ...core.settings import settings


def _project_path(variable, default):
    value = Path(os.getenv(variable, default))
    return value if value.is_absolute() else settings.project_root / value


TAXII_BUNDLES_DIR = _project_path("TAXII_BUNDLES_DIR", "data/stix")
IOC_PULL_OUTPUT_DIR = _project_path("IOC_PULL_OUTPUT_DIR", "data/iocs")
