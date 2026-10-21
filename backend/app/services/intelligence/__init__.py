"""Threat-intelligence services."""

from .ioc_pipeline import extract_iocs_from_text, generate_stix_bundles

__all__ = ["StixIngestionService", "extract_iocs_from_text", "generate_stix_bundles"]


def __getattr__(name):
    """Load the STIX service lazily so it can also run as a module."""
    if name == "StixIngestionService":
        from .stix_ingestion import StixIngestionService

        return StixIngestionService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
