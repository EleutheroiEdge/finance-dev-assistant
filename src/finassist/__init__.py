"""Evidence-first developer assistance. No import-time IO or provider selection."""

__version__ = "0.5.0"

DISTRIBUTION_NAME = "finledgerpoli"


def installed_version() -> str:
    """Report installed distribution metadata, with a source-checkout fallback."""
    from importlib import metadata

    try:
        return metadata.version(DISTRIBUTION_NAME)
    except metadata.PackageNotFoundError:
        return __version__
