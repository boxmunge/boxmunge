"""Where the version-check service lives; the one place that knows."""
import os

DEFAULT_BASE = "https://boxmunge.dev"
BASE_ENV = "BOXMUNGE_VERSION_CHECK_URL"


def version_check_base() -> str:
    """Base URL of the version-check service, without a trailing slash.

    BOXMUNGE_VERSION_CHECK_URL overrides it. The test suites set it to an
    unroutable local address so no test can reach the production service.
    """
    return os.environ.get(BASE_ENV, DEFAULT_BASE).rstrip("/")
