"""boxmunge — minimalist, agent-friendly VPS hosting framework.

The canonical version lives in pyproject.toml and is read at runtime
via boxmunge.version.get_build_version(). Don't add a __version__
constant here — it drifts.
"""


def __getattr__(name: str) -> str:
    # The upgrade shims of v0.6.x to v0.9.1 import-test the new release with
    # `print(boxmunge.__version__)` before they install its shim; without it
    # those boxes can never upgrade (tests/integration/test_shim_hop.py).
    # Remove with the 0.11.7 upgrade floor.
    if name == "__version__":
        from boxmunge.version import get_build_version
        return get_build_version()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
