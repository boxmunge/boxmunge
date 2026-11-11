"""boxmunge — minimalist, agent-friendly VPS hosting framework.

The canonical version lives in pyproject.toml and is read at runtime
via boxmunge.version.get_build_version(). Don't add a __version__
constant here — it drifts.
"""


def __getattr__(name: str) -> str:
    # The upgrade shims of 0.5.8 to 0.9.1 pre-flight a new release with
    # `print(boxmunge.__version__)`. Those boxes are below the upgrade floor,
    # and this traceback is the only place the release can tell them so.
    if name == "__version__":
        from boxmunge.upgrade_floor import package_version_refusal
        raise AttributeError(package_version_refusal())
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
