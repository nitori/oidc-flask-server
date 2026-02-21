from pathlib import Path

from platformdirs import PlatformDirs

__all__ = ["path"]

app_dirs = PlatformDirs("py-oidc-server", "Sani")
here = Path(__file__).absolute().parent

SCHEMES = {
    "app": "app",
    "res": "assets",
    "asset": "assets",
    "assets": "assets",
    "conf": "config",
    "config": "config",
    "data": "data",
    "log": "log",
    "cache": "cache",
    "temp": "cache",
    "tmp": "cache",
}

ROOTS = {
    "app": here,
    "assets": here / "assets",
    "config": app_dirs.user_config_path,
    "data": app_dirs.user_data_path,
    "log": app_dirs.user_log_path,
    "cache": app_dirs.user_cache_path,
}


def path(refpath: str, *, parents=False) -> Path:
    """
    Convert a schemed path like 'res://textures/bg.png' into an absolute path,
    validating that it stays within the expected root directory.
    """
    if "://" not in refpath:
        raise ValueError(
            f"Invalid path format: expected 'scheme://path', got {refpath!r}"
        )

    scheme, rel_path = refpath.split("://", maxsplit=1)
    scheme = scheme.lower()
    rel_path = rel_path.lstrip("/")

    kind = SCHEMES.get(scheme)
    if kind is None:
        raise ValueError(f"Invalid scheme: {scheme}")
    root = ROOTS[kind]
    root.mkdir(parents=True, exist_ok=True)

    full_path = (root / rel_path).resolve(strict=False)
    if not full_path.is_relative_to(root):
        raise ValueError(
            f"The specified path {str(rel_path)!r} is outside the root {str(root)!r}"
        )

    if parents and full_path != root:
        full_path.parent.mkdir(parents=True, exist_ok=True)

    return full_path
