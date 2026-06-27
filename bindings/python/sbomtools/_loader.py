"""Locate and load the sbom-tools native library."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
from functools import lru_cache
from pathlib import Path

from ._errors import NativeLibraryLoadError, NativeLibraryNotFoundError

_LIB_PATH_ENV = "SBOM_TOOLS_LIB_PATH"


def _library_name() -> str:
    system = platform.system()
    if system == "Darwin":
        return "libsbom_tools_ffi.dylib"
    if system == "Linux":
        return "libsbom_tools_ffi.so"
    if system == "Windows":
        return "sbom_tools_ffi.dll"
    raise NativeLibraryNotFoundError(f"unsupported platform: {system}")


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _rust_target_triple() -> str | None:
    machine = platform.machine().lower()
    system = platform.system()
    triples = {
        ("Darwin", "arm64"): "aarch64-apple-darwin",
        ("Darwin", "aarch64"): "aarch64-apple-darwin",
        ("Darwin", "x86_64"): "x86_64-apple-darwin",
        ("Linux", "aarch64"): "aarch64-unknown-linux-gnu",
        ("Linux", "arm64"): "aarch64-unknown-linux-gnu",
        ("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
        ("Windows", "amd64"): "x86_64-pc-windows-msvc",
        ("Windows", "x86_64"): "x86_64-pc-windows-msvc",
        ("Windows", "arm64"): "aarch64-pc-windows-msvc",
    }
    return triples.get((system, machine))


def _local_candidates(name: str) -> tuple[Path, ...]:
    package_root = Path(__file__).resolve().parents[1]
    repository_root = _repository_root()
    target_root = repository_root / "target"
    candidates = [
        package_root / "native" / name,
        target_root / "release" / name,
    ]
    target_triple = _rust_target_triple()
    if target_triple is not None:
        candidates.append(target_root / target_triple / "release" / name)
    candidates.append(target_root / "debug" / name)
    if target_triple is not None:
        candidates.append(target_root / target_triple / "debug" / name)
    return tuple(candidates)


def _load_exact(path: Path) -> ctypes.CDLL:
    if not path.is_file():
        raise NativeLibraryNotFoundError(f"{_LIB_PATH_ENV} does not name a library file: {path}")
    try:
        return ctypes.CDLL(str(path))
    except OSError as error:
        raise NativeLibraryLoadError(f"failed to load {_LIB_PATH_ENV}={path}: {error}") from error


@lru_cache(maxsize=1)
def load_library() -> ctypes.CDLL:
    """Load and cache the native library using the documented precedence."""

    configured = os.environ.get(_LIB_PATH_ENV)
    if configured:
        return _load_exact(Path(configured).expanduser())

    name = _library_name()
    attempted: list[str] = []
    load_errors: list[str] = []

    for candidate in _local_candidates(name):
        attempted.append(str(candidate))
        if not candidate.is_file():
            continue
        try:
            return ctypes.CDLL(str(candidate))
        except OSError as error:
            load_errors.append(f"{candidate}: {error}")

    system_candidate = ctypes.util.find_library("sbom_tools_ffi")
    if system_candidate:
        attempted.append(system_candidate)
        try:
            return ctypes.CDLL(system_candidate)
        except OSError as error:
            load_errors.append(f"{system_candidate}: {error}")

    attempted.append(name)
    try:
        return ctypes.CDLL(name)
    except OSError as error:
        fallback_error = str(error)

    searched = ", ".join(attempted)
    if load_errors:
        details = "; ".join(load_errors)
        raise NativeLibraryLoadError(
            f"found no loadable native library; searched {searched}; loader errors: {details}"
        )
    raise NativeLibraryNotFoundError(
        f"native library not found; searched {searched}; system loader: {fallback_error}"
    )
