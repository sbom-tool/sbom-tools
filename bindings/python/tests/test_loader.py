from __future__ import annotations

from pathlib import Path

import pytest

from sbomtools import NativeLibraryNotFoundError
from sbomtools import _loader
from sbomtools._loader import load_library


def test_explicit_missing_library_fails_without_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    missing = tmp_path / "missing-library"
    monkeypatch.setenv("SBOM_TOOLS_LIB_PATH", str(missing))
    load_library.cache_clear()

    try:
        with pytest.raises(NativeLibraryNotFoundError, match="does not name a library file"):
            load_library()
    finally:
        load_library.cache_clear()


def test_unbuilt_checkout_reports_not_found(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("SBOM_TOOLS_LIB_PATH", raising=False)
    monkeypatch.setattr(_loader, "_local_candidates", lambda name: (tmp_path / name,))
    monkeypatch.setattr(_loader.ctypes.util, "find_library", lambda name: None)

    def missing_library(name: str) -> None:
        raise OSError(f"{name} not found")

    monkeypatch.setattr(_loader.ctypes, "CDLL", missing_library)
    load_library.cache_clear()

    try:
        with pytest.raises(NativeLibraryNotFoundError, match="native library not found"):
            load_library()
    finally:
        load_library.cache_clear()
