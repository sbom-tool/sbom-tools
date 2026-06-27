"""Public exceptions raised by the Python binding."""

from __future__ import annotations

from .types import ErrorCode


class SbomToolsNativeError(RuntimeError):
    """An operation failed at the native ABI boundary."""

    def __init__(self, message: str, code: ErrorCode | None = None) -> None:
        self.code = code
        prefix = (
            f"sbom-tools ABI error ({code.value})"
            if code is not None
            else "sbom-tools ABI error"
        )
        super().__init__(f"{prefix}: {message}")


class NativeLibraryNotFoundError(SbomToolsNativeError):
    """The sbom-tools native library could not be found."""


class NativeLibraryLoadError(SbomToolsNativeError):
    """A discovered sbom-tools native library could not be loaded."""
