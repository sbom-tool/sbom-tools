from __future__ import annotations

import os

import pytest

from sbomtools import NativeLibraryNotFoundError
from sbomtools._loader import load_library


@pytest.fixture
def native_library() -> None:
    try:
        load_library()
    except NativeLibraryNotFoundError as error:
        if os.environ.get("SBOM_TOOLS_LIB_PATH"):
            pytest.fail(str(error))
        pytest.skip(str(error))
