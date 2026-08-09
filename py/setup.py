# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
"""Build unicrypto._core, a Cython extension over the UniCrypto C ABI.
Run `nimble pyLib` first so the library is at the repo root."""
import os
import shutil
import sys

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext as _build_ext
from Cython.Build import cythonize

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
INCLUDE = os.path.join(ROOT, "include")
PKG_DIR = os.path.join(HERE, "unicrypto")

# Windows: link a vcc static lib, since MSVC CPython cannot link MinGW output.
# Elsewhere: bundle the shared lib in the package, found through an rpath
# relative to the extension. macOS rejects distutils' -R, hence extra_link_args.
if sys.platform == "win32":
    LIB_NAME, BUNDLED = "UniCrypto.lib", False
    RUNTIME_DIRS, LINK_ARGS, NIMBLE_TASK = [], [], "clibMsvc"
elif sys.platform == "darwin":
    LIB_NAME, BUNDLED = "libUniCrypto.dylib", True
    RUNTIME_DIRS, LINK_ARGS, NIMBLE_TASK = [], ["-Wl,-rpath,@loader_path"], "clib"
else:
    LIB_NAME, BUNDLED = "libUniCrypto.so", True
    RUNTIME_DIRS, LINK_ARGS, NIMBLE_TASK = ["$ORIGIN"], [], "clib"


class build_ext_with_lib(_build_ext):
    """Copy the shared library into the package dir before linking."""

    def run(self):
        src = os.path.join(ROOT, LIB_NAME)
        if not os.path.exists(src):
            raise SystemExit(
                f"setup.py: {src} not found — run `nimble {NIMBLE_TASK}` first."
            )
        if BUNDLED:
            os.makedirs(PKG_DIR, exist_ok=True)
            shutil.copy2(src, os.path.join(PKG_DIR, LIB_NAME))
        super().run()


ext = Extension(
    "unicrypto._core",
    sources=[os.path.join("unicrypto", "_core.pyx")],
    include_dirs=[INCLUDE],
    library_dirs=[ROOT],
    runtime_library_dirs=RUNTIME_DIRS,
    extra_link_args=LINK_ARGS,
    libraries=["UniCrypto"],
)

setup(
    ext_modules=cythonize([ext], language_level=3),
    cmdclass={"build_ext": build_ext_with_lib},
    include_package_data=True,
    package_data={"unicrypto": [LIB_NAME] if BUNDLED else []},
    exclude_package_data={"unicrypto": ["_core.c"]},
    zip_safe=False,
)
