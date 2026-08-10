# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 lituus-lab
"""Build unicrypto._core, a Cython extension over the UniCrypto C ABI.

A repository checkout links the native library built by ``nimble pyLib``.
An extracted source distribution builds the vendored Nim project in
``_nimsrc``; Nim and Nimble must be available on PATH.
"""
import os
import shutil
import subprocess
import sys

from setuptools import Extension, setup
from Cython.Build import cythonize

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PKG_DIR = os.path.join(HERE, "unicrypto")
VENDOR_DIR = os.path.join(HERE, "_nimsrc")
NIMBLE_FILE = "UniCrypto.nimble"
VENDOR_FILES = [NIMBLE_FILE, "config.nims"]
VENDOR_DIRS = ["src", "include"]

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


def vendor_nim_source():
    """Copy the files needed for a standalone Nim build into the sdist."""
    if os.path.exists(VENDOR_DIR):
        shutil.rmtree(VENDOR_DIR)
    os.makedirs(VENDOR_DIR)
    for filename in VENDOR_FILES:
        shutil.copy2(os.path.join(ROOT, filename), os.path.join(VENDOR_DIR, filename))
    for dirname in VENDOR_DIRS:
        shutil.copytree(os.path.join(ROOT, dirname), os.path.join(VENDOR_DIR, dirname))


def nim_project_dir():
    """Return the checkout or vendored Nim project directory."""
    if os.path.exists(os.path.join(ROOT, NIMBLE_FILE)):
        return ROOT
    if os.path.exists(os.path.join(VENDOR_DIR, NIMBLE_FILE)):
        return VENDOR_DIR
    return None


def ensure_lib_built():
    """Return the native library, building it for an sdist when needed."""
    prebuilt = os.path.join(ROOT, LIB_NAME)
    if os.path.exists(prebuilt):
        return prebuilt
    project = nim_project_dir()
    if project is None:
        raise SystemExit(
            f"setup.py: {prebuilt} not found — run `nimble {NIMBLE_TASK}` first."
        )
    built = os.path.join(project, LIB_NAME)
    if os.path.exists(built):
        return built
    nimble = shutil.which("nimble")
    if nimble is None:
        raise SystemExit(
            "setup.py: `nimble` not found on PATH. Building unicrypto from "
            "source needs Nim (https://nim-lang.org/install.html)."
        )
    try:
        subprocess.check_call([nimble, "install", "--depsOnly", "-y"], cwd=project)
        subprocess.check_call([nimble, NIMBLE_TASK], cwd=project)
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"setup.py: `nimble {NIMBLE_TASK}` failed: {error}") from error
    if not os.path.exists(built):
        raise SystemExit(f"setup.py: `nimble {NIMBLE_TASK}` did not produce {built}")
    return built


commands = [argument for argument in sys.argv[1:] if not argument.startswith("-")]
if commands == ["sdist"]:
    vendor_nim_source()
    include_dir, library_dir = os.path.join(ROOT, "include"), ROOT
else:
    library_path = ensure_lib_built()
    library_dir = os.path.dirname(library_path)
    include_dir = os.path.join(ROOT, "include")
    if not os.path.isdir(include_dir):
        include_dir = os.path.join(VENDOR_DIR, "include")
    if BUNDLED:
        os.makedirs(PKG_DIR, exist_ok=True)
        shutil.copy2(library_path, os.path.join(PKG_DIR, LIB_NAME))

pyx = os.path.join("unicrypto", "_core.pyx")
core_c = os.path.join("unicrypto", "_core.c")
extension = Extension(
    "unicrypto._core",
    sources=[pyx if os.path.exists(os.path.join(HERE, pyx)) else core_c],
    include_dirs=[include_dir],
    library_dirs=[library_dir],
    runtime_library_dirs=RUNTIME_DIRS,
    extra_link_args=LINK_ARGS,
    libraries=["UniCrypto"],
)
ext_modules = (
    cythonize([extension], language_level=3)
    if extension.sources[0].endswith(".pyx")
    else [extension]
)

setup(
    ext_modules=ext_modules,
    include_package_data=True,
    package_data={"unicrypto": [LIB_NAME] if BUNDLED else []},
    exclude_package_data={"unicrypto": ["_core.c"]},
    zip_safe=False,
)
