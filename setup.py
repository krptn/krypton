import sys
import pathlib
import os
from glob import glob
from setuptools import setup, find_packages
from pybind11.setup_helpers import Pybind11Extension

folder = pathlib.Path(__file__).parent.as_posix()

DEBUG = sys.argv.count("--debug") >= 1

macros = []
link_libararies = ["sodium"]
runtime_libs = []
extra_args = []
extra_link_args = []
library_dirs = []
include_dirs = ["CryptoLib"]

VCPKG_PORT_BASE_PATH = (
    os.sep.join(glob("vcpkg_installed/**/**/libsodium.*")[0].split(os.sep)[:2])
)

print("Found VCPKG_PORT_PATH: ", VCPKG_PORT_BASE_PATH)

if sys.platform == "win32":
    link_libararies = ["libsodium"]
    macros += [("SODIUM_STATIC", 1), ("SODIUM_EXPORT", None)]
    runtime_libs = []
elif sys.platform == "darwin":
    extra_args += ["-std=c++17"]

include_dirs += [os.path.join(VCPKG_PORT_BASE_PATH, "include/")]
library_dirs += [os.path.join(VCPKG_PORT_BASE_PATH, "lib/")]

setup(
    packages=find_packages(),
    ext_modules=[
        Pybind11Extension(
            "__CryptoLib",
            glob("CryptoLib/*.cpp"),
            include_dirs=include_dirs,
            library_dirs=library_dirs,
            libraries=link_libararies,
            runtime_library_dirs=runtime_libs,
            extra_compile_args=extra_args,
            extra_link_args=extra_args + extra_link_args,
            define_macros=macros,
        )
    ],
)
