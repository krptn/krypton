import sys
import pathlib
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

if sys.platform == "linux":
  LIBSODIUM_BASE_PATH = "vcpkg/packages/libsodium_x64-linux/"
  include_dirs += [LIBSODIUM_BASE_PATH + "include/"]
  library_dirs += [LIBSODIUM_BASE_PATH + "lib/"]
elif sys.platform == "win32":
  LIBSODIUM_BASE_PATH = "vcpkg/packages/libsodium_x64-windows-static/"
  link_libararies = ["libsodium"]
  macros += [("SODIUM_STATIC", 1), ("SODIUM_EXPORT", None)]
  runtime_libs = []
  library_dirs += [f"{LIBSODIUM_BASE_PATH}lib"]
  include_dirs += [f"{LIBSODIUM_BASE_PATH}include/"]
elif sys.platform == "darwin":
  LIBSODIUM_BASE_PATH = "vcpkg/packages/libsodium_x64-darwin/"
  include_dirs += [LIBSODIUM_BASE_PATH + "include/"]
  library_dirs += [LIBSODIUM_BASE_PATH + "lib/"]
  extra_args += ["-std=c++17"]

setup(
  packages=find_packages(),
  ext_modules=[Pybind11Extension('__CryptoLib',
    glob("CryptoLib/*.cpp"),
    include_dirs=include_dirs,
    library_dirs=library_dirs,
    libraries=link_libararies,
    runtime_library_dirs=runtime_libs,
    extra_compile_args=extra_args,
    extra_link_args=extra_args+extra_link_args,
    define_macros=macros)
  ],
)
