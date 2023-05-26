import os
import sys
import pathlib
import warnings
from glob import glob
from setuptools import setup, find_packages
from pybind11.setup_helpers import Pybind11Extension

folder = pathlib.Path(__file__).parent.as_posix()

DEBUG = sys.argv.count("--debug") >= 1
OPENSSL_INSTALL_PREFIX = os.environ.get("KR_OPENSSL_INSTALL", "kr-openssl-install")

macros = []
link_libararies = ["crypto"]
runtime_libs = [os.path.join(folder, f"{OPENSSL_INSTALL_PREFIX}/lib")]
extra_args = []
library_dirs = [f"{OPENSSL_INSTALL_PREFIX}/lib"]

package_data = [
  f"../{OPENSSL_INSTALL_PREFIX}/bin/libcrypto-3-x64.dll",
  f"../{OPENSSL_INSTALL_PREFIX}/bin/libssl-3-x64.dll",
  f"../{OPENSSL_INSTALL_PREFIX}/bin/libssl-3-arm64.dll",
  f"../{OPENSSL_INSTALL_PREFIX}/bin/libcrypto-3-arm64.dll",
  f"../{OPENSSL_INSTALL_PREFIX}/bin/libcrypto-3.dll",
  f"../{OPENSSL_INSTALL_PREFIX}/bin/libssl-3.dll",
  f"../{OPENSSL_INSTALL_PREFIX}/lib/ossl-modules/fips.dll",
  f"../{OPENSSL_INSTALL_PREFIX}/bin/openssl.exe",
  f"../{OPENSSL_INSTALL_PREFIX}/openssl.cnf",
  f"../{OPENSSL_INSTALL_PREFIX}/fipsmodule.cnf",
  f"../{OPENSSL_INSTALL_PREFIX}/bin/openssl",
  f"../{OPENSSL_INSTALL_PREFIX}/lib64/libcrypto.so.3",
  f"../{OPENSSL_INSTALL_PREFIX}/lib64/libssl.so.3",
  f"../{OPENSSL_INSTALL_PREFIX}/lib64/ossl-modules/fips.so",
  f"../{OPENSSL_INSTALL_PREFIX}/lib/libcrypto.so.3",
  f"../{OPENSSL_INSTALL_PREFIX}/lib/libssl.so.3",
  f"../{OPENSSL_INSTALL_PREFIX}/lib/ossl-modules/fips.so",
  f"../{OPENSSL_INSTALL_PREFIX}/lib/libcrypto.dylib",
  f"../{OPENSSL_INSTALL_PREFIX}/lib/libssl.dylib",
  f"../{OPENSSL_INSTALL_PREFIX}/lib/ossl-modules/fips.dylib",
]

if not pathlib.Path(folder, OPENSSL_INSTALL_PREFIX).exists():
  warnings.warn("We detected that you are likely building Krptn from source in an unsuitable manner. "
    "Do not attempt to build Krptn from source without reading https://docs.krptn.dev/README-BUILD.html first. "
    "Doing so is a terrible mistake and is likely to cause failures and other errors."
    "If you are not building Krptn from source or you don't get any errors, please ignore this false positive.", 
    RuntimeWarning, stacklevel=2)

if sys.platform == "linux":
  library_dirs += [f"{OPENSSL_INSTALL_PREFIX}/lib64"]
  runtime_libs += [os.path.join(folder, f"{OPENSSL_INSTALL_PREFIX}/lib64")]
elif sys.platform == "win32":
  link_libararies = ["libcrypto", "user32", "WS2_32", "GDI32", "ADVAPI32", "CRYPT32"]
  macros += [("WIN", None)]
  runtime_libs = []
elif sys.platform == "darwin":
  extra_args += ["-std=c++17", "-O0"] # Disable optimizationas as they trigger segementation faults

setup(
  package_data={"": package_data},
  include_package_data=True,
  packages=find_packages(),
  ext_modules=[Pybind11Extension('__CryptoLib',
    glob("CryptoLib/*.cpp"),
    include_dirs=[f"{OPENSSL_INSTALL_PREFIX}/include", "CryptoLib"],
    library_dirs=library_dirs,
    libraries=link_libararies,
    runtime_library_dirs=runtime_libs,
    extra_compile_args=extra_args,
    extra_link_args=extra_args,
    define_macros=macros)
  ],
)
