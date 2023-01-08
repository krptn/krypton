import os
import sys
import pathlib
import warnings
from glob import glob
from setuptools import setup, find_packages
from pybind11.setup_helpers import Pybind11Extension

folder = pathlib.Path(__file__).parent.as_posix()

DEBUG = sys.argv.count("--debug") >= 1

macros = []
link_libararies = []
runtime_libs = []
extra_args = []
library_dirs = []

package_data = [
  "../kr-openssl-install/bin/libcrypto-3-x64.dll",
  "../kr-openssl-install/bin/libssl-3-x64.dll",
  "../kr-openssl-install/bin/libssl-3-arm64.dll",
  "../kr-openssl-install/bin/libcrypto-3-arm64.dll",
  "../kr-openssl-install/bin/libcrypto-3.dll",
  "../kr-openssl-install/bin/libssl-3.dll",
  "../kr-openssl-install/lib/ossl-modules/fips.dll",
  "../kr-openssl-install/bin/openssl.exe",
  "../kr-openssl-config/openssl.cnf",
  "../kr-openssl-config/fipsmodule.cnf",
  "../kr-openssl-install/bin/openssl",
  "../kr-openssl-install/lib64/libcrypto.so.3",
  "../kr-openssl-install/lib64/libssl.so.3",
  "../kr-openssl-install/lib64/ossl-modules/fips.so",
  "../kr-openssl-install/lib/libcrypto.so.3",
  "../kr-openssl-install/lib/libssl.so.3",
  "../kr-openssl-install/lib/ossl-modules/fips.so",
  "../kr-openssl-install/lib/libcrypto.dylib",
  "../kr-openssl-install/lib/libssl.dylib",
  "../kr-openssl-install/lib/ossl-modules/fips.dylib",
]

if not pathlib.Path(folder, "kr-openssl-install/").exists():
  warnings.warn("We detected that you may be building Krptn from source in an unsuitable manner. "
    "Do not attempt to build Krptn from source without reading https://docs.krptn.dev/README-BUILD.html first. "
    "Doing so is a terrible mistake and is likely to cause failures and other errors."
    "If you are not building Krptn from source or you don't get any errors, please ignore this false positive.", 
    RuntimeWarning, stacklevel=2)

if sys.platform == "linux":
  link_libararies += ["crypto"]
  macros += []
  library_dirs += ["kr-openssl-install/lib64", "kr-openssl-install/lib"]
  runtime_libs += [os.path.join(folder, "kr-openssl-install/lib64"), os.path.join(folder, "kr-openssl-install/lib")]
elif sys.platform == "win32":
  link_libararies += ["libcrypto", "user32", "WS2_32", "GDI32", "ADVAPI32", "CRYPT32"]
  library_dirs += ["kr-openssl-install/lib"]
  macros += [("WIN", None)]
  runtime_libs += []
elif sys.platform == "darwin":
  link_libararies += ["crypto"]
  library_dirs += ["kr-openssl-install/lib"]
  macros += []
  runtime_libs += [os.path.join(folder, "kr-openssl-install/lib")]
  extra_args += ["-std=c++17", "-O0"] # Disable optimizationas as they trigger segementation faults

setup(
  package_data={"": package_data},
  include_package_data=True,
  packages=find_packages(),
  ext_modules=[Pybind11Extension('__CryptoLib',
    glob("CryptoLib/*.cpp"),
    include_dirs=["kr-openssl-install/include", "CryptoLib"],
    library_dirs=library_dirs,
    libraries=link_libararies,
    runtime_library_dirs=runtime_libs,
    extra_compile_args=extra_args,
    extra_link_args=extra_args,
    define_macros=macros)],
)
