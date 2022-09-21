import pathlib
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop
from pybind11.setup_helpers import Pybind11Extension
from glob import glob
import os
import sys

folder = pathlib.Path(__file__).parent.as_posix()
description = open("README.md", "r").read()

DEBUG = sys.argv.count("--debug") >= 1

macros = []
link_libararies = []
runtime_libs = []
extra_args = []
library_dirs = []

if sys.platform == "linux":
  link_libararies += ["crypto"]
  macros += []
  library_dirs += ["kr-openssl-install/lib64"]
  runtime_libs += [os.path.join(folder, "kr-openssl-install/lib64")]
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

def finishInstall():
  openssl_fips_module = "kr-openssl-install/lib/ossl-modules/fips.dll" if sys.platform == "win32" else "kr-openssl-install/lib64/ossl-modules/fips.so"
  openssl_fips_conf = "kr-openssl-config/fipsmodule.cnf"
  openssl = '"kr-openssl-install\\bin\\openssl"' if sys.platform == "win32" else './kr-openssl-install/bin/openssl'
  os.system(f'{openssl} fipsinstall -out {openssl_fips_conf} -module {openssl_fips_module}')

class completeInstall(install):
  def run(self):
    temp = os.getcwd()
    install.run(self)
    try: os.chdir(os.path.join(self.install_base, "site-packages/"))
    except FileNotFoundError:
      try: os.chdir(os.path.join(self.install_base, "Lib/site-packages/"))
      except FileNotFoundError: return
    finishInstall()
    os.chdir(temp)

class completeDevelop(develop):
  def run(self):
    temp = os.getcwd()
    develop.run(self)
    os.chdir(pathlib.Path(__file__).parent.as_posix())
    finishInstall()
    os.chdir(temp)

setup(name='krptn',
  version='0.1.8',
  description='Zero Knowledge security for Python',
  long_description=description,
  long_description_content_type="text/markdown",
  author='Krptn Project',
  author_email='contact@krptn.dev',
  project_urls={
    'Homepage': "https://www.krptn.dev/",
    'Documentation': "https://docs.krptn.dev/",
    'GitHub': "https://github.com/krptn/krypton/",
    'Bug Tracker': "https://github.com/krptn/krypton/issues",
  },
  classifiers=[
      'License :: OSI Approved :: Apache Software License',
      'Operating System :: OS Independent',
      'Intended Audience :: Developers',
      'Intended Audience :: System Administrators',
      'Topic :: Security',
      'Topic :: Security :: Cryptography',
      'Framework :: Django',
      'Framework :: Flask',
  ],
  package_data={"":[
    "../kr-openssl-install/bin/libcrypto-3-x64.dll",
    "../kr-openssl-install/bin/libcrypto-3.dll",
    "../kr-openssl-install/lib/ossl-modules/fips.dll",
    "../kr-openssl-install/bin/openssl.exe",
    "../kr-openssl-config/openssl.cnf",
    "../kr-openssl-config/fipsmodule.cnf",
    "../kr-openssl-install/bin/openssl",
    "../kr-openssl-install/lib64/libcrypto.so.3",
    "../kr-openssl-install/lib64/ossl-modules/fips.so",
    "../kr-openssl-install/lib/libcrypto.so.3",
    "../kr-openssl-install/lib/ossl-modules/fips.so",
    "../kr-openssl-install/lib/libcrypto.dylib",
    "../kr-openssl-install/lib/ossl-modules/fips.dylib",
  ]},
  packages=find_packages(),
  python_requires=">3.9",
  install_requires=["SQLAlchemy==1.4.41", "webauthn==1.6.0", "Django==4.1.1"],
  extras_require={
        "MSSQL": ["pyodbc"],
        "MySQL": ["mysqlclient"],
        "PostgreSQL": ["psycopg2"],
        "Django": ["django"],
        "Flask": ["flask"]
  },
  include_package_data=True,
  cmdclass={
    'install': completeInstall,
    'develop': completeDevelop
  },
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
