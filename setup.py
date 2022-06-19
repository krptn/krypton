import pathlib
from setuptools import setup
from setuptools.command.install import install
from setuptools.command.develop import develop
from pybind11.setup_helpers import Pybind11Extension
import os
import sys

description = ""
with open("README.md","r") as file:
  description=file.read()
extra_args = None
if sys.argv.count("--debug") >= 1 and sys.platform != "win32":
  extra_args = ["-g"]

link_libararies = ["crypto", "ssl"]
macros = []
runtime_libs = ["openssl-install/lib64"]
if sys.platform == "win32":
  link_libararies = ["libcrypto", "user32", "WS2_32", "GDI32", "ADVAPI32", "CRYPT32"]
  macros = [("WIN", None)]
  runtime_libs = None

def finishInstall():
  os.environ["OPENSSL_MODULES"] = os.path.join(pathlib.Path(__file__).parent.as_posix(), "openssl-install/lib/ossl-modules")
  openssl_fips_module = "openssl-install/lib/ossl-modules/fips.dll" if sys.platform == "win32" else "openssl-install/lib64/ossl-modules/fips.so" 
  openssl_fips_conf = "openssl-config/fipsmodule.cnf"
  openssl = '"openssl-install\\bin\\openssl"' if sys.platform == "win32" else './openssl-install/bin/openssl'
  pysec_data = pathlib.Path(pathlib.Path.home(), ".pysec-data/")
  if not pysec_data.exists():
    os.mkdir(pysec_data.as_posix())
  os.system('{openssl} fipsinstall -out {openssl_fips_conf} -module {openssl_fips_module}'
    .format(openssl=openssl, openssl_fips_module=openssl_fips_module, openssl_fips_conf=openssl_fips_conf))

class completeInstall(install):
  def run(self):
    temp = os.getcwd()
    install.run(self)
    try: os.chdir(os.path.join(self.install_base, "site-packages/"))
    except FileNotFoundError: os.chdir(os.path.join(self.install_base, "Lib/site-packages/"))
    finishInstall()
    os.chdir(temp)

class completeDevelop(develop):
  def run(self):
    temp = os.getcwd()
    develop.run(self)
    os.chdir(pathlib.Path(__file__).parent.as_posix())
    finishInstall()
    os.chdir(temp)

setup(name='krypton',
  version='1.0',
  description='krypton',
  long_description=description,
  long_description_content_type="text/markdown",
  author='Mark Barsi-Siminszky',
  author_email='mark.barsisiminszky@outlook.com',
  url='https://github.com/mbs9org/PySec',
  project_urls={
    'Bug Tracker': "https://github.com/mbs9org/PySec/issues",
  },
  classifiers=[
      'License :: OSI Approved :: Apache Software License',
      'Operating System :: OS Independent',
      'Intended Audience :: Developers',
      'Intended Audience :: System Administrators',
      'Topic :: Security',
      'Topic :: Security :: Cryptography',
      'Framework :: Django',
      'Framework :: Flask'
  ],
  package_data={"":["../openssl-install/bin/libcrypto-3-x64.dll",
    "../openssl-install/lib/ossl-modules/fips.dll",
    "../openssl-install/bin/openssl.exe",
    "../openssl-config/openssl.cnf",
    "../openssl-config/fipsmodule.cnf",
    "../openssl-install/bin/openssl",
    "../openssl-install/lib64/libcrypto.so",
    "../openssl-install/lib64/libcrypto.a",
    "../openssl-install/lib64/ossl-modules/fips.so",
    "../openssl-install/lib64/libcrypto.so.3",
<<<<<<< HEAD
    "../openssl-install/lib64/libssl.so.3"]},
  packages=['krypton'],
=======
    "../openssl-install/lib64/libssl.so.3",
    "../openssl-install/lib64/libssl.so"]},
  packages=['pysec'],
>>>>>>> b775f605ae0a9d978dff4618b0ee7c71831e9d6d
  python_requires=">3.8",
  install_requires=["SQLAlchemy"],
  extras_require={
        "MSSQL": ["pyodbc"],
        "MySQL": ["mysqlclient"],
        "PostgreSQL": ["psycopg2"]
  },
  include_package_data=True,
  cmdclass={
    'install': completeInstall,
    'develop':completeDevelop
  },
  ext_modules=[Pybind11Extension('__CryptoLib',
    ["CryptoLib/CryptoLib.cpp", "CryptoLib/aes.cpp", "CryptoLib/ecc.cpp", 
      "CryptoLib/hashes.cpp", "CryptoLib/bases.cpp"],
    include_dirs=["openssl-install/include", "CryptoLib"],
    library_dirs=["openssl-install/lib", "openssl-install/lib64"],
    libraries=link_libararies,
    runtime_library_dirs=runtime_libs,
    extra_compile_args=extra_args,
    extra_link_args=extra_args,
    define_macros=macros)],
)
