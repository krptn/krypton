import pathlib
from setuptools import setup
from glob import glob
from setuptools.command.install import install
from setuptools.command.develop import develop
from pybind11.setup_helpers import Pybind11Extension
import os
import sys
import sqlite3

description = ""
with open("README.md","r") as file:
  description=file.read()

def finishInstall(install_base):
  openssl_fips_module = "openssl-install/lib/ossl-modules/fips.dll" if sys.platform == "win32" else "openssl-install/lib/ossl-modules/fips.so" 
  openssl_fips_conf = "openssl-config/fipsmodule.cnf"
  try: 
    open(openssl_fips_conf,"w").close()
    print("Running self-tests for openssl fips validated module")
    os.system('"openssl-install\\bin\\openssl" fipsinstall -out {openssl_fips_conf} -module {openssl_fips_module}'
      .format(openssl_fips_module=openssl_fips_module, openssl_fips_conf=openssl_fips_conf))
  except:
    print("Not doing openssl self-test. Please perform these manually.")

  try:
    os.mkdir("pysec-data")
  except:
    pass
  try:
    os.chdir("pysec-data")
  except:
    print("Not setting up db")
    return

  if pathlib.Path(os.getcwd(),"crypto.db").exists():
    print("Not setting up crypto.db as it already exists")
    return
  conn = sqlite3.connect("crypto.db")
  c = conn.cursor()
  c.execute("CREATE TABLE crypto (id int, ctext blob)")
  c.execute("INSERT INTO crypto VALUES (?, ?)", (0, b"Position Reserved"))
  c.execute("CREATE TABLE keys (name text, key blob)")
  conn.commit()
  c.close()
  conn.close()
  if pathlib.Path(os.getcwd(),"altKMS.db").exists():
    print("Not setting up altKMS.db as it already exists")
    return
  conn = sqlite3.connect("altKMS.db")
  c = conn.cursor()
  c.execute("CREATE TABLE keys (name text, key blob)")
  conn.commit()
  c.close()
  conn.close()

class completeInstall(install):
  def run(self):
    temp = os.getcwd()
    try: os.chdir(os.path.join(self.install_base, "site-packages"))
    except: os.chdir(os.path.join(self.install_base, "Lib/site-packages"))
    install.run(self)
    finishInstall(self.install_base)
    os.chdir(temp)

class completeDevelop(develop):
  def run(self):
    temp = os.getcwd()
    os.chdir(pathlib.Path(__file__).parent.parent.as_posix())
    develop.run(self)
    finishInstall(self.install_base)
    os.chdir(temp)

setup(name='pysec',
  version='1.0',
  description='pysec',
  long_description=description,
  long_description_content_type="text/markdown",
  author='Mark Barsi-Siminszky',
  author_email='mark.barsisiminszky@outlook.com',
  url='https://github.com/mbs9org/PySec',
  project_urls={
    "Bug Tracker": "https://github.com/mbs9org/PySec/issues",
  },
  classifiers=[
      "License :: OSI Approved :: Apache Software License",
      "Operating System :: OS Independent",
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
    "../openssl-config/fipsmodule.cnf"]},
  packages=['pysec'],
  python_requires=">3.8",
  include_package_data=True,
  cmdclass={
    'install': completeInstall,
    'develop':completeDevelop
  },
  ext_modules=[Pybind11Extension('__CryptoLib',
    sorted(glob("CryptoLib/*.cpp")), 
    include_dirs=["openssl-install/include","CryptoLib"],
    library_dirs=["openssl-install/lib"],
    libraries=["libcrypto"])]
)
