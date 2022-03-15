from setuptools import setup, find_packages
from pybind11.setup_helpers import Pybind11Extension
with open("README.md","r") as file:
  description=file.read()

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
  ],
  packages=['pysec'],
  python_requires=">3.8",
  ext_modules=[Pybind11Extension('CryptoLib', 
    ['CryptoLib/Cryptolib.cpp'], 
    include_dirs=["openssl/include","CryptoLib"],
    library_dirs=["openssl"],
    libraries=["libcrypto"],
    data_files=[("","openssl/libcrypto-3-x64.dll")])]
)