from distutils.core import setup
from distutils.extension import Extension
import pybind11
from pathlib import Path
from urllib import request
import os

setup(name='pysec',
      version='1.0',
      description='pysec',
      author='Mark Barsi-Siminszky',
      author_email='mark.barsisiminszky@outlook.com',
      url='https://github.com/mbs9org/PySec',
      packages=['pysec'],
      ext_modules=[Extension('pysec.cryptolib', 
        ['CryptoLib/Cryptolib.cpp'], 
        include_dirs=["pybind11/include","openssl/include"],
        library_dirs=["openssl"],
        libraries=["openssl"])]
     )
