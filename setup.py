from distutils.core import setup
from distutils.extension import Extension
import pybind11

setup(name='pysec',
      version='1.0',
      description='pysec',
      author='Mark Barsi-Siminszky',
      author_email='mark.barsisiminszky@outlook.com',
      url='https://github.com/mbs9org/PySec',
      packages=['pysec'],
      ext_modules=[Extension('pysec.cryptolib', ['CryptoLib/Cryptolib.cpp'],include_dirs=[pybind11.get_include(),"openssl/include"])]
     )
